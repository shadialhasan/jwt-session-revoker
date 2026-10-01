/**
 * Distributed JWT Revocation & Multi-Device Logout Engine
 * Author: Eng. MHD. Shadi AL-Hasan <mhd.shadi.alhasan@gmail.com>
 * Phone: +963934005922
 * Copyright (c) 2026 MHD. Shadi AL-Hasan
 */

'use strict';

const { performance } = require('perf_hooks');

class JwtSessionRevoker {
  /**
   * @param {Object|null} redisClient - Optional Redis client instance (ioredis or redis v4)
   * @param {Object} options - Configuration options
   */
  constructor(redisClient = null, options = {}) {
    this.redis = redisClient;
    this.memoryStore = new Map(); // jti -> expiryTimestamp
    this.userRevocationStore = new Map(); // userId -> revokedBeforeTimestamp
    this.options = {
      defaultTtlSeconds: parseInt(process.env.DEFAULT_TTL_SECONDS || options.defaultTtlSeconds || '3600', 10),
      enablePerfLogging: process.env.ENABLE_PERF_LOGGING === 'true' || options.enablePerfLogging || false,
      keyPrefix: options.keyPrefix || 'jwt:blacklist:',
      userPrefix: options.userPrefix || 'jwt:user_revocation:',
      ...options,
    };

    this.metrics = {
      totalRevocations: 0,
      totalChecks: 0,
      hits: 0,
      misses: 0,
      totalCheckLatencyMs: 0.0,
      totalRevokeLatencyMs: 0.0,
    };
  }

  /**
   * Logs performance metrics if enabled
   * @private
   */
  _logPerf(operation, durationMs, details = {}) {
    if (this.options.enablePerfLogging) {
      console.log(`[PERF][${operation}] ${durationMs.toFixed(3)}ms`, JSON.stringify(details));
    }
  }

  /**
   * Blacklist a specific JWT token identifier (JTI)
   * @param {string} jti - Unique JWT Token ID
   * @param {number} [ttlSeconds] - TTL in seconds until expiration
   */
  async revokeToken(jti, ttlSeconds = null) {
    if (!jti) throw new Error('JTI cannot be empty');
    const ttl = ttlSeconds !== null ? ttlSeconds : this.options.defaultTtlSeconds;
    const start = performance.now();

    if (this.redis) {
      const key = `${this.options.keyPrefix}${jti}`;
      if (typeof this.redis.setex === 'function') {
        await this.redis.setex(key, ttl, 'revoked');
      } else if (typeof this.redis.set === 'function') {
        await this.redis.set(key, 'revoked', { EX: ttl });
      }
    } else {
      const expiry = Date.now() + ttl * 1000;
      this.memoryStore.set(jti, expiry);
      const timer = setTimeout(() => {
        if (this.memoryStore.get(jti) <= Date.now()) {
          this.memoryStore.delete(jti);
        }
      }, ttl * 1000);
      if (timer.unref) timer.unref();
    }

    const duration = performance.now() - start;
    this.metrics.totalRevocations++;
    this.metrics.totalRevokeLatencyMs += duration;
    this._logPerf('REVOKE_TOKEN', duration, { jti, ttl });

    return { jti, ttl, revoked: true };
  }

  /**
   * Revoke multiple tokens in batch
   * @param {string[]} jtis - Array of JTI strings
   * @param {number} [ttlSeconds]
   */
  async revokeTokens(jtis, ttlSeconds = null) {
    if (!Array.isArray(jtis)) throw new Error('jtis must be an array');
    return Promise.all(jtis.map(jti => this.revokeToken(jti, ttlSeconds)));
  }

  /**
   * Check whether a specific JTI has been revoked
   * @param {string} jti - Unique JWT Token ID
   * @returns {Promise<boolean>}
   */
  async isRevoked(jti) {
    if (!jti) return false;
    const start = performance.now();
    let revoked = false;

    if (this.redis) {
      const key = `${this.options.keyPrefix}${jti}`;
      const res = await this.redis.get(key);
      revoked = res !== null && res !== undefined;
    } else {
      const expiry = this.memoryStore.get(jti);
      if (expiry) {
        if (Date.now() < expiry) {
          revoked = true;
        } else {
          this.memoryStore.delete(jti);
          revoked = false;
        }
      }
    }

    const duration = performance.now() - start;
    this.metrics.totalChecks++;
    this.metrics.totalCheckLatencyMs += duration;
    if (revoked) {
      this.metrics.hits++;
    } else {
      this.metrics.misses++;
    }
    this._logPerf('CHECK_TOKEN', duration, { jti, revoked });

    return revoked;
  }

  /**
   * Revoke all tokens issued for a user before a specific timestamp (instant multi-device logout)
   * @param {string|number} userId
   * @param {number} [revokedBeforeTimestamp] - Epoch timestamp in seconds (defaults to now)
   * @param {number} [ttlSeconds]
   */
  async revokeUser(userId, revokedBeforeTimestamp = null, ttlSeconds = null) {
    if (!userId) throw new Error('UserId cannot be empty');
    const start = performance.now();
    const cutOff = revokedBeforeTimestamp || Math.floor(Date.now() / 1000);
    const ttl = ttlSeconds !== null ? ttlSeconds : this.options.defaultTtlSeconds;

    if (this.redis) {
      const key = `${this.options.userPrefix}${userId}`;
      if (typeof this.redis.setex === 'function') {
        await this.redis.setex(key, ttl, cutOff.toString());
      } else if (typeof this.redis.set === 'function') {
        await this.redis.set(key, cutOff.toString(), { EX: ttl });
      }
    } else {
      this.userRevocationStore.set(String(userId), { cutOff, expiry: Date.now() + ttl * 1000 });
    }

    const duration = performance.now() - start;
    this._logPerf('REVOKE_USER', duration, { userId, cutOff });
    return { userId, cutOff, ttl };
  }

  /**
   * Check whether a user's token is revoked based on its issued-at (iat) claim
   * @param {string|number} userId
   * @param {number} iat - Token iat timestamp in seconds
   * @returns {Promise<boolean>}
   */
  async isUserTokenRevoked(userId, iat) {
    if (!userId || !iat) return false;

    if (this.redis) {
      const key = `${this.options.userPrefix}${userId}`;
      const cutOff = await this.redis.get(key);
      if (cutOff !== null && cutOff !== undefined) {
        return iat <= parseInt(cutOff, 10);
      }
      return false;
    }

    const record = this.userRevocationStore.get(String(userId));
    if (record) {
      if (Date.now() < record.expiry) {
        return iat <= record.cutOff;
      }
      this.userRevocationStore.delete(String(userId));
    }
    return false;
  }

  /**
   * Connect/Express middleware for revoking requests with blacklisted tokens
   */
  createMiddleware(extractTokenPayload) {
    return async (req, res, next) => {
      try {
        const payload = extractTokenPayload ? extractTokenPayload(req) : req.user;
        if (!payload) return next();

        if (payload.jti && (await this.isRevoked(payload.jti))) {
          return res.status(401).json({ error: 'Unauthorized', message: 'Token has been revoked' });
        }

        if (payload.sub && payload.iat && (await this.isUserTokenRevoked(payload.sub, payload.iat))) {
          return res.status(401).json({ error: 'Unauthorized', message: 'Session terminated across devices' });
        }

        next();
      } catch (err) {
        next(err);
      }
    };
  }

  /**
   * Retrieve performance and usage metrics
   */
  getMetrics() {
    const avgCheckLatency = this.metrics.totalChecks > 0
      ? this.metrics.totalCheckLatencyMs / this.metrics.totalChecks
      : 0;
    const avgRevokeLatency = this.metrics.totalRevocations > 0
      ? this.metrics.totalRevokeLatencyMs / this.metrics.totalRevocations
      : 0;

    return {
      ...this.metrics,
      avgCheckLatencyMs: Number(avgCheckLatency.toFixed(4)),
      avgRevokeLatencyMs: Number(avgRevokeLatency.toFixed(4)),
      memoryStoreSize: this.memoryStore.size,
      userStoreSize: this.userRevocationStore.size,
    };
  }

  /**
   * Reset performance metrics
   */
  resetMetrics() {
    this.metrics = {
      totalRevocations: 0,
      totalChecks: 0,
      hits: 0,
      misses: 0,
      totalCheckLatencyMs: 0.0,
      totalRevokeLatencyMs: 0.0,
    };
  }
}

module.exports = JwtSessionRevoker;
