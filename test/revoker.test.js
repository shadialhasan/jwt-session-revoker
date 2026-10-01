'use strict';

const { test, describe, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const JwtSessionRevoker = require('../index.js');

describe('JwtSessionRevoker', () => {
  let revoker;

  beforeEach(() => {
    revoker = new JwtSessionRevoker(null, { enablePerfLogging: false });
  });

  describe('In-Memory Mode', () => {
    test('should report non-revoked token as false', async () => {
      const isRevoked = await revoker.isRevoked('token-123');
      assert.strictEqual(isRevoked, false);
    });

    test('should revoke token and confirm it is revoked', async () => {
      await revoker.revokeToken('token-abc', 300);
      const isRevoked = await revoker.isRevoked('token-abc');
      assert.strictEqual(isRevoked, true);
    });

    test('should handle batch token revocation', async () => {
      const tokens = ['token-1', 'token-2', 'token-3'];
      await revoker.revokeTokens(tokens, 300);

      for (const t of tokens) {
        assert.strictEqual(await revoker.isRevoked(t), true);
      }
      assert.strictEqual(await revoker.isRevoked('token-other'), false);
    });

    test('should expire revoked token after TTL has elapsed', async () => {
      // 1 second TTL
      await revoker.revokeToken('short-lived', 1);
      assert.strictEqual(await revoker.isRevoked('short-lived'), true);

      // Manually simulate time expiration in memoryStore
      revoker.memoryStore.set('short-lived', Date.now() - 100);
      assert.strictEqual(await revoker.isRevoked('short-lived'), false);
    });

    test('should handle empty or null JTI safely', async () => {
      assert.strictEqual(await revoker.isRevoked(null), false);
      assert.strictEqual(await revoker.isRevoked(''), false);
      await assert.rejects(async () => {
        await revoker.revokeToken('');
      }, /JTI cannot be empty/);
    });
  });

  describe('Multi-Device User Revocation', () => {
    test('should revoke all tokens issued before a specific timestamp', async () => {
      const now = Math.floor(Date.now() / 1000);
      await revoker.revokeUser('user-42', now);

      // Token issued 10 seconds ago should be revoked
      const oldTokenRevoked = await revoker.isUserTokenRevoked('user-42', now - 10);
      assert.strictEqual(oldTokenRevoked, true);

      // Token issued 5 seconds in future should NOT be revoked
      const newTokenRevoked = await revoker.isUserTokenRevoked('user-42', now + 5);
      assert.strictEqual(newTokenRevoked, false);

      // Other user should not be affected
      assert.strictEqual(await revoker.isUserTokenRevoked('user-99', now - 10), false);
    });
  });

  describe('Mock Redis Mode', () => {
    test('should delegate to Redis client when provided', async () => {
      const redisStore = new Map();
      const mockRedis = {
        async setex(key, ttl, value) {
          redisStore.set(key, value);
        },
        async get(key) {
          return redisStore.has(key) ? redisStore.get(key) : null;
        },
      };

      const redisRevoker = new JwtSessionRevoker(mockRedis);
      assert.strictEqual(await redisRevoker.isRevoked('redis-jti-1'), false);

      await redisRevoker.revokeToken('redis-jti-1', 60);
      assert.strictEqual(await redisRevoker.isRevoked('redis-jti-1'), true);
      assert.strictEqual(redisStore.get('jwt:blacklist:redis-jti-1'), 'revoked');
    });
  });

  describe('Middleware Integration', () => {
    test('should reject request with revoked token', async () => {
      const middleware = revoker.createMiddleware();
      await revoker.revokeToken('revoked-jti');

      const req = { user: { jti: 'revoked-jti' } };
      let statusCalled = null;
      let jsonCalled = null;
      const res = {
        status(code) {
          statusCalled = code;
          return this;
        },
        json(data) {
          jsonCalled = data;
        },
      };
      let nextCalled = false;

      await middleware(req, res, () => {
        nextCalled = true;
      });

      assert.strictEqual(statusCalled, 401);
      assert.strictEqual(jsonCalled.message, 'Token has been revoked');
      assert.strictEqual(nextCalled, false);
    });

    test('should allow request with valid non-revoked token', async () => {
      const middleware = revoker.createMiddleware();
      const req = { user: { jti: 'valid-active-jti' } };
      const res = {};
      let nextCalled = false;

      await middleware(req, res, () => {
        nextCalled = true;
      });

      assert.strictEqual(nextCalled, true);
    });
  });

  describe('Performance Telemetry', () => {
    test('should record operations count, hits, and latency metrics', async () => {
      revoker.resetMetrics();
      await revoker.revokeToken('perf-test-1');
      await revoker.isRevoked('perf-test-1'); // hit
      await revoker.isRevoked('perf-test-2'); // miss

      const metrics = revoker.getMetrics();
      assert.strictEqual(metrics.totalRevocations, 1);
      assert.strictEqual(metrics.totalChecks, 2);
      assert.strictEqual(metrics.hits, 1);
      assert.strictEqual(metrics.misses, 1);
      assert.ok(metrics.avgCheckLatencyMs >= 0);
      assert.ok(metrics.avgRevokeLatencyMs >= 0);
    });
  });
});
