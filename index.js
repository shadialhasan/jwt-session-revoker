/**
 * Distributed JWT Revocation & Multi-Device Logout Engine
 * Author: Eng. MHD. Shadi AL-Hasan <mhd.shadi.alhasan@gmail.com>
 * Phone: +963934005922
 * Copyright (c) 2026 MHD. Shadi AL-Hasan
 */

class JwtSessionRevoker {
  constructor(redisClient = null) {
    this.memoryStore = new Set();
    this.redis = redisClient;
  }

  async revokeToken(jti, ttlSeconds = 3600) {
    console.log(`[REVOKE] Blacklisting JWT token: ${jti} for ${ttlSeconds}s`);
    if (this.redis) {
      await this.redis.setex(`blacklist:${jti}`, ttlSeconds, 'revoked');
    } else {
      this.memoryStore.add(jti);
      setTimeout(() => this.memoryStore.delete(jti), ttlSeconds * 1000);
    }
  }

  async isRevoked(jti) {
    if (this.redis) {
      const exists = await this.redis.get(`blacklist:${jti}`);
      return exists !== null;
    }
    return this.memoryStore.has(jti);
  }
}

module.exports = JwtSessionRevoker;
