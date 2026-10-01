# 🔒 jwt-session-revoker

> **Topics:** `jwt` `session-revocation` `redis` `token-blacklist` `authentication` `api-security` `nodejs`


[![Release](https://img.shields.io/badge/Release-v1.0.0-blue.svg)](https://github.com/shadialhasan/jwt-session-revoker/releases/tag/v1.0.0)
[![CI Pipeline](https://github.com/shadialhasan/jwt-session-revoker/actions/workflows/ci.yml/badge.svg)](https://github.com/shadialhasan/jwt-session-revoker/actions)
[![Node: >=18](https://img.shields.io/badge/Node.js-%3E%3D18.0.0-green.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Store: Redis](https://img.shields.io/badge/Cache-Redis%20TTL-red.svg)](https://redis.io)

High-speed Redis-backed JWT token revocation, session blacklist, and multi-device instant logout middleware for Node.js microservices and API gateways. Eliminates the traditional security vulnerabilities of stateless JWTs during credential compromise, privilege changes, and explicit user logouts.

---

## 🌟 Key Features

- **Distributed Redis TTL Storage:** Revoked tokens automatically expire from the blacklist when their original TTL elapses, keeping memory footprints minimal.
- **In-Memory Fallback:** Seamless in-memory `Map` fallback with automated timer cleanup for local development, testing, and single-instance deployments.
- **Multi-Device Global Logout:** Instant invalidation of all existing sessions for a given user by setting a revocation timestamp boundary (`iat` validation).
- **Express & Fastify Middleware:** Ready-to-use middleware helper for protecting HTTP routes with zero boilerplate.
- **Sub-Millisecond Telemetry:** Built-in performance metrics tracking check latency, hit/miss ratios, and throughput.
- **Automated CI/CD:** GitHub Actions test pipeline verifying compatibility across Node 18, 20, and 22 with live Redis service containers.

---

## 🏗️ Architecture & Workflows

### Session Revocation Architecture

```mermaid
flowchart TD
    Client["Client / Mobile App"] --> Gateway["API Gateway / Express Server"]
    Gateway --> Guard{"JwtSessionRevoker Middleware"}
    
    subgraph Storage Engine
        Guard --> Check{"Redis Connected?"}
        Check -- "Yes" --> RedisLookup["Redis GET key: blacklist:{jti}"]
        Check -- "No" --> MemLookup["In-Memory Map Lookup"]
    end
    
    RedisLookup --> Eval{"Is JTI Blacklisted?"}
    MemLookup --> Eval
    
    Eval -- "Yes" --> Reject["401 Unauthorized (Token Revoked)"]
    Eval -- "No" --> Pass["200 OK / Route Controller Executed"]
```

### Multi-Device Logout Sequence

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Admin
    participant App as API Server
    participant Revoker as JwtSessionRevoker
    participant Redis as Redis Cache
    actor Attacker as Stolen Token Bearer

    User->>App: POST /auth/logout-all-devices
    App->>Revoker: revokeUser(userId, currentTimestamp, ttl)
    Revoker->>Redis: SETEX jwt:user_revocation:{userId} {ttl} {timestamp}
    Redis-->>Revoker: OK
    Revoker-->>App: Session Terminated
    App-->>User: Successfully Logged Out Everywhere

    Note over Attacker, App: Compromised token issued before cutoff
    Attacker->>App: GET /api/sensitive-data (Bearer token)
    App->>Revoker: isUserTokenRevoked(userId, token.iat)
    Revoker->>Redis: GET jwt:user_revocation:{userId}
    Redis-->>Revoker: Returns Cutoff Timestamp
    Revoker-->>App: Token is Revoked (iat <= Cutoff)
    App-->>Attacker: 401 Unauthorized
```

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/shadialhasan/jwt-session-revoker.git
cd jwt-session-revoker

# Copy environment configuration
cp .env.example .env
```

### Basic Usage

```javascript
const JwtSessionRevoker = require('jwt-session-revoker');

// Initialize with in-memory storage (or pass a Redis client instance)
const revoker = new JwtSessionRevoker();

async function run() {
  const jti = "d3b07384-d113-46fb-a0ff-5c7a364be16a";

  // Revoke token for 1 hour (3600 seconds)
  await revoker.revokeToken(jti, 3600);

  // Check if token is revoked
  const isBlocked = await revoker.isRevoked(jti);
  console.log(`Is token blacklisted: ${isBlocked}`); // true
}

run();
```

### With Redis (ioredis / node-redis)

```javascript
const Redis = require('ioredis');
const JwtSessionRevoker = require('jwt-session-revoker');

const redis = new Redis({ host: process.env.REDIS_HOST, port: process.env.REDIS_PORT });
const revoker = new JwtSessionRevoker(redis, {
  defaultTtlSeconds: 3600,
  enablePerfLogging: true,
});
```

### Express Middleware Example

```javascript
const express = require('express');
const JwtSessionRevoker = require('jwt-session-revoker');

const app = express();
const revoker = new JwtSessionRevoker();

// Protect routes with revocation middleware
app.use('/api', revoker.createMiddleware((req) => req.user));

app.post('/auth/logout', async (req, res) => {
  await revoker.revokeToken(req.user.jti, 3600);
  res.json({ message: "Successfully logged out" });
});
```

---

## ⚙️ Configuration (`.env`)

```env
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_PASSWORD=
DEFAULT_TTL_SECONDS=3600
ENABLE_PERF_LOGGING=false
LOG_LEVEL=info
```

---

## 🧪 Automated Testing

The project uses Node.js native test runner (`node:test` and `node:assert`):

```bash
npm test
```

---

## 👤 Author & Maintainer

**Eng. MHD. Shadi AL-Hasan**  
- **Role:** Executive CTO & Enterprise Solutions Architect  
- **Email:** [mhd.shadi.alhasan@gmail.com](mailto:mhd.shadi.alhasan@gmail.com)  
- **Phone / WhatsApp:** [+963934005922](tel:+963934005922)  
- **Location:** Damascus, Syria  
- **GitHub:** [shadialhasan](https://github.com/shadialhasan)  

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.  
Copyright (c) 2026 **MHD. Shadi AL-Hasan**. All rights reserved.