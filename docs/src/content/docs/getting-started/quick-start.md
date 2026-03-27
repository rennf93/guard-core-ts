---
title: "Quick Start"
description: "Minimal working examples for Express, Fastify, NestJS, and Hono"
---

## Express

```typescript
import express from 'express';
import { createSecurityMiddleware, guardBodyParser } from '@guardcore/express';

const app = express();
app.use(guardBodyParser());

app.use(createSecurityMiddleware({
  config: {
    enableRedis: false,
    rateLimit: 100,
    rateLimitWindow: 60,
    enablePenetrationDetection: true,
  },
}));

app.get('/health', (_req, res) => res.json({ status: 'ok' }));
app.listen(3000);
```

```bash
curl http://localhost:3000/health
# {"status":"ok"}

curl "http://localhost:3000/health?q=<script>alert(1)</script>"
# {"detail":"Suspicious activity detected"}
```

## Fastify

```typescript
import Fastify from 'fastify';
import { guardPlugin } from '@guardcore/fastify';

const app = Fastify();

await app.register(guardPlugin, {
  config: {
    enableRedis: false,
    rateLimit: 100,
    rateLimitWindow: 60,
    enablePenetrationDetection: true,
  },
});

app.get('/health', async () => ({ status: 'ok' }));
await app.listen({ port: 3000 });
```

```bash
curl http://localhost:3000/health
# {"status":"ok"}
```

## NestJS

```typescript
import { Module } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { GuardModule } from '@guardcore/nestjs';

@Module({
  imports: [
    GuardModule.forRoot({
      config: {
        enableRedis: false,
        rateLimit: 100,
        rateLimitWindow: 60,
        enablePenetrationDetection: true,
      },
    }),
  ],
})
class AppModule {}

const app = await NestFactory.create(AppModule);
await app.listen(3000);
```

```bash
curl http://localhost:3000/health
```

## Hono

```typescript
import { Hono } from 'hono';
import { createGuardMiddleware } from '@guardcore/hono';

const app = new Hono();

app.use('*', createGuardMiddleware({
  config: {
    enableRedis: false,
    rateLimit: 100,
    rateLimitWindow: 60,
    enablePenetrationDetection: true,
  },
}));

app.get('/health', (c) => c.json({ status: 'ok' }));
export default app;
```

```bash
curl http://localhost:3000/health
# {"status":"ok"}
```

## What happens next

With the default configuration above, the middleware:

1. Rate limits each IP to 100 requests per 60 seconds
2. Scans query parameters, headers, URL paths, and request bodies against 75 attack patterns
3. Runs semantic analysis for obfuscated payloads
4. Applies 10 security headers to every response
5. Auto-bans IPs after 10 suspicious requests (configurable via `autoBanThreshold`)

All of this runs in-memory. Add `ioredis` and set `enableRedis: true` for distributed state across multiple processes.
