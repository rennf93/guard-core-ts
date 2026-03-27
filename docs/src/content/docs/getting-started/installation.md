---
title: "Installation"
description: "How to install @guardcore packages with npm, pnpm, yarn, or bun"
---

## Requirements

- **Node.js** >= 18 (ES2022 target)
- **TypeScript** >= 5.0 (recommended)

## Core + Adapter

Install the adapter package for your framework. Each adapter includes `@guardcore/core` as a dependency.

### Express

```bash
npm install @guardcore/express
pnpm add @guardcore/express
yarn add @guardcore/express
bun add @guardcore/express
```

### Fastify

```bash
npm install @guardcore/fastify
pnpm add @guardcore/fastify
yarn add @guardcore/fastify
bun add @guardcore/fastify
```

### NestJS

```bash
npm install @guardcore/nestjs
pnpm add @guardcore/nestjs
yarn add @guardcore/nestjs
bun add @guardcore/nestjs
```

### Hono

```bash
npm install @guardcore/hono
pnpm add @guardcore/hono
yarn add @guardcore/hono
bun add @guardcore/hono
```

## Optional Peer Dependencies

These are all optional. Install them to enable specific features.

| Package | Feature | Required for |
|---------|---------|-------------|
| `ioredis` | Redis client | Distributed rate limiting, IP bans, caching |
| `re2-wasm` | ReDoS-safe regex | Safe pattern matching on untrusted input |
| `maxmind` | GeoIP lookups | Country-based filtering (`blockedCountries`, `whitelistCountries`) |
| `he` | HTML entity decoding | Enhanced content preprocessing in detection engine |
| `acorn` | JS AST parsing | Code injection risk scoring in semantic analyzer |

```bash
# Redis support
pnpm add ioredis

# ReDoS-safe regex (recommended for production)
pnpm add re2-wasm

# GeoIP country filtering
pnpm add maxmind
```

All features gracefully degrade when their peer dependency is not installed:
- Without `ioredis`: rate limiting and IP bans use in-memory storage
- Without `re2-wasm`: falls back to native `RegExp` with `worker_threads` timeout protection
- Without `maxmind`: country-based filtering is unavailable (you can still provide a custom `geoResolver`)

## CORS Packages

CORS integration requires a framework-specific CORS package:

| Adapter | CORS Package |
|---------|-------------|
| `@guardcore/express` | `cors` |
| `@guardcore/fastify` | `@fastify/cors` |
| `@guardcore/hono` | Built-in (`hono/cors`) |
| `@guardcore/nestjs` | Use Express CORS or `@nestjs/platform-express` |
