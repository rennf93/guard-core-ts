---
title: "Introduction"
description: "What @guardcore is, the ecosystem architecture, feature overview, and runtime support"
---

## What is @guardcore?

`@guardcore` is a framework-agnostic security middleware engine for Node.js and edge runtimes. It provides IP filtering, rate limiting, penetration detection, security headers, behavioral analysis, and more -- all in a single library that works across Express, Fastify, NestJS, and Hono.

The core package (`@guardcore/core`) contains all security logic. Framework-specific adapter packages are thin wrappers that wire the engine into their respective frameworks.

## Ecosystem

```
@guardcore/core               <- Engine: all security logic
├── @guardcore/express         <- Adapter: Express middleware
├── @guardcore/fastify         <- Adapter: Fastify plugin
├── @guardcore/nestjs          <- Adapter: NestJS module + middleware
└── @guardcore/hono            <- Adapter: Hono middleware (edge-safe)
```

Adapters contain zero security logic. They implement the core's `GuardRequest`/`GuardResponse` interfaces for their native request/response types and delegate everything to the core engine.

## Features

- **IP Filtering** -- Whitelist, blacklist, CIDR ranges, country-based filtering
- **Rate Limiting** -- Global, per-endpoint, per-route, geo-based. Redis Lua scripts for atomicity with in-memory fallback
- **Penetration Detection** -- 75 regex patterns across 15 attack categories, semantic analysis, entropy scoring, obfuscation detection
- **Security Headers** -- 10 default headers, configurable CSP, HSTS, custom headers
- **CORS** -- Full CORS configuration with per-adapter integration
- **Cloud Provider Blocking** -- Block requests from AWS, GCP, and Azure IP ranges
- **Behavioral Analysis** -- Usage monitoring, return pattern tracking, frequency analysis with ban/log/throttle/alert actions
- **Auto-Banning** -- Automatic IP banning after configurable suspicious request thresholds
- **Emergency Mode** -- Kill switch that blocks all traffic except whitelisted IPs
- **Per-Route Decorators** -- 20 decorator methods for fine-grained per-route security configuration
- **Dynamic Rules** -- Agent-driven rule updates without redeploys
- **Redis Integration** -- Distributed state for rate limiting, IP bans, cloud ranges, and caching
- **Request Logging** -- Configurable log levels and formats (text/JSON)

## Python Parity

`@guardcore` is a faithful TypeScript port of the Python `guard-core` library. Every field, protocol, handler, check, and pattern is mapped 1:1 from the Python codebase. Redis key patterns are cross-language compatible -- you can share Redis state between Python and TypeScript deployments.

## Runtime Support

| Runtime | Support |
|---------|---------|
| Node.js 18+ | Full support |
| Cloudflare Workers | Supported via `@guardcore/hono` |
| Deno | Supported via `@guardcore/hono` |
| Vercel Edge | Supported via `@guardcore/hono` |

Edge safety is achieved through `Uint8Array` protocols (no `Buffer`), optional `re2-wasm` for ReDoS-safe regex, and graceful degradation of Redis/maxmind features on runtimes that lack them.
