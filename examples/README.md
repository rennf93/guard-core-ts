# @guardcore Examples

Example applications demonstrating @guardcore with each supported framework.

| Framework | Directory | Edge-Safe | Redis |
|-----------|-----------|-----------|-------|
| [Express](express/) | `examples/express/` | No | Yes |
| [Fastify](fastify/) | `examples/fastify/` | No | Yes |
| [NestJS](nestjs/) | `examples/nestjs/` | No | Yes |
| [Hono](hono/) | `examples/hono/` | Yes | No |

## Prerequisites

```bash
docker run -d -p 6379:6379 redis:7-alpine
```

## Running

Each example can be run with:

```bash
cd examples/<framework>
npx tsx app.ts
```

## Features Demonstrated

- SecurityConfig with full security headers, CORS, and Redis
- SecurityDecorator per-route configuration
- IP whitelisting/blacklisting
- Bearer token and API key authentication
- Custom rate limiting (per-route and geographic)
- Behavioral analysis (usage monitoring, return patterns)
- Cloud provider blocking
- Country-based access control
- Penetration detection
