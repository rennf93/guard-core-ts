# @guardcore Examples

Example applications demonstrating @guardcore with each supported framework.
Each example is a pnpm workspace member, so `pnpm install` at the repo root
links `@guardcore/core` and the adapter packages automatically (build them
first with `pnpm build`).

| Framework | Directory | Edge-Safe | Redis |
|-----------|-----------|-----------|-------|
| [Express](express/) | `examples/express/` | No | Yes |
| [Fastify](fastify/) | `examples/fastify/` | No | Yes |
| [NestJS](nestjs/) | `examples/nestjs/` | No | Yes |
| [Hono](hono/) | `examples/hono/` | Yes | No |
| [Advanced (Express)](advanced/) | `examples/advanced/` | No | Yes |

## Prerequisites

Each example ships a `Dockerfile` and a `docker-compose.yml` (app plus
`redis:7-alpine` where the example uses Redis, with healthchecks and
resource limits):

```bash
cd examples/<framework>
docker compose up --build
```

## Running without Docker

Start Redis (needed by every example except Hono):

```bash
docker run -d -p 6379:6379 redis:7-alpine
```

Then, from the repo root:

```bash
pnpm install
pnpm build
cd examples/<framework>
npx tsx app.ts
```

The Hono example serves through `@hono/node-server` via `server.ts`
(`npx tsx server.ts`); `app.ts` stays edge-safe and exports the app.

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

The [advanced example](advanced/) adds environment-driven `SecurityConfig`,
engine-level per-endpoint rate limits (`endpointRateLimits`) with a custom
429 body (`customErrorResponses`), and an admin route gated on a required
header.

## A note on per-route SecurityDecorator configs

The examples call `SecurityDecorator` methods (`guard.rateLimit(...)`,
`guard.requireAuth(...)`, and friends) to document the decorator API, but
the adapter middleware does not populate `request.state.guardRouteId` yet,
so these route configs are not resolved through the middleware at runtime.
Requests to routes configured only through decorators are therefore handled
by the global `SecurityConfig` alone. The advanced example shows the
engine-level alternatives that do apply today (`endpointRateLimits`,
`customErrorResponses`).
