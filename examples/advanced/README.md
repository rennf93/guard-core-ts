# @guardcore/express advanced example

A production-style guarded Express server that mirrors the guard-core-go
`advanced_app`: environment-driven `SecurityConfig`, a per-endpoint rate
limit with a custom 429 body, and an admin route gated on a required
header.

## Run it

With Docker Compose (recommended, includes Redis):

```bash
cd examples/advanced
docker compose up --build
```

Or directly (Redis on localhost:6379 or `GUARD_ENABLE_REDIS=false`):

```bash
cd examples/advanced
npx tsx app.ts
```

## Endpoints

| Endpoint | What it demonstrates |
|---|---|
| `GET /` | API info; passes the guard |
| `GET /health` | Liveness probe; excluded from the pipeline via `excludePaths` |
| `GET /admin/keys` | Admin gate: requires the `X-Admin-Token` header (app-level check) |
| `GET /rate/burst` | Per-endpoint rate limit via `endpointRateLimits`, with a custom 429 body from `customErrorResponses` |
| `GET /search?q=...` | Query parameter scanning; XSS payloads are blocked as suspicious activity (403) |

## Try the security behavior

```bash
# Allowed
curl -i http://localhost:8080/

# Missing header: 400 before the handler runs
curl -i http://localhost:8080/admin/keys

# With the token
curl -i -H "X-Admin-Token: admin-token-change-me" http://localhost:8080/admin/keys

# Rate limited: the 6th request within 60 seconds returns 429 with the
# custom body "Rate limit exceeded, slow down"
for i in $(seq 1 6); do curl -s http://localhost:8080/rate/burst; done

# Blocked by penetration detection (403, "Suspicious activity detected")
curl -i -G http://localhost:8080/search --data-urlencode 'q=<script>alert(1)</script>'
```

## A note on route-scoped config

`@guardcore/core` ships the `SecurityDecorator` route registry and the
`RequiredHeadersCheck` (400, `Missing or invalid required header: ...`),
but the adapter middleware does not populate `request.state.guardRouteId`
yet, so per-route decorator configs (including
`guard.requireHeaders(...)`) are not resolved through the middleware at
runtime. The admin gate here is therefore enforced at the application
level, and the per-endpoint rate limit uses the engine-level
`endpointRateLimits` config, which does apply to every request.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | Listen port (compose sets `8080`) |
| `REDIS_URL` | `redis://localhost:6379` | Shared state for rate limits and bans |
| `REDIS_PREFIX` | `guard_core:` | Redis key prefix |
| `GUARD_ENABLE_REDIS` | `true` | Set to `false` to run on in-process state |
| `GUARD_RATE_LIMIT` | `100` | Global rate limit (requests per window) |
| `GUARD_RATE_LIMIT_WINDOW` | `60` | Global rate limit window (seconds) |
| `GUARD_BURST_LIMIT` | `5` | `/rate/burst` limit (requests per window) |
| `GUARD_BURST_WINDOW` | `60` | `/rate/burst` window (seconds) |
| `GUARD_RATE_LIMIT_MESSAGE` | `Rate limit exceeded, slow down` | Custom 429 body via `customErrorResponses` |
| `ADMIN_TOKEN` | `admin-token-change-me` | Expected `X-Admin-Token` value |
