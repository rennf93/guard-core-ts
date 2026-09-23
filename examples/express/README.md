# @guardcore/express Example

## Running

With Docker Compose (app plus Redis, with healthchecks):

```bash
cd examples/express
docker compose up --build
```

The app listens on port 8080 in compose and on port 3000 when run directly.

Or directly from the repo root (after `pnpm install` and `pnpm build`):

```bash
cd examples/express
npx tsx app.ts
```

## Available Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Route listing |
| `GET /health` | Health check (excluded from security) |
| `GET /basic` | Basic protected endpoint |
| `GET /ip-whitelist` | IP whitelist enforcement (127.0.0.1, 10.0.0.0/8) |
| `GET /bearer-auth` | Bearer token authentication |
| `GET /rate-limited` | Custom rate limit (5 requests per 60 seconds) |
| `GET /geo-rate-limited` | Geographic rate limiting (US: 100/min, CN: 10/min) |
| `GET /usage-monitored` | Usage pattern monitoring (10 calls per 5 minutes) |
| `GET /no-cloud` | Block all cloud provider IPs |
| `GET /country-block` | Block CN, RU, KP |

## Testing

```bash
# Basic request
curl http://localhost:3000/basic

# Bearer auth
curl -H "Authorization: Bearer mytoken" http://localhost:3000/bearer-auth

# Rate limit (send 6 requests quickly)
for i in $(seq 1 6); do curl -s http://localhost:3000/rate-limited; done
```
