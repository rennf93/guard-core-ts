# @guardcore/fastify Example

## Running

With Docker Compose (app plus Redis, with healthchecks):

```bash
cd examples/fastify
docker compose up --build
```

The app listens on port 8080 in compose and on port 3000 when run directly.

Or directly from the repo root (after `pnpm install` and `pnpm build`):

```bash
cd examples/fastify
npx tsx app.ts
```

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Route listing |
| `GET /health` | Health check (excluded) |
| `GET /basic` | Basic protected endpoint |
| `GET /rate-limited` | 5 requests per 60 seconds |
| `GET /bearer-auth` | Bearer token required |
| `GET /no-cloud` | Block AWS/GCP/Azure |
