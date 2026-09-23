# @guardcore/hono Example

Edge-safe example. No Redis, no Node-only dependencies. Runs on Cloudflare Workers, Deno, or Node.

## Running (Node)

With Docker Compose (no Redis needed):

```bash
cd examples/hono
docker compose up --build
```

The app listens on port 8080 in compose and on port 3000 when run directly.

Or directly from the repo root (after `pnpm install` and `pnpm build`):
`server.ts` serves the edge-safe `app.ts` through `@hono/node-server`:

```bash
cd examples/hono
npx tsx server.ts
```

## Running (Cloudflare Workers)

```bash
npx wrangler dev app.ts
```

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Route listing |
| `GET /health` | Health check (excluded) |
| `GET /basic` | Basic protected endpoint |
| `GET /rate-limited` | 5 requests per 60 seconds (in-memory) |
