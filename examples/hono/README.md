# @guardcore/hono Example

Edge-safe example. No Redis, no Node-only dependencies. Runs on Cloudflare Workers, Deno, or Node.

## Running (Node)

```bash
npm install hono @guardcore/core @guardcore/hono
npx tsx app.ts
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
