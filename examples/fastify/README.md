# @guardcore/fastify Example

## Running

```bash
npm install fastify @guardcore/core @guardcore/fastify
docker run -d -p 6379:6379 redis:7-alpine
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
