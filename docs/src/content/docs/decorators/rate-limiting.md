---
title: "Rate Limiting Decorators"
description: "Per-route and geo-based rate limiting with rateLimit() and geoRateLimit()"
---

## `rateLimit(requests, window?)`

Apply a custom rate limit to a specific route handler. Overrides the global `rateLimit` and `rateLimitWindow` from `SecurityConfig`.

**Parameters**:
- `requests` -- Maximum number of requests allowed in the window
- `window` -- Window duration in seconds (default: `60`)

```typescript
const loginHandler = guard.rateLimit(5, 300)(async (req, res) => {
  res.json({ token: 'abc123' });
});

app.post('/api/login', loginHandler);
```

This limits `/api/login` to 5 requests per 5 minutes per IP, regardless of the global rate limit.

### Different limits for different routes

```typescript
const searchHandler = guard.rateLimit(20, 60)(async (req, res) => {
  res.json({ results: [] });
});

const exportHandler = guard.rateLimit(2, 3600)(async (req, res) => {
  res.json({ csv: '...' });
});

const healthHandler = guard.bypass(['rate_limit'])(async (req, res) => {
  res.json({ status: 'ok' });
});

app.get('/api/search', searchHandler);
app.get('/api/export', exportHandler);
app.get('/health', healthHandler);
```

## `geoRateLimit(limits)`

Apply different rate limits based on the client's country. Requires a `geoIpHandler` in the config: the middleware resolves the request's country through it, and without one the geo tier is skipped and the global rate limit applies.

**Parameters**:
- `limits` -- A `Record<string, [number, number]>` mapping country codes to `[maxRequests, windowSeconds]`

```typescript
const handler = guard.geoRateLimit({
  US: [100, 60],
  GB: [100, 60],
  CN: [10, 60],
  RU: [10, 60],
  '*': [50, 60],
})(async (req, res) => {
  res.json({ data: 'geo-limited' });
});

app.get('/api/resource', handler);
```

Country codes are ISO 3166-1 alpha-2. A country-specific entry wins over the `"*"` fallback tier; if the client's country is not in the map (or cannot be resolved) and no `"*"` entry is present, the global rate limit applies. The geo tier counts per IP and endpoint, like every other endpoint-scoped tier.

### Combining with other decorators

```typescript
const sensitiveHandler = guard.rateLimit(10, 60)(
  guard.geoRateLimit({
    US: [10, 60],
    '*': [3, 60],
  })(
    guard.requireAuth('bearer')(async (req, res) => {
      res.json({ sensitive: true });
    })
  )
);
```

When both `rateLimit` and `geoRateLimit` are applied, the geo-based limits take precedence for countries that have an entry. The route-level `rateLimit` serves as the fallback.
