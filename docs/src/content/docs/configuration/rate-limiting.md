---
title: "Rate Limiting"
description: "Global, per-endpoint, per-route, and geo-based rate limiting with Redis and in-memory backends"
---

Rate limiting in `@guardcore` supports multiple granularity levels, atomic Redis operations via Lua scripts, and automatic in-memory fallback when Redis is unavailable.

## Global Rate Limiting

Applies to all endpoints:

```typescript
const config: SecurityConfig = {
  enableRateLimiting: true,
  rateLimit: 100,
  rateLimitWindow: 60,
};
```

Every IP is limited to 100 requests per 60-second sliding window.

## Per-Endpoint Rate Limits

Override limits for specific URL paths:

```typescript
const config: SecurityConfig = {
  rateLimit: 100,
  rateLimitWindow: 60,
  endpointRateLimits: {
    '/api/login': [5, 300],
    '/api/search': [20, 60],
    '/api/upload': [3, 60],
  },
};
```

The tuple is `[maxRequests, windowSeconds]`. Endpoint limits take priority over global limits.

## Per-Route Rate Limits (Decorators)

Apply rate limits to individual route handlers using decorators:

```typescript
import { SecurityDecorator, SecurityConfigSchema } from '@guardcore/core';

const config = SecurityConfigSchema.parse({ enableRedis: false });
const guard = new SecurityDecorator(config);

const handler = guard.rateLimit(5, 60)(async (req) => {
  return { data: 'limited endpoint' };
});
```

## Geo-Based Rate Limits

Different limits per country code (requires `geoIpHandler` or `geoResolver`):

```typescript
const handler = guard.geoRateLimit({
  US: [100, 60],
  CN: [10, 60],
  DEFAULT: [50, 60],
})(async (req) => {
  return { data: 'geo-limited' };
});
```

## Redis Lua Script

When Redis is available, rate limiting uses an atomic Lua script for accuracy under concurrency:

```lua
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local window_start = now - window

redis.call('ZADD', key, now, now)
redis.call('ZREMRANGEBYSCORE', key, 0, window_start)
local count = redis.call('ZCARD', key)
redis.call('EXPIRE', key, window * 2)

return count
```

This uses a Redis sorted set where each request timestamp is a member scored by its time. Old entries are pruned, and the count is returned atomically.

The script is loaded once via `SCRIPT LOAD` and executed with `EVALSHA` for performance.

## In-Memory Fallback

When Redis is unavailable, rate limiting automatically falls back to an in-memory `Map<string, number[]>` that tracks timestamps per key. This works correctly for single-process deployments but does not share state across processes.

The fallback activates when:
- `enableRedis` is `false`
- Redis connection fails at startup
- A Redis operation fails at runtime (per-request fallback)

## Redis Key Format

```
{prefix}rate_limit:rate:{ip}:{endpoint}
```

Example: `guard_core:rate_limit:rate:192.168.1.1:/api/login`

Value type: Sorted set (timestamps as scores)
TTL: `window * 2` seconds

## Rate Limit Response

When a client exceeds their limit, the middleware returns:

```json
{
  "detail": "Rate limit exceeded"
}
```

Status code: `429 Too Many Requests`

## Configuration Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enableRateLimiting` | `boolean` | `true` | Enable/disable rate limiting |
| `rateLimit` | `number` | `10` | Global max requests per window |
| `rateLimitWindow` | `number` | `60` | Global window in seconds |
| `endpointRateLimits` | `Record<string, [number, number]>` | `{}` | Per-endpoint `[limit, window]` |
