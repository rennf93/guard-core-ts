---
title: "Redis Key Patterns"
description: "All Redis keys, their format, value type, TTL, and the rate limiting Lua script"
---

All Redis keys are prefixed with `config.redisPrefix` (default: `guard_core:`). Key patterns are cross-language compatible with the Python `guard-core` library.

## Key Reference

| Handler | Key Pattern | Value Type | TTL |
|---------|------------|------------|-----|
| RateLimitManager | `{prefix}rate_limit:rate:{ip}:{endpoint}` | Sorted set (timestamps) | `window * 2` |
| IPBanManager | `{prefix}banned_ips:{ip}` | String (expiry timestamp) | Ban duration |
| CloudHandler | `{prefix}cloud_ranges:{provider}` | String (comma-separated CIDRs) | `cloudIpRefreshInterval` |
| SusPatternsManager | `{prefix}patterns:custom` | String (comma-separated patterns) | None |
| SecurityHeadersManager | `{prefix}security_headers:csp_config` | JSON string | 86400s |
| SecurityHeadersManager | `{prefix}security_headers:hsts_config` | JSON string | 86400s |
| SecurityHeadersManager | `{prefix}security_headers:custom_headers` | JSON string | 86400s |
| BehaviorTracker | `{prefix}behavior:usage:{endpoint}:{client_ip}` | Key-value | Rule window |
| BehaviorTracker | `{prefix}behavior:return:{endpoint}:{client_ip}:{pattern}` | Key-value | Rule window |
| IPInfoManager | `{prefix}ipinfo:database` | String (latin-1 encoded DB) | 86400s |

## Key Examples

With the default prefix `guard_core:`:

```
guard_core:rate_limit:rate:192.168.1.1:/api/login
guard_core:banned_ips:10.0.0.50
guard_core:cloud_ranges:AWS
guard_core:cloud_ranges:GCP
guard_core:cloud_ranges:Azure
guard_core:patterns:custom
guard_core:security_headers:csp_config
guard_core:security_headers:hsts_config
guard_core:security_headers:custom_headers
guard_core:behavior:usage:/api/redeem:192.168.1.1
guard_core:behavior:return:/api/redeem:192.168.1.1:status:404
```

## Rate Limiting Lua Script

The rate limit check uses an atomic Lua script loaded via `SCRIPT LOAD` and executed with `EVALSHA`:

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

**How it works**:
1. `ZADD` adds the current timestamp as both score and member
2. `ZREMRANGEBYSCORE` removes all entries older than the window
3. `ZCARD` returns the count of entries in the window
4. `EXPIRE` sets the key TTL to `window * 2` for cleanup

The script is executed in a single Redis transaction, preventing race conditions in concurrent environments.

**Fallback**: If `EVALSHA` fails (script not cached), the manager falls back to individual `ZADD`, `ZREMRANGEBYSCORE`, `ZCARD`, and `EXPIRE` commands. If Redis is entirely unavailable, it falls back to in-memory tracking.

## Key Namespacing

The `RedisManager` formats keys as:

```
{prefix}{namespace}:{key}
```

Where `prefix` is `config.redisPrefix` (default `guard_core:`), `namespace` is the handler's domain (e.g., `banned_ips`, `rate_limit`), and `key` is the specific identifier.

## Cross-Language Compatibility

These key patterns are identical to the Python `guard-core` library. A TypeScript deployment and a Python deployment sharing the same Redis instance will see each other's bans, rate limits, cloud ranges, and custom patterns.

To enable this, both deployments must use the same `redisPrefix` value.

## Cleanup

Keys with TTL expire automatically. Keys without TTL (`patterns:custom`) persist until explicitly deleted via `reset()` or `removePattern()`.

To clear all guard keys from Redis:

```bash
redis-cli KEYS "guard_core:*" | xargs redis-cli DEL
```
