---
title: "Handlers"
description: "All 9 handlers: what they do, Redis key patterns, and cache strategies"
---

Handlers are the stateful components of the security engine. They manage data in memory and optionally synchronize with Redis for distributed deployments.

## RedisManager

Wraps `ioredis` to provide namespaced key-value operations.

**Responsibilities**:
- Manages the Redis connection lifecycle
- Provides `getKey`, `setKey`, `delete`, `keys`, `incr`, `exists` operations
- Prefixes all keys with `config.redisPrefix` (default: `guard_core:`)
- Returns `null` for all operations when Redis is unavailable

**Key format**: `{prefix}{namespace}:{key}`

```typescript
await redisHandler.setKey('banned_ips', '192.168.1.1', '1711234567.89', 3600);
// Redis key: guard_core:banned_ips:192.168.1.1
```

## IPBanManager

Manages temporary IP bans with automatic expiration.

**Storage**: In-memory `Map<string, BanEntry>` + Redis `String` keys

**Redis key**: `{prefix}banned_ips:{ip}`
**Value**: Expiry timestamp as string
**TTL**: Ban duration

**Operations**:
- `banIp(ip, duration, reason)` -- Ban an IP for `duration` seconds
- `isIpBanned(ip)` -- Check ban status (checks memory first, then Redis)
- `unbanIp(ip)` -- Remove a ban
- `reset()` -- Clear all bans

**Max size**: 10,000 in-memory entries (LRU eviction)

## RateLimitManager

Tracks request counts per IP per endpoint using a sliding window.

**Storage**: In-memory `Map<string, number[]>` + Redis sorted sets

**Redis key**: `{prefix}rate_limit:rate:{ip}:{endpoint}`
**Value**: Sorted set (timestamps as scores and members)
**TTL**: `window * 2`

Uses a Lua script (`EVALSHA`) for atomic operations. Falls back to in-memory when Redis is unavailable.

**Operations**:
- `checkRateLimit(request, clientIp, createErrorResponse, endpointPath, rateLimit, rateLimitWindow)` -- Check and record a request
- `reset()` -- Clear all rate limit data

## CloudHandler

Fetches and caches cloud provider IP ranges (AWS, GCP, Azure).

**Storage**: In-memory `Map<string, string[]>` + Redis `String` keys

**Redis key**: `{prefix}cloud_ranges:{provider}`
**Value**: Comma-separated CIDR strings
**TTL**: `cloudIpRefreshInterval` (default: 3600s)

**Sources**:
- AWS: `https://ip-ranges.amazonaws.com/ip-ranges.json`
- GCP: `https://www.gstatic.com/ipranges/cloud.json`
- Azure: Scraped from Microsoft download page, then JSON endpoint

**Operations**:
- `refreshAsync(providers, ttl)` -- Fetch latest ranges for specified providers
- `isCloudIp(ip, providers)` -- Check if IP belongs to any provider
- `getCloudProviderDetails(ip, providers)` -- Get provider name and matching CIDR

## SusPatternsManager

The main detection engine orchestrator. Combines all four detection pipeline stages.

**Components owned**:
- `PatternCompiler` (re2-wasm + worker_threads fallback)
- `ContentPreprocessor` (unicode normalization, encoding decoding)
- `SemanticAnalyzer` (attack probability, entropy, obfuscation)
- `PerformanceMonitor` (z-score anomaly detection)

**Redis key**: `{prefix}patterns:custom`
**Value**: Comma-separated custom pattern strings
**TTL**: None (persistent)

**Operations**:
- `detect(content, ipAddress, context, correlationId)` -- Full detection pipeline
- `detectPatternMatch(content, ipAddress, context, correlationId)` -- Boolean match result
- `addPattern(pattern)` -- Add a custom pattern
- `removePattern(pattern)` -- Remove a custom pattern
- `getPerformanceStats()` -- Get pattern performance metrics
- `configureSemanticThreshold(threshold)` -- Adjust semantic threshold at runtime

## SecurityHeadersManager

Manages security response headers with caching.

**Storage**: In-memory `Map` + Redis `String` keys

**Redis keys**:
- `{prefix}security_headers:csp_config` -- CSP configuration (JSON)
- `{prefix}security_headers:hsts_config` -- HSTS configuration (JSON)
- `{prefix}security_headers:custom_headers` -- Custom headers (JSON)
**TTL**: 86400s (24 hours)

**Cache**: In-memory LRU cache per request path, 5-minute TTL, max 1000 entries

**Operations**:
- `configure(options)` -- Update header configuration
- `getHeaders(requestPath)` -- Get headers for a request path
- `getCorsHeaders(origin)` -- Get CORS headers for an origin
- `reset()` -- Clear all cached headers

## BehaviorTracker

Tracks endpoint usage and response patterns per IP over time.

**Storage**: In-memory nested `Map` structures + Redis (via key operations)

**Redis keys**:
- `{prefix}behavior:usage:{endpoint}:{client_ip}` -- Usage count
- `{prefix}behavior:return:{endpoint}:{client_ip}:{pattern}` -- Return pattern count
**TTL**: Rule window duration

**Operations**:
- `trackEndpointUsage(endpointId, clientIp, rule)` -- Track a request, return whether threshold is exceeded
- `trackReturnPattern(endpointId, clientIp, response, rule)` -- Track a response pattern
- `applyAction(rule, clientIp, endpointId, details)` -- Execute the action (ban/log/throttle/alert)

## DynamicRuleManager

Polls the agent for dynamic rule updates.

**Storage**: Current rules in memory

**Operations**:
- `initializeAgent(agentHandler)` -- Start the polling loop
- `updateRules()` -- Fetch and apply new rules
- `getCurrentRules()` -- Get the current rule set
- `forceUpdate()` -- Trigger an immediate update
- `stop()` -- Stop the polling loop

Rules are versioned -- the manager only applies rules with a newer version than the current set.

## IPInfoManager

Default `GeoIPHandler` implementation using the `maxmind` package.

**Storage**: In-memory maxmind reader

**Operations**:
- `initialize()` -- Load the `.mmdb` database from disk
- `getCountry(ip)` -- Return ISO 3166-1 alpha-2 country code

Expects the database at `data/ipinfo/country_asn.mmdb`. Returns `null` for any IP when the database is not loaded.
