---
title: "SecurityConfig"
description: "Complete reference for the SecurityConfig Zod schema with all 44 fields"
---

`SecurityConfig` is the central configuration object for all `@guardcore` adapters. It is validated at startup using a Zod schema. All fields have sensible defaults -- you only need to specify what you want to change.

```typescript
import { SecurityConfigSchema } from '@guardcore/core';
import type { SecurityConfig } from '@guardcore/core';

const config: SecurityConfig = {
  rateLimit: 100,
  rateLimitWindow: 60,
};

const resolved = SecurityConfigSchema.parse(config);
```

## Proxy

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `trustedProxies` | `string[]` | `[]` | IP addresses or CIDR ranges of trusted reverse proxies |
| `trustedProxyDepth` | `number` | `1` | How many `X-Forwarded-For` hops to trust |
| `trustXForwardedProto` | `boolean` | `false` | Trust `X-Forwarded-Proto` header for HTTPS detection |
| `passiveMode` | `boolean` | `false` | Log violations without blocking requests |

## IP Filtering

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `whitelist` | `string[] \| null` | `null` | IP/CIDR allowlist. When set, only these IPs are allowed |
| `blacklist` | `string[]` | `[]` | IP/CIDR blocklist. These IPs are always blocked |
| `whitelistCountries` | `string[]` | `[]` | Two-letter country codes to allow (requires `geoIpHandler` or `geoResolver`) |
| `blockedCountries` | `string[]` | `[]` | Two-letter country codes to block (requires `geoIpHandler` or `geoResolver`) |

## Rate Limiting

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `rateLimit` | `number` | `10` | Max requests per window per IP |
| `rateLimitWindow` | `number` | `60` | Window duration in seconds |
| `enableRateLimiting` | `boolean` | `true` | Enable/disable rate limiting globally |
| `endpointRateLimits` | `Record<string, [number, number]>` | `{}` | Per-endpoint overrides: `{ "/api/search": [5, 60] }` |

## Detection

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enablePenetrationDetection` | `boolean` | `true` | Enable the 75-pattern detection engine |
| `detectionCompilerTimeout` | `number` | `2.0` | Regex compilation timeout in seconds (0.1-10) |
| `detectionMaxContentLength` | `number` | `10000` | Max content length for scanning (1000-100000) |
| `detectionPreserveAttackPatterns` | `boolean` | `true` | Preserve attack regions when truncating long content |
| `detectionSemanticThreshold` | `number` | `0.7` | Semantic analysis threat score threshold (0-1) |
| `detectionAnomalyThreshold` | `number` | `3.0` | Z-score threshold for performance anomaly detection (1-10) |
| `detectionSlowPatternThreshold` | `number` | `0.1` | Seconds before a pattern is considered slow (0.01-1) |
| `detectionMonitorHistorySize` | `number` | `1000` | Number of recent metrics to keep (100-10000) |
| `detectionMaxTrackedPatterns` | `number` | `1000` | Max patterns to track in performance monitor (100-5000) |

## Auto-Banning

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enableIpBanning` | `boolean` | `true` | Enable automatic IP banning |
| `autoBanThreshold` | `number` | `10` | Suspicious requests before auto-ban |
| `autoBanDuration` | `number` | `3600` | Ban duration in seconds |

## User Agent Filtering

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `blockedUserAgents` | `string[]` | `[]` | Substring patterns to match against User-Agent header |

## Security Headers

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `securityHeaders` | `object \| null` | See [Security Headers](../security-headers/) | Security headers configuration object |
| `enforceHttps` | `boolean` | `false` | Redirect HTTP requests to HTTPS |

## CORS

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enableCors` | `boolean` | `false` | Enable CORS handling |
| `corsAllowOrigins` | `string[]` | `['*']` | Allowed origins |
| `corsAllowMethods` | `string[]` | `['GET','POST','PUT','PATCH','DELETE','OPTIONS']` | Allowed methods |
| `corsAllowHeaders` | `string[]` | `['*']` | Allowed headers |
| `corsAllowCredentials` | `boolean` | `false` | Allow credentials |
| `corsExposeHeaders` | `string[]` | `[]` | Headers exposed to the browser |
| `corsMaxAge` | `number` | `600` | Preflight cache duration in seconds |

## Cloud Provider Blocking

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `blockCloudProviders` | `('AWS' \| 'GCP' \| 'Azure')[]` | `[]` | Cloud providers to block |
| `cloudIpRefreshInterval` | `number` | `3600` | Seconds between cloud IP range refreshes (60-86400) |

## GeoIP

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `geoIpHandler` | `GeoIPHandler` | `undefined` | GeoIP handler instance (e.g., `IPInfoManager`) |
| `geoResolver` | `(ip: string) => string \| null` | `undefined` | Simple function returning 2-letter country code |

## Agent (Telemetry)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enableAgent` | `boolean` | `false` | Enable telemetry agent |
| `agentApiKey` | `string \| null` | `null` | API key (required when `enableAgent` is true) |
| `agentEndpoint` | `string` | `'https://api.fastapi-guard.com'` | Agent endpoint URL |
| `agentProjectId` | `string \| null` | `null` | Project identifier |
| `agentBufferSize` | `number` | `100` | Events buffered before flush |
| `agentFlushInterval` | `number` | `30` | Flush interval in seconds |
| `agentEnableEvents` | `boolean` | `true` | Send security events |
| `agentEnableMetrics` | `boolean` | `true` | Send performance metrics |
| `agentTimeout` | `number` | `30` | Request timeout in seconds |
| `agentRetryAttempts` | `number` | `3` | Retry count on failure |

## Dynamic Rules

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enableDynamicRules` | `boolean` | `false` | Enable agent-driven rule updates (requires `enableAgent`) |
| `dynamicRuleInterval` | `number` | `300` | Polling interval in seconds |

## Redis

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enableRedis` | `boolean` | `true` | Enable Redis for distributed state |
| `redisUrl` | `string` | `'redis://localhost:6379'` | Redis connection URL |
| `redisPrefix` | `string` | `'guard_core:'` | Prefix for all Redis keys |

## Logging

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `logger` | `Logger` | `defaultLogger` | Custom logger instance |
| `customLogFile` | `string \| null` | `null` | Path to a log file |
| `logSuspiciousLevel` | `string \| null` | `'WARNING'` | Log level for suspicious requests |
| `logRequestLevel` | `string \| null` | `null` | Log level for all requests (null = disabled) |
| `logFormat` | `'text' \| 'json'` | `'text'` | Log output format |

## Emergency Mode

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `emergencyMode` | `boolean` | `false` | Block all traffic except whitelisted IPs |
| `emergencyWhitelist` | `string[]` | `[]` | IPs allowed during emergency mode |

## Custom Checks

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `excludePaths` | `string[]` | `[]` | URL paths to skip all security checks |
| `customErrorResponses` | `Record<number, string>` | `{}` | Custom error messages by status code |
| `customRequestCheck` | `(req: GuardRequest) => Promise<GuardResponse \| null>` | `undefined` | Custom check function run at the end of the pipeline |
| `customResponseModifier` | `(res: GuardResponse) => Promise<GuardResponse>` | `undefined` | Modify responses before sending |

## Validation Rules

The schema enforces these constraints:
- `agentApiKey` is required when `enableAgent` is true
- `enableAgent` must be true when `enableDynamicRules` is true
- `geoIpHandler` or `geoResolver` is required when using `blockedCountries` or `whitelistCountries`

## Production Example

```typescript
import type { SecurityConfig } from '@guardcore/core';

const config: SecurityConfig = {
  trustedProxies: ['10.0.0.0/8'],
  trustedProxyDepth: 2,
  trustXForwardedProto: true,

  enableRedis: true,
  redisUrl: process.env.REDIS_URL ?? 'redis://localhost:6379',

  rateLimit: 100,
  rateLimitWindow: 60,
  endpointRateLimits: {
    '/api/login': [5, 300],
    '/api/search': [20, 60],
  },

  enablePenetrationDetection: true,
  detectionSemanticThreshold: 0.7,

  autoBanThreshold: 5,
  autoBanDuration: 7200,

  blockedUserAgents: ['sqlmap', 'nikto', 'nmap', 'masscan'],

  enforceHttps: true,

  enableCors: true,
  corsAllowOrigins: ['https://app.example.com'],
  corsAllowCredentials: true,

  excludePaths: ['/health', '/metrics'],

  customErrorResponses: {
    403: 'Access denied',
    429: 'Too many requests, slow down',
  },
};
```
