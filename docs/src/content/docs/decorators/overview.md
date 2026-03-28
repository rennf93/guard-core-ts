---
title: "Decorators Overview"
description: "How SecurityDecorator works, mixin composition, WeakMap route IDs, and the 20 available methods"
---

The `SecurityDecorator` provides per-route security configuration through 20 chainable methods. Each method returns a higher-order function that wraps a route handler and associates a `RouteConfig` with it.

## How It Works

### Mixin Composition

`SecurityDecorator` is built by composing 6 mixin classes onto `BaseSecurityDecorator`:

```
BaseSecurityDecorator
  └── AccessControl
      └── RateLimiting
          └── Authentication
              └── Behavioral
                  └── ContentFiltering
                      └── Advanced = SecurityDecorator
```

Each mixin adds methods to the class. The final `SecurityDecorator` has all 20 methods available.

### Route ID Assignment

Each decorated function gets a unique route ID stored in a `WeakMap<Function, string>`. This avoids polluting the function object and allows garbage collection. IDs follow the pattern `guard_route_N`.

When the middleware processes a request, it reads the route ID from `request.state.guardRouteId` and looks up the corresponding `RouteConfig` from the decorator's internal `Map<string, RouteConfig>`.

### RouteConfig

A `RouteConfig` object holds all per-route settings:

```typescript
class RouteConfig {
  rateLimit: number | null = null;
  rateLimitWindow: number | null = null;
  ipWhitelist: string[] | null = null;
  ipBlacklist: string[] | null = null;
  blockedCountries: string[] | null = null;
  whitelistCountries: string[] | null = null;
  bypassedChecks: Set<string> = new Set();
  requireHttps: boolean = false;
  authRequired: string | null = null;
  customValidators: Array<(request: GuardRequest) => Promise<GuardResponse | null>> = [];
  blockedUserAgents: string[] = [];
  requiredHeaders: Record<string, string> = {};
  behaviorRules: BehaviorRule[] = [];
  blockCloudProviders: Set<string> = new Set();
  maxRequestSize: number | null = null;
  allowedContentTypes: string[] | null = null;
  timeRestrictions: { start: string; end: string } | null = null;
  enableSuspiciousDetection: boolean = true;
  requireReferrer: string[] | null = null;
  apiKeyRequired: boolean = false;
  sessionLimits: Record<string, number> | null = null;
  geoRateLimits: Record<string, [number, number]> | null = null;
}
```

## Creating an Instance

```typescript
import { SecurityDecorator, SecurityConfigSchema } from '@guardcore/core';

const config = SecurityConfigSchema.parse({
  enableRedis: false,
  rateLimit: 100,
  rateLimitWindow: 60,
});

const guard = new SecurityDecorator(config);
```

Pass the `guard` instance to your adapter:

```typescript
createSecurityMiddleware({ config, guardDecorator: guard });
```

## Applying to Handlers

Each decorator method returns a function that wraps a route handler:

```typescript
const handler = guard.rateLimit(5, 60)(async (req, res) => {
  res.json({ data: 'limited' });
});

app.get('/api/resource', handler);
```

Decorators can be chained by nesting:

```typescript
const handler = guard.rateLimit(5, 60)(
  guard.requireAuth('bearer')(
    guard.blockCountries(['CN', 'RU'])(async (req, res) => {
      res.json({ data: 'protected' });
    })
  )
);
```

## All 20 Methods

### Access Control
| Method | Description |
|--------|-------------|
| [`requireIp(whitelist?, blacklist?)`](../access-control/) | IP whitelist/blacklist per route |
| [`blockCountries(countries)`](../access-control/) | Block specific countries |
| [`allowCountries(countries)`](../access-control/) | Allow only specific countries |
| [`blockClouds(providers?)`](../access-control/) | Block cloud provider IPs |
| [`bypass(checks)`](../access-control/) | Bypass specific security checks |

### Authentication
| Method | Description |
|--------|-------------|
| [`requireHttps()`](../authentication/) | Require HTTPS for this route |
| [`requireAuth(type?)`](../authentication/) | Require authorization header |
| [`apiKeyAuth(headerName?)`](../authentication/) | Require API key header |
| [`requireHeaders(headers)`](../authentication/) | Require specific headers |

### Rate Limiting
| Method | Description |
|--------|-------------|
| [`rateLimit(requests, window?)`](../rate-limiting/) | Per-route rate limit |
| [`geoRateLimit(limits)`](../rate-limiting/) | Country-based rate limits |

### Behavioral
| Method | Description |
|--------|-------------|
| [`usageMonitor(maxCalls, window?, action?)`](../behavioral/) | Monitor endpoint call frequency |
| [`returnMonitor(pattern, maxOccurrences, window?, action?)`](../behavioral/) | Monitor response patterns |
| [`behaviorAnalysis(rules)`](../behavioral/) | Custom behavior rules |
| [`suspiciousFrequency(maxFrequency, window?, action?)`](../behavioral/) | Flag suspicious request frequency |

### Content Filtering
| Method | Description |
|--------|-------------|
| [`blockUserAgents(patterns)`](../content-filtering/) | Block specific user agents |
| [`contentTypeFilter(allowedTypes)`](../content-filtering/) | Restrict content types |
| [`maxRequestSize(sizeBytes)`](../content-filtering/) | Limit request body size |
| [`requireReferrer(allowedDomains)`](../content-filtering/) | Require valid referrer |
| [`customValidation(validator)`](../content-filtering/) | Custom validation function |

### Advanced
| Method | Description |
|--------|-------------|
| [`timeWindow(startTime, endTime)`](../advanced/) | Restrict access to time windows |
| [`suspiciousDetection(enabled?)`](../advanced/) | Toggle penetration detection |
| [`honeypotDetection(trapFields)`](../advanced/) | Add honeypot form fields |
