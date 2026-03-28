---
editUrl: false
next: false
prev: false
title: "DynamicRulesSchema"
---

> `const` **DynamicRulesSchema**: `ZodObject`\<\{ `blockedCloudProviders`: `ZodPipe`\<`ZodDefault`\<`ZodArray`\<`ZodEnum`\<\{ `AWS`: `"AWS"`; `Azure`: `"Azure"`; `GCP`: `"GCP"`; \}\>\>\>, `ZodTransform`\<`Set`\<`"AWS"` \| `"GCP"` \| `"Azure"`\>, (`"AWS"` \| `"GCP"` \| `"Azure"`)[]\>\>; `blockedCountries`: `ZodDefault`\<`ZodArray`\<`ZodString`\>\>; `blockedUserAgents`: `ZodDefault`\<`ZodArray`\<`ZodString`\>\>; `emergencyMode`: `ZodDefault`\<`ZodBoolean`\>; `emergencyWhitelist`: `ZodDefault`\<`ZodArray`\<`ZodString`\>\>; `enableIpBanning`: `ZodDefault`\<`ZodNullable`\<`ZodBoolean`\>\>; `enablePenetrationDetection`: `ZodDefault`\<`ZodNullable`\<`ZodBoolean`\>\>; `enableRateLimiting`: `ZodDefault`\<`ZodNullable`\<`ZodBoolean`\>\>; `endpointRateLimits`: `ZodDefault`\<`ZodRecord`\<`ZodString`, `ZodTuple`\<\[`ZodNumber`, `ZodNumber`\], `null`\>\>\>; `expiresAt`: `ZodDefault`\<`ZodNullable`\<`ZodString`\>\>; `globalRateLimit`: `ZodDefault`\<`ZodNullable`\<`ZodNumber`\>\>; `globalRateWindow`: `ZodDefault`\<`ZodNullable`\<`ZodNumber`\>\>; `ipBanDuration`: `ZodDefault`\<`ZodNumber`\>; `ipBlacklist`: `ZodDefault`\<`ZodArray`\<`ZodString`\>\>; `ipWhitelist`: `ZodDefault`\<`ZodArray`\<`ZodString`\>\>; `ruleId`: `ZodString`; `suspiciousPatterns`: `ZodDefault`\<`ZodArray`\<`ZodString`\>\>; `timestamp`: `ZodString`; `ttl`: `ZodDefault`\<`ZodNumber`\>; `version`: `ZodNumber`; `whitelistCountries`: `ZodDefault`\<`ZodArray`\<`ZodString`\>\>; \}, `$strip`\>

Defined in: [core/src/models/dynamic-rules.ts:5](https://github.com/rennf93/guard-core-ts/blob/3e2d853c83968c3c17771a7b42062692ebe97b52/packages/core/src/models/dynamic-rules.ts#L5)
