---
title: "Access Control Decorators"
description: "Per-route IP filtering, country blocking, cloud provider blocking, and check bypassing"
---

## `requireIp(whitelist?, blacklist?)`

Restrict access to specific IP addresses or CIDR ranges per route.

```typescript
const adminHandler = guard.requireIp(
  ['10.0.0.0/8', '192.168.1.0/24'],
  ['10.0.0.99'],
)(async (req, res) => {
  res.json({ admin: true });
});

app.get('/admin', adminHandler);
```

When `whitelist` is provided, only those IPs can access the route. When `blacklist` is provided, those IPs are blocked even if they match the whitelist.

## `blockCountries(countries)`

Block requests from specific countries. Requires a `geoIpHandler` or `geoResolver` in the config.

```typescript
const handler = guard.blockCountries(['CN', 'RU', 'KP'])(async (req, res) => {
  res.json({ data: 'not available in blocked countries' });
});

app.get('/api/data', handler);
```

Country codes are ISO 3166-1 alpha-2 (two uppercase letters).

## `allowCountries(countries)`

Only allow requests from specific countries. All other countries are blocked.

```typescript
const handler = guard.allowCountries(['US', 'CA', 'GB'])(async (req, res) => {
  res.json({ data: 'US/CA/GB only' });
});

app.get('/api/domestic', handler);
```

## `blockClouds(providers?)`

Block requests originating from cloud provider IP ranges. Useful for preventing automated scraping from cloud-hosted bots.

```typescript
const handler = guard.blockClouds(['AWS', 'GCP'])(async (req, res) => {
  res.json({ data: 'no cloud access' });
});

app.get('/api/resource', handler);
```

Without arguments, blocks all three providers (AWS, GCP, Azure):

```typescript
const handler = guard.blockClouds()(async (req, res) => {
  res.json({ data: 'residential IPs only' });
});
```

## `bypass(checks)`

Bypass specific security checks for a route. Check names correspond to the 17 checks in the security pipeline.

```typescript
const handler = guard.bypass([
  'rate_limit',
  'suspicious_activity',
])(async (req, res) => {
  res.json({ webhook: 'processed' });
});

app.post('/webhook', handler);
```

Available check names:

| Check Name | Pipeline Step |
|-----------|--------------|
| `route_config` | Route configuration extraction |
| `emergency_mode` | Emergency mode |
| `https_enforcement` | HTTPS enforcement |
| `request_logging` | Request logging |
| `request_size_content` | Size/content validation |
| `required_headers` | Required headers |
| `authentication` | Authentication |
| `referrer` | Referrer validation |
| `custom_validators` | Custom validators |
| `time_window` | Time windows |
| `cloud_ip_refresh` | Cloud IP refresh |
| `ip_security` | IP security |
| `cloud_provider` | Cloud provider blocking |
| `user_agent` | User agent filtering |
| `rate_limit` | Rate limiting |
| `suspicious_activity` | Suspicious activity detection |
| `custom_request` | Custom request checks |
