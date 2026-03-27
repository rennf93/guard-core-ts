---
title: "Security Headers"
description: "Default security headers, CSP, HSTS, custom headers, and CORS header handling"
---

The `SecurityHeadersManager` applies security headers to every response. It ships with 10 hardened defaults and supports CSP, HSTS, and custom header configuration.

## Default Headers

These 10 headers are applied to every response when `securityHeaders.enabled` is `true` (the default):

| Header | Default Value |
|--------|---------------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `SAMEORIGIN` |
| `X-XSS-Protection` | `1; mode=block` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` |
| `X-Permitted-Cross-Domain-Policies` | `none` |
| `X-Download-Options` | `noopen` |
| `Cross-Origin-Embedder-Policy` | `require-corp` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` |

## Disabling Security Headers

```typescript
const config: SecurityConfig = {
  securityHeaders: null,
};
```

Or disable while keeping the object:

```typescript
const config: SecurityConfig = {
  securityHeaders: {
    enabled: false,
  },
};
```

## Configuring HSTS

`Strict-Transport-Security` is generated from the `hsts` sub-object:

```typescript
const config: SecurityConfig = {
  securityHeaders: {
    enabled: true,
    hsts: {
      maxAge: 31536000,
      includeSubdomains: true,
      preload: true,
    },
  },
};
```

This produces: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`

## Configuring CSP

`Content-Security-Policy` is built from a directive map:

```typescript
const config: SecurityConfig = {
  securityHeaders: {
    enabled: true,
    csp: {
      'default-src': ["'self'"],
      'script-src': ["'self'", 'https://cdn.example.com'],
      'style-src': ["'self'", "'unsafe-inline'"],
      'img-src': ["'self'", 'data:', 'https:'],
      'connect-src': ["'self'", 'https://api.example.com'],
    },
  },
};
```

This produces: `Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://api.example.com`

## Overriding Default Headers

Override individual headers through the `securityHeaders` object:

```typescript
const config: SecurityConfig = {
  securityHeaders: {
    enabled: true,
    frameOptions: 'DENY',
    referrerPolicy: 'no-referrer',
    permissionsPolicy: 'camera=(), microphone=(), geolocation=(self)',
  },
};
```

## Custom Headers

Add arbitrary headers:

```typescript
const config: SecurityConfig = {
  securityHeaders: {
    enabled: true,
    custom: {
      'X-Custom-Header': 'my-value',
      'X-Request-ID-Required': 'true',
    },
  },
};
```

## Header Validation

All header values are validated:
- CR (`\r`) and LF (`\n`) characters are rejected (prevents HTTP response splitting)
- Values exceeding 8192 characters are rejected
- Control characters (`\x00`-`\x08`, `\x0b`, `\x0c`, `\x0e`-`\x1f`) are stripped

## CORS Headers on Error Responses

When `enableCors` is `true`, the `SecurityHeadersManager` also manages CORS headers on error responses (403, 429, etc.). This ensures browsers can read error details from blocked cross-origin requests.

CORS headers applied to error responses:

| Header | Value |
|--------|-------|
| `Access-Control-Allow-Origin` | Matching origin or `*` |
| `Access-Control-Allow-Methods` | Configured methods |
| `Access-Control-Allow-Headers` | Configured headers |
| `Access-Control-Allow-Credentials` | `true` (if enabled) |

## Caching

Headers are cached in-memory per request path with a 5-minute TTL and a max cache size of 1000 entries. When Redis is enabled, CSP, HSTS, and custom header configurations are persisted to Redis with a 24-hour TTL for shared access across processes.
