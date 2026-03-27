---
title: "Authentication Decorators"
description: "Per-route HTTPS, Bearer auth, API key, and required header enforcement"
---

## `requireHttps()`

Enforce HTTPS for a specific route. Requests over HTTP are rejected with a 403 (or redirected if `enforceHttps` is set globally).

```typescript
const handler = guard.requireHttps()(async (req, res) => {
  res.json({ secure: true });
});

app.get('/api/sensitive', handler);
```

## `requireAuth(type?)`

Require an `Authorization` header with a specific scheme. Defaults to `'bearer'`.

```typescript
const handler = guard.requireAuth('bearer')(async (req, res) => {
  res.json({ authenticated: true });
});

app.get('/api/profile', handler);
```

The middleware checks that the `Authorization` header is present and starts with the specified type. It does not validate the token itself -- that is your application's responsibility.

Supported types:

```typescript
guard.requireAuth('bearer')
guard.requireAuth('basic')
guard.requireAuth('digest')
```

## `apiKeyAuth(headerName?)`

Require an API key in a specific header. Defaults to `'X-API-Key'`.

```typescript
const handler = guard.apiKeyAuth('X-API-Key')(async (req, res) => {
  res.json({ data: 'api access granted' });
});

app.get('/api/external', handler);
```

This sets `apiKeyRequired = true` on the route config and adds the header name to `requiredHeaders`. The middleware verifies the header is present and non-empty.

Custom header name:

```typescript
const handler = guard.apiKeyAuth('X-Service-Token')(async (req, res) => {
  res.json({ data: 'service access' });
});
```

## `requireHeaders(headers)`

Require specific headers with optional value matching. Pass a `Record<string, string>` where keys are header names and values are expected values (empty string means any value is accepted).

```typescript
const handler = guard.requireHeaders({
  'X-Request-ID': '',
  'X-Client-Version': '2.0',
})(async (req, res) => {
  res.json({ ok: true });
});

app.post('/api/v2/data', handler);
```

In this example:
- `X-Request-ID` must be present (any value)
- `X-Client-Version` must be present with value `2.0`

## Combining Authentication Decorators

```typescript
const handler = guard.requireHttps()(
  guard.requireAuth('bearer')(
    guard.requireHeaders({
      'X-Request-ID': '',
    })(async (req, res) => {
      res.json({ secure: true, authenticated: true });
    })
  )
);

app.get('/api/admin', handler);
```
