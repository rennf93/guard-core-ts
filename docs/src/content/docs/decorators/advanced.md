---
title: "Advanced Decorators"
description: "Time window restrictions, suspicious detection toggle, and honeypot form fields"
---

## `timeWindow(startTime, endTime)`

Restrict access to a route within a specific time window (UTC). Requests outside the window receive a 403.

**Parameters**:
- `startTime` -- Start time in `HH:MM` format
- `endTime` -- End time in `HH:MM` format

```typescript
const handler = guard.timeWindow('09:00', '17:00')(async (req, res) => {
  res.json({ data: 'business hours only' });
});

app.get('/api/trading', handler);
```

This allows access only between 09:00 and 17:00 UTC.

### Overnight windows

```typescript
const handler = guard.timeWindow('22:00', '06:00')(async (req, res) => {
  res.json({ data: 'maintenance window' });
});
```

When `startTime` is greater than `endTime`, the window wraps around midnight.

## `suspiciousDetection(enabled?)`

Toggle the penetration detection engine for a specific route. By default, detection is enabled on all routes (inheriting from `config.enablePenetrationDetection`).

**Parameters**:
- `enabled` -- Whether to enable detection (default: `true`)

Disable detection on a route that expects user-generated content with code snippets:

```typescript
const handler = guard.suspiciousDetection(false)(async (req, res) => {
  res.json({ saved: true });
});

app.post('/api/code-snippets', handler);
```

Re-enable detection on a route where it was globally disabled:

```typescript
const handler = guard.suspiciousDetection(true)(async (req, res) => {
  res.json({ data: 'scanned' });
});

app.post('/api/comments', handler);
```

## `honeypotDetection(trapFields)`

Add invisible form fields that legitimate users never fill in. If any trap field contains a value, the request is blocked with a 403.

**Parameters**:
- `trapFields` -- Array of field names that should remain empty

```typescript
const handler = guard.honeypotDetection([
  'website',
  'fax_number',
  'middle_name_2',
])(async (req, res) => {
  res.json({ submitted: true });
});

app.post('/api/contact', handler);
```

The detection works with both `application/json` and `application/x-www-form-urlencoded` content types.

**JSON request body**:
```json
{
  "name": "John",
  "email": "john@example.com",
  "website": ""
}
```
This passes because `website` is empty.

```json
{
  "name": "Bot",
  "email": "bot@spam.com",
  "website": "http://spam.com"
}
```
This is blocked because `website` has a value.

### Frontend implementation

Add hidden fields to your form that are invisible to users:

```html
<form action="/api/contact" method="POST">
  <input type="text" name="name" />
  <input type="email" name="email" />

  <!-- Honeypot fields - hidden from users -->
  <div style="display: none;" aria-hidden="true">
    <input type="text" name="website" tabindex="-1" autocomplete="off" />
    <input type="text" name="fax_number" tabindex="-1" autocomplete="off" />
  </div>

  <button type="submit">Send</button>
</form>
```

Bots that auto-fill all form fields will populate the hidden fields and get blocked.

## Combining Advanced Decorators

```typescript
const handler = guard.timeWindow('09:00', '17:00')(
  guard.honeypotDetection(['phone_2', 'address_2'])(
    guard.suspiciousDetection(true)(async (req, res) => {
      res.json({ submitted: true });
    })
  )
);

app.post('/api/applications', handler);
```
