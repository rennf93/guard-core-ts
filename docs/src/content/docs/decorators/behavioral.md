---
title: "Behavioral Decorators"
description: "Usage monitoring, return pattern tracking, frequency analysis, and behavioral actions"
---

Behavioral decorators track request and response patterns over time to detect abuse that cannot be caught by single-request checks.

## Actions

All behavioral decorators accept an `action` parameter:

| Action | Behavior |
|--------|----------|
| `'ban'` | Ban the IP for the configured `autoBanDuration` |
| `'log'` | Log the violation without blocking |
| `'throttle'` | Log a throttle event (apply throttling in your handler) |
| `'alert'` | Log a warning-level alert |

## `usageMonitor(maxCalls, window?, action?)`

Monitor how many times a specific endpoint is called by the same IP within a time window.

**Parameters**:
- `maxCalls` -- Maximum allowed calls before triggering the action
- `window` -- Time window in seconds (default: `3600`)
- `action` -- Action to take when threshold is exceeded (default: `'ban'`)

```typescript
const handler = guard.usageMonitor(100, 3600, 'ban')(async (req, res) => {
  res.json({ data: 'monitored' });
});

app.get('/api/data', handler);
```

This bans any IP that calls `/api/data` more than 100 times in an hour.

## `returnMonitor(pattern, maxOccurrences, window?, action?)`

Monitor response patterns. Triggers when a specific response pattern occurs too many times for the same IP on the same endpoint.

**Parameters**:
- `pattern` -- Pattern to match against responses (see pattern formats below)
- `maxOccurrences` -- Maximum times the pattern can match before triggering
- `window` -- Time window in seconds (default: `86400`)
- `action` -- Action to take (default: `'ban'`)

```typescript
const handler = guard.returnMonitor('status:404', 50, 3600, 'ban')(async (req, res) => {
  const item = await db.find(req.params.id);
  if (!item) return res.status(404).json({ error: 'not found' });
  res.json(item);
});

app.get('/api/items/:id', handler);
```

This bans IPs that trigger 50+ 404 responses in an hour (directory enumeration detection).

### Pattern Formats

| Prefix | Matching Logic | Example |
|--------|---------------|---------|
| `status:` | Matches response status code | `status:404` |
| `json:` | Checks for existence of a JSON path in response body | `json:error.code` |
| `regex:` | Tests response body against a regex (case-insensitive) | `regex:unauthorized\|forbidden` |
| *(none)* | Substring match against response body | `"error"` |

**`status:`** -- Matches the exact status code:
```typescript
guard.returnMonitor('status:401', 10, 600, 'ban')
```

**`json:`** -- Traverses a dot-separated path in the parsed JSON body:
```typescript
guard.returnMonitor('json:error.type', 20, 3600, 'alert')
```

**`regex:`** -- Tests the body text against a regular expression:
```typescript
guard.returnMonitor('regex:invalid.*token', 5, 300, 'ban')
```

## `behaviorAnalysis(rules)`

Apply multiple custom `BehaviorRule` instances to a route.

```typescript
import { BehaviorRule } from '@guardcore/core';

const handler = guard.behaviorAnalysis([
  new BehaviorRule('usage', 50, 3600, null, 'throttle'),
  new BehaviorRule('return_pattern', 10, 600, 'status:429', 'ban'),
  new BehaviorRule('frequency', 200, 300, null, 'alert'),
])(async (req, res) => {
  res.json({ data: 'analyzed' });
});
```

`BehaviorRule` constructor:
```typescript
new BehaviorRule(
  ruleType: 'usage' | 'return_pattern' | 'frequency',
  threshold: number,
  window: number,
  pattern: string | null,
  action: 'ban' | 'log' | 'throttle' | 'alert',
  customAction?: ((...args: unknown[]) => unknown) | null,
)
```

## `suspiciousFrequency(maxFrequency, window?, action?)`

Flag IPs making requests at a suspiciously high frequency.

**Parameters**:
- `maxFrequency` -- Maximum requests before flagging
- `window` -- Time window in seconds (default: `300`)
- `action` -- Action to take (default: `'ban'`)

```typescript
const handler = guard.suspiciousFrequency(50, 60, 'ban')(async (req, res) => {
  res.json({ data: 'frequency-monitored' });
});

app.post('/api/submit', handler);
```

## Gaming Anti-Exploit Example

```typescript
import { BehaviorRule } from '@guardcore/core';

const redeemHandler = guard.usageMonitor(5, 3600, 'ban')(
  guard.returnMonitor('status:200', 3, 86400, 'alert')(
    guard.returnMonitor('json:error.code', 10, 3600, 'ban')(
      guard.suspiciousFrequency(20, 60, 'ban')(async (req, res) => {
        const result = await redeemReward(req.body);
        if (result.error) {
          return res.status(400).json({ error: result.error });
        }
        res.json({ reward: result.reward });
      })
    )
  )
);

app.post('/api/game/redeem', redeemHandler);
```

This setup:
- Limits each IP to 5 redemptions per hour
- Alerts if the same IP gets 3+ successful redemptions in 24 hours
- Bans IPs that trigger 10+ errors in an hour
- Bans IPs making more than 20 requests per minute
