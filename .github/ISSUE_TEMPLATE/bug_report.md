---
name: Bug Report
about: Report a bug in @guardcore
title: '[BUG] '
labels: bug
assignees: ''
---

## Bug Description

<!-- A clear and concise description of what the bug is -->

## Steps To Reproduce

1.
2.
3.
4.

## Expected Behavior

<!-- What you expected to happen -->

## Actual Behavior

<!-- What actually happened. Include error messages, stack traces, or logs -->

```
Paste error output here
```

## Environment

- **Node.js version**:
- **Package manager**: pnpm / npm / yarn / bun
- **@guardcore/core version**:
- **Adapter package**: @guardcore/express | @guardcore/fastify | @guardcore/nestjs | @guardcore/hono
- **Adapter version**:
- **OS**:
- **Redis version** (if applicable):

## Configuration

```typescript
import { SecurityConfigSchema } from '@guardcore/core';

const config = SecurityConfigSchema.parse({
  // Your configuration here
});
```

## Additional Context

- Is this in production or development?
- Does it happen consistently or intermittently?
- Have you found a workaround?
