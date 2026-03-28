---
editUrl: false
next: false
prev: false
title: "sendAgentEvent"
---

> **sendAgentEvent**(`agentHandler`, `eventType`, `ipAddress`, `actionTaken`, `reason`, `request?`, `metadata?`): `Promise`\<`void`\>

Defined in: [core/src/utils.ts:25](https://github.com/rennf93/guard-core-ts/blob/3e2d853c83968c3c17771a7b42062692ebe97b52/packages/core/src/utils.ts#L25)

## Parameters

### agentHandler

[`AgentHandlerProtocol`](/guard-core-ts/api/core/src/interfaces/agenthandlerprotocol/) \| `null`

### eventType

`string`

### ipAddress

`string`

### actionTaken

`string`

### reason

`string`

### request?

[`GuardRequest`](/guard-core-ts/api/core/src/interfaces/guardrequest/) \| `null`

### metadata?

`Record`\<`string`, `unknown`\>

## Returns

`Promise`\<`void`\>
