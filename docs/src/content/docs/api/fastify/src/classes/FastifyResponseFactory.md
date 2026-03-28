---
editUrl: false
next: false
prev: false
title: "FastifyResponseFactory"
---

Defined in: [fastify/src/adapters.ts:43](https://github.com/rennf93/guard-core-ts/blob/3e2d853c83968c3c17771a7b42062692ebe97b52/packages/fastify/src/adapters.ts#L43)

## Implements

- [`GuardResponseFactory`](/guard-core-ts/api/core/src/interfaces/guardresponsefactory/)

## Constructors

### Constructor

> **new FastifyResponseFactory**(): `FastifyResponseFactory`

#### Returns

`FastifyResponseFactory`

## Methods

### createRedirectResponse()

> **createRedirectResponse**(`url`, `statusCode`): [`GuardResponse`](/guard-core-ts/api/core/src/interfaces/guardresponse/)

Defined in: [fastify/src/adapters.ts:48](https://github.com/rennf93/guard-core-ts/blob/3e2d853c83968c3c17771a7b42062692ebe97b52/packages/fastify/src/adapters.ts#L48)

#### Parameters

##### url

`string`

##### statusCode

`number`

#### Returns

[`GuardResponse`](/guard-core-ts/api/core/src/interfaces/guardresponse/)

#### Implementation of

[`GuardResponseFactory`](/guard-core-ts/api/core/src/interfaces/guardresponsefactory/).[`createRedirectResponse`](/guard-core-ts/api/core/src/interfaces/guardresponsefactory/#createredirectresponse)

***

### createResponse()

> **createResponse**(`content`, `statusCode`): [`GuardResponse`](/guard-core-ts/api/core/src/interfaces/guardresponse/)

Defined in: [fastify/src/adapters.ts:44](https://github.com/rennf93/guard-core-ts/blob/3e2d853c83968c3c17771a7b42062692ebe97b52/packages/fastify/src/adapters.ts#L44)

#### Parameters

##### content

`string`

##### statusCode

`number`

#### Returns

[`GuardResponse`](/guard-core-ts/api/core/src/interfaces/guardresponse/)

#### Implementation of

[`GuardResponseFactory`](/guard-core-ts/api/core/src/interfaces/guardresponsefactory/).[`createResponse`](/guard-core-ts/api/core/src/interfaces/guardresponsefactory/#createresponse)
