---
editUrl: false
next: false
prev: false
title: "NestResponseFactory"
---

Defined in: [nestjs/src/adapters.ts:42](https://github.com/rennf93/guard-core-ts/blob/3e2d853c83968c3c17771a7b42062692ebe97b52/packages/nestjs/src/adapters.ts#L42)

## Implements

- [`GuardResponseFactory`](/guard-core-ts/api/core/src/interfaces/guardresponsefactory/)

## Constructors

### Constructor

> **new NestResponseFactory**(): `NestResponseFactory`

#### Returns

`NestResponseFactory`

## Methods

### createRedirectResponse()

> **createRedirectResponse**(`url`, `statusCode`): [`GuardResponse`](/guard-core-ts/api/core/src/interfaces/guardresponse/)

Defined in: [nestjs/src/adapters.ts:47](https://github.com/rennf93/guard-core-ts/blob/3e2d853c83968c3c17771a7b42062692ebe97b52/packages/nestjs/src/adapters.ts#L47)

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

Defined in: [nestjs/src/adapters.ts:43](https://github.com/rennf93/guard-core-ts/blob/3e2d853c83968c3c17771a7b42062692ebe97b52/packages/nestjs/src/adapters.ts#L43)

#### Parameters

##### content

`string`

##### statusCode

`number`

#### Returns

[`GuardResponse`](/guard-core-ts/api/core/src/interfaces/guardresponse/)

#### Implementation of

[`GuardResponseFactory`](/guard-core-ts/api/core/src/interfaces/guardresponsefactory/).[`createResponse`](/guard-core-ts/api/core/src/interfaces/guardresponsefactory/#createresponse)
