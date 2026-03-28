---
editUrl: false
next: false
prev: false
title: "SecurityMiddlewareNest"
---

Defined in: [nestjs/src/guard-module.ts:26](https://github.com/rennf93/guard-core-ts/blob/3e2d853c83968c3c17771a7b42062692ebe97b52/packages/nestjs/src/guard-module.ts#L26)

## Implements

- `NestMiddleware`

## Constructors

### Constructor

> **new SecurityMiddlewareNest**(`components`): `SecurityMiddlewareNest`

Defined in: [nestjs/src/guard-module.ts:27](https://github.com/rennf93/guard-core-ts/blob/3e2d853c83968c3c17771a7b42062692ebe97b52/packages/nestjs/src/guard-module.ts#L27)

#### Parameters

##### components

[`SecurityMiddlewareComponents`](/guard-core-ts/api/core/src/interfaces/securitymiddlewarecomponents/)

#### Returns

`SecurityMiddlewareNest`

## Methods

### use()

> **use**(`req`, `res`, `next`): `Promise`\<`void`\>

Defined in: [nestjs/src/guard-module.ts:31](https://github.com/rennf93/guard-core-ts/blob/3e2d853c83968c3c17771a7b42062692ebe97b52/packages/nestjs/src/guard-module.ts#L31)

#### Parameters

##### req

`Request`

##### res

`Response`

##### next

`NextFunction`

#### Returns

`Promise`\<`void`\>

#### Implementation of

`NestMiddleware.use`
