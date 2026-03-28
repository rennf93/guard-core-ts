---
editUrl: false
next: false
prev: false
title: "NestGuardResponse"
---

Defined in: [nestjs/src/adapters.ts:27](https://github.com/rennf93/guard-core-ts/blob/3e2d853c83968c3c17771a7b42062692ebe97b52/packages/nestjs/src/adapters.ts#L27)

## Implements

- [`GuardResponse`](/guard-core-ts/api/core/src/interfaces/guardresponse/)

## Constructors

### Constructor

> **new NestGuardResponse**(`statusCode`, `content`): `NestGuardResponse`

Defined in: [nestjs/src/adapters.ts:31](https://github.com/rennf93/guard-core-ts/blob/3e2d853c83968c3c17771a7b42062692ebe97b52/packages/nestjs/src/adapters.ts#L31)

#### Parameters

##### statusCode

`number`

##### content

`string`

#### Returns

`NestGuardResponse`

## Properties

### statusCode

> `readonly` **statusCode**: `number`

Defined in: [nestjs/src/adapters.ts:31](https://github.com/rennf93/guard-core-ts/blob/3e2d853c83968c3c17771a7b42062692ebe97b52/packages/nestjs/src/adapters.ts#L31)

#### Implementation of

[`GuardResponse`](/guard-core-ts/api/core/src/interfaces/guardresponse/).[`statusCode`](/guard-core-ts/api/core/src/interfaces/guardresponse/#statuscode)

## Accessors

### body

#### Get Signature

> **get** **body**(): `Uint8Array`\<`ArrayBufferLike`\> \| `null`

Defined in: [nestjs/src/adapters.ts:38](https://github.com/rennf93/guard-core-ts/blob/3e2d853c83968c3c17771a7b42062692ebe97b52/packages/nestjs/src/adapters.ts#L38)

##### Returns

`Uint8Array`\<`ArrayBufferLike`\> \| `null`

#### Implementation of

[`GuardResponse`](/guard-core-ts/api/core/src/interfaces/guardresponse/).[`body`](/guard-core-ts/api/core/src/interfaces/guardresponse/#body)

***

### bodyText

#### Get Signature

> **get** **bodyText**(): `string` \| `null`

Defined in: [nestjs/src/adapters.ts:39](https://github.com/rennf93/guard-core-ts/blob/3e2d853c83968c3c17771a7b42062692ebe97b52/packages/nestjs/src/adapters.ts#L39)

##### Returns

`string` \| `null`

#### Implementation of

[`GuardResponse`](/guard-core-ts/api/core/src/interfaces/guardresponse/).[`bodyText`](/guard-core-ts/api/core/src/interfaces/guardresponse/#bodytext)

***

### headers

#### Get Signature

> **get** **headers**(): `Record`\<`string`, `string`\>

Defined in: [nestjs/src/adapters.ts:36](https://github.com/rennf93/guard-core-ts/blob/3e2d853c83968c3c17771a7b42062692ebe97b52/packages/nestjs/src/adapters.ts#L36)

##### Returns

`Record`\<`string`, `string`\>

#### Implementation of

[`GuardResponse`](/guard-core-ts/api/core/src/interfaces/guardresponse/).[`headers`](/guard-core-ts/api/core/src/interfaces/guardresponse/#headers)

## Methods

### setHeader()

> **setHeader**(`name`, `value`): `void`

Defined in: [nestjs/src/adapters.ts:37](https://github.com/rennf93/guard-core-ts/blob/3e2d853c83968c3c17771a7b42062692ebe97b52/packages/nestjs/src/adapters.ts#L37)

#### Parameters

##### name

`string`

##### value

`string`

#### Returns

`void`

#### Implementation of

[`GuardResponse`](/guard-core-ts/api/core/src/interfaces/guardresponse/).[`setHeader`](/guard-core-ts/api/core/src/interfaces/guardresponse/#setheader)
