# @guardcore/nestjs Example

## Setup

```bash
npm install @nestjs/core @nestjs/common @nestjs/platform-express @guardcore/core @guardcore/nestjs reflect-metadata rxjs
```

## Usage

Import `GuardModule.forRoot()` in your root module:

```typescript
import { Module } from '@nestjs/common';
import { GuardModule } from '@guardcore/nestjs';

@Module({
  imports: [
    GuardModule.forRoot({
      config: {
        enableRateLimiting: true,
        rateLimit: 30,
        rateLimitWindow: 60,
        enablePenetrationDetection: true,
      },
    }),
  ],
})
export class AppModule {}
```

The `GuardModule` registers a global `NestMiddleware` that runs the full security pipeline on every request. No per-controller setup needed.

## SecurityDecorator

For per-route configuration, use `SecurityDecorator` on your controller methods:

```typescript
import { Controller, Get } from '@nestjs/common';
import { SecurityDecorator, SecurityConfigSchema } from '@guardcore/nestjs';

const guard = new SecurityDecorator(SecurityConfigSchema.parse({}));

@Controller('api')
export class ApiController {
  @Get('protected')
  getProtected() {
    return { message: 'Access granted' };
  }
}

guard.rateLimit(5, 60)(ApiController.prototype.getProtected);
guard.requireAuth('bearer')(ApiController.prototype.getProtected);
```
