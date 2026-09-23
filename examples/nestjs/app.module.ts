import { Module } from '@nestjs/common';
import { GuardModule } from '@guardcore/nestjs';
import { AppController } from './app.controller.js';

@Module({
  imports: [
    GuardModule.forRoot({
      config: {
        blockedUserAgents: ['badbot', 'sqlmap'],

        enableRateLimiting: true,
        rateLimit: 30,
        rateLimitWindow: 60,

        enableIpBanning: true,
        autoBanThreshold: 5,
        autoBanDuration: 300,

        enablePenetrationDetection: true,

        enableRedis: true,
        redisUrl: process.env['REDIS_URL'] ?? 'redis://localhost:6379',

        securityHeaders: {
          enabled: true,
          csp: { 'default-src': ["'self'"] },
        },

        excludePaths: ['/health'],
      },
    }),
  ],
  controllers: [AppController],
})
export class AppModule {}
