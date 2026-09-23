import { Controller, Get } from '@nestjs/common';

@Controller()
export class AppController {
  @Get('health')
  health() {
    return { status: 'healthy' };
  }

  @Get()
  root() {
    return {
      message: '@guardcore/nestjs example',
      routes: {
        '/health': 'Health check (excluded from security)',
        '/basic': 'Basic protected endpoint',
      },
    };
  }

  @Get('basic')
  basic() {
    return { message: 'Access granted' };
  }
}
