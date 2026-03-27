import { Hono } from 'hono';
import {
  createGuardMiddleware,
  configureCors,
  SecurityConfigSchema,
  SecurityDecorator,
} from '@guardcore/hono';

const config = SecurityConfigSchema.parse({
  blockedUserAgents: ['badbot', 'sqlmap'],

  enableRateLimiting: true,
  rateLimit: 30,
  rateLimitWindow: 60,

  enablePenetrationDetection: true,

  enableRedis: false,

  securityHeaders: {
    enabled: true,
    csp: { 'default-src': ["'self'"] },
  },

  enableCors: true,
  corsAllowOrigins: ['*'],

  excludePaths: ['/health'],
});

const guard = new SecurityDecorator(config);
const app = new Hono();

configureCors(app, config);
app.use('*', createGuardMiddleware({ config, guardDecorator: guard }));

app.get('/health', (c) => c.json({ status: 'healthy' }));

app.get('/', (c) => c.json({
  message: '@guardcore/hono example (edge-safe)',
  routes: {
    '/health': 'Health check',
    '/basic': 'Basic protected endpoint',
    '/rate-limited': 'Custom rate limit',
  },
}));

function basicHandler() {}
app.get('/basic', (c) => c.json({ message: 'Access granted' }));

function rateLimitedHandler() {}
guard.rateLimit(5, 60)(rateLimitedHandler);
app.get('/rate-limited', (c) => c.json({ message: 'Rate limited', limit: '5 req/60s' }));

export default app;
