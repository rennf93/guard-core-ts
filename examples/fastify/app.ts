import Fastify from 'fastify';
import {
  guardPlugin,
  configureCors,
  SecurityConfigSchema,
  SecurityDecorator,
} from '@guardcore/fastify';

const config = SecurityConfigSchema.parse({
  blacklist: ['192.168.100.0/24'],
  trustedProxies: ['172.16.0.0/12', '10.0.0.0/8'],
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

  logFormat: 'json',

  securityHeaders: {
    enabled: true,
    hsts: { maxAge: 31536000, includeSubdomains: true, preload: false },
    csp: { 'default-src': ["'self'"] },
  },

  enableCors: true,
  corsAllowOrigins: ['http://localhost:3000'],

  excludePaths: ['/health'],
});

const guard = new SecurityDecorator(config);
const app = Fastify({ logger: true });

async function start() {
  await configureCors(app, config);
  await app.register(guardPlugin, { config, guardDecorator: guard });

  app.get('/health', async () => ({ status: 'healthy' }));

  app.get('/', async () => ({
    message: '@guardcore/fastify example',
    routes: {
      '/health': 'Health check',
      '/basic': 'Basic protected endpoint',
      '/rate-limited': 'Custom rate limit (5 req/min)',
      '/bearer-auth': 'Bearer token authentication',
      '/no-cloud': 'Block cloud provider IPs',
    },
  }));

  function basicHandler() { return { message: 'Access granted' }; }
  app.get('/basic', basicHandler);

  function rateLimitedHandler() { return { message: 'Custom rate limit', limit: '5 req/60s' }; }
  guard.rateLimit(5, 60)(rateLimitedHandler);
  app.get('/rate-limited', rateLimitedHandler);

  function bearerAuthHandler() { return { authenticated: true, method: 'bearer' }; }
  guard.requireAuth('bearer')(bearerAuthHandler);
  app.get('/bearer-auth', bearerAuthHandler);

  function noCloudHandler() { return { message: 'Not from cloud provider' }; }
  guard.blockClouds()(noCloudHandler);
  app.get('/no-cloud', noCloudHandler);

  const port = Number(process.env['PORT'] ?? 3000);
  await app.listen({ port });
  console.log(`@guardcore/fastify example running on port ${port}`);
}

start();
