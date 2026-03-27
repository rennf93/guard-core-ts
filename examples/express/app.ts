import express from 'express';
import {
  createSecurityMiddleware,
  configureCors,
  guardBodyParser,
  SecurityConfigSchema,
  SecurityDecorator,
  BehaviorRule,
} from '@guardcore/express';

const config = SecurityConfigSchema.parse({
  blacklist: ['192.168.100.0/24'],
  trustedProxies: ['172.16.0.0/12', '10.0.0.0/8'],
  trustedProxyDepth: 1,
  trustXForwardedProto: true,

  blockCloudProviders: ['AWS', 'GCP', 'Azure'],
  blockedUserAgents: ['badbot', 'evil-crawler', 'sqlmap'],

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
    csp: {
      'default-src': ["'self'"],
      'script-src': ["'self'", "'strict-dynamic'"],
      'style-src': ["'self'", "'unsafe-inline'"],
    },
    frameOptions: 'SAMEORIGIN',
    referrerPolicy: 'strict-origin-when-cross-origin',
  },

  enableCors: true,
  corsAllowOrigins: ['http://localhost:3000'],
  corsAllowCredentials: true,

  excludePaths: ['/health'],
});

const guard = new SecurityDecorator(config);
const app = express();

app.use(guardBodyParser());
configureCors(app, config);
app.use(createSecurityMiddleware({ config, guardDecorator: guard }));

app.get('/health', (_req, res) => {
  res.json({ status: 'healthy' });
});

app.get('/', (_req, res) => {
  res.json({
    message: '@guardcore/express example',
    routes: {
      '/health': 'Health check (excluded from security)',
      '/basic': 'Basic protected endpoint',
      '/ip-whitelist': 'IP whitelist enforcement',
      '/bearer-auth': 'Bearer token authentication',
      '/rate-limited': 'Custom rate limit (5 req/min)',
      '/geo-rate-limited': 'Geographic rate limiting',
      '/usage-monitored': 'Usage pattern monitoring',
      '/no-cloud': 'Block cloud provider IPs',
      '/country-block': 'Block specific countries',
    },
  });
});

function basicHandler(_req: express.Request, res: express.Response) {
  res.json({ message: 'Access granted' });
}

function ipWhitelistHandler(_req: express.Request, res: express.Response) {
  res.json({ message: 'Access granted from whitelisted IP' });
}
guard.requireIp(['127.0.0.1', '10.0.0.0/8'])(ipWhitelistHandler);

function bearerAuthHandler(_req: express.Request, res: express.Response) {
  res.json({ authenticated: true, method: 'bearer' });
}
guard.requireAuth('bearer')(bearerAuthHandler);

function rateLimitedHandler(_req: express.Request, res: express.Response) {
  res.json({ message: 'Custom rate limit endpoint', limit: '5 req/60s' });
}
guard.rateLimit(5, 60)(rateLimitedHandler);

function geoRateLimitedHandler(_req: express.Request, res: express.Response) {
  res.json({ message: 'Geographic rate limiting applied' });
}
guard.geoRateLimit({ US: [100, 60], CN: [10, 60], '*': [50, 60] })(geoRateLimitedHandler);

function usageMonitoredHandler(_req: express.Request, res: express.Response) {
  res.json({ message: 'Usage monitoring active' });
}
guard.usageMonitor(10, 300, 'log')(usageMonitoredHandler);

function noCloudHandler(_req: express.Request, res: express.Response) {
  res.json({ message: 'Access granted - not from cloud provider' });
}
guard.blockClouds()(noCloudHandler);

function countryBlockHandler(_req: express.Request, res: express.Response) {
  res.json({ message: 'Access granted - your country is not blocked' });
}
guard.blockCountries(['CN', 'RU', 'KP'])(countryBlockHandler);

app.get('/basic', basicHandler);
app.get('/ip-whitelist', ipWhitelistHandler);
app.get('/bearer-auth', bearerAuthHandler);
app.get('/rate-limited', rateLimitedHandler);
app.get('/geo-rate-limited', geoRateLimitedHandler);
app.get('/usage-monitored', usageMonitoredHandler);
app.get('/no-cloud', noCloudHandler);
app.get('/country-block', countryBlockHandler);

const PORT = process.env['PORT'] ?? 3000;
app.listen(PORT, () => {
  console.log(`@guardcore/express example running on port ${PORT}`);
});
