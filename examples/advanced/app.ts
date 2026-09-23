import express from 'express';
import {
  createSecurityMiddleware,
  configureCors,
  guardBodyParser,
  SecurityConfigSchema,
  SecurityDecorator,
} from '@guardcore/express';

function positiveIntFromEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer, got: ${raw}`);
  }
  return parsed;
}

const burstLimit = positiveIntFromEnv('GUARD_BURST_LIMIT', 5);
const burstWindow = positiveIntFromEnv('GUARD_BURST_WINDOW', 60);

const configInput = {
  trustedProxies: ['172.16.0.0/12', '10.0.0.0/8'],
  trustedProxyDepth: 1,
  trustXForwardedProto: true,

  enableRateLimiting: true,
  rateLimit: positiveIntFromEnv('GUARD_RATE_LIMIT', 100),
  rateLimitWindow: positiveIntFromEnv('GUARD_RATE_LIMIT_WINDOW', 60),

  endpointRateLimits: {
    '/rate/burst': [burstLimit, burstWindow],
  },

  customErrorResponses: {
    429: process.env['GUARD_RATE_LIMIT_MESSAGE'] ?? 'Rate limit exceeded, slow down',
  },

  enablePenetrationDetection: true,

  enableRedis: process.env['GUARD_ENABLE_REDIS'] !== 'false',
  redisUrl: process.env['REDIS_URL'] ?? 'redis://localhost:6379',
  redisPrefix: process.env['REDIS_PREFIX'] ?? 'guard_core:',

  logFormat: 'json',

  securityHeaders: {
    enabled: true,
    csp: { 'default-src': ["'self'"] },
    frameOptions: 'SAMEORIGIN',
    referrerPolicy: 'strict-origin-when-cross-origin',
  },

  excludePaths: ['/health'],
};

const config = SecurityConfigSchema.parse(configInput);

const guard = new SecurityDecorator(config);
const app = express();

app.use(guardBodyParser());
configureCors(app, config);
app.use(createSecurityMiddleware({ config: configInput, guardDecorator: guard }));

const adminToken = process.env['ADMIN_TOKEN'] ?? 'admin-token-change-me';

function requireAdminToken(req: express.Request, res: express.Response, next: express.NextFunction): void {
  const token = req.header('X-Admin-Token');
  if (token !== adminToken) {
    res.status(400).json({ detail: 'Missing or invalid required header: X-Admin-Token' });
    return;
  }
  next();
}

app.get('/health', (_req, res) => {
  res.json({ status: 'healthy' });
});

app.get('/', (_req, res) => {
  res.json({
    message: '@guardcore/express advanced example',
    routes: {
      '/health': 'Health check (excluded from security)',
      '/admin/keys': 'Admin gate: requires the X-Admin-Token header',
      '/rate/burst': `Per-endpoint rate limit (${burstLimit} req/${burstWindow}s) with a custom 429 body`,
      '/search?q=...': 'Query parameter scanning; XSS payloads are blocked as suspicious activity',
    },
  });
});

app.get('/admin/keys', requireAdminToken, (_req, res) => {
  res.json({ message: 'Welcome, admin', keys: ['demo-key-1', 'demo-key-2'] });
});

app.get('/rate/burst', (_req, res) => {
  res.json({ message: 'Burst endpoint', limit: `${burstLimit} req/${burstWindow}s` });
});

app.get('/search', (req, res) => {
  res.json({ message: 'Search results', query: req.query['q'] ?? null });
});

const PORT = process.env['PORT'] ?? 3000;
app.listen(PORT, () => {
  console.log(`@guardcore/express advanced example running on port ${PORT}`);
});
