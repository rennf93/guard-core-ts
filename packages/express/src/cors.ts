import type { Express } from 'express';
import type { ResolvedSecurityConfig } from '@guardcore/core';

export function configureCors(app: Express, config: ResolvedSecurityConfig): void {
  if (!config.enableCors) return;

  try {
    const corsMiddleware = require('cors');
    app.use(corsMiddleware({
      origin: config.corsAllowOrigins,
      methods: config.corsAllowMethods,
      allowedHeaders: config.corsAllowHeaders,
      credentials: config.corsAllowCredentials,
      exposedHeaders: config.corsExposeHeaders,
      maxAge: config.corsMaxAge,
    }));
  } catch {
    throw new Error(
      '@guardcore/express: CORS is enabled but the "cors" package is not installed. ' +
      'Run: pnpm add cors',
    );
  }
}
