import type { Hono } from 'hono';
import { cors } from 'hono/cors';
import type { ResolvedSecurityConfig } from '@guardcore/core';

export function configureCors(app: Hono, config: ResolvedSecurityConfig): void {
  if (!config.enableCors) return;

  app.use('*', cors({
    origin: config.corsAllowOrigins,
    allowMethods: config.corsAllowMethods,
    allowHeaders: config.corsAllowHeaders,
    credentials: config.corsAllowCredentials,
    exposeHeaders: config.corsExposeHeaders,
    maxAge: config.corsMaxAge,
  }));
}
