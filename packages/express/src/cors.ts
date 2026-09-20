import { createRequire } from 'module';
import type { Express, RequestHandler } from 'express';
import type { ResolvedSecurityConfig } from '@guardcore/core';

type CorsMiddlewareFactory = (options?: Record<string, unknown>) => RequestHandler;

/**
 * Loads the optional "cors" peer dependency. The package ships dual ESM/CJS
 * builds, so `require` must not be assumed to exist: in the ESM build it is
 * undefined and resolution has to go through `createRequire`.
 */
function loadCors(): CorsMiddlewareFactory | null {
  try {
    if (typeof require === 'function') {
      return require('cors') as CorsMiddlewareFactory;
    }
  } catch {
    // fall through to createRequire
  }
  try {
    return createRequire(import.meta.url)('cors') as CorsMiddlewareFactory;
  } catch {
    return null;
  }
}

export function configureCors(app: Express, config: ResolvedSecurityConfig): void {
  if (!config.enableCors) return;

  try {
    const corsMiddleware = loadCors();
    if (!corsMiddleware) {
      throw new Error('cors package is not installed');
    }
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
