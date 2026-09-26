/**
 * Middleware-level parity tests for geo rate limits (guard-core
 * RateLimitCheck._check_geo_rate_limit port, with the Go tiersFor tier
 * selection: country-specific entry first, "*" fallback tier second, no
 * match = no geo tier).
 *
 * Every vector below goes through the real pipeline built by
 * initializeSecurityMiddleware: the geoRateLimits route selector that the
 * geoRateLimit decorator writes is finally enforced, with the request's
 * country resolved through the middleware's geoip handler. Without a geo
 * handler (or without a matching tier) the request falls through to the
 * default global limit, exactly like the reference.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initializeSecurityMiddleware } from '../../../src/middleware-support.js';
import type { SecurityMiddlewareComponents } from '../../../src/middleware-support.js';
import { SecurityConfigSchema } from '../../../src/models/config.js';
import { RouteConfig } from '../../../src/models/route-config.js';
import { defaultLogger } from '../../../src/models/logger.js';
import type { GeoIPHandler } from '../../../src/protocols/geo-ip.js';
import type { GuardRequest } from '../../../src/protocols/request.js';
import { createMockResponseFactory } from '../../helpers.js';

function makeGeoHandler(country: string | null): GeoIPHandler {
  return {
    isInitialized: true,
    async initialize() {},
    async initializeRedis() {},
    async initializeAgent() {},
    getCountry: () => country,
  };
}

function makeRequest(ip: string, urlPath = '/api/test'): GuardRequest {
  return {
    urlPath,
    urlScheme: 'https',
    urlFull: `https://example.com${urlPath}`,
    urlReplaceScheme: (s: string) => `${s}://example.com${urlPath}`,
    method: 'GET',
    clientHost: ip,
    headers: { 'user-agent': 'TestAgent/1.0' },
    queryParams: {},
    body: async () => new Uint8Array(0),
    state: {},
    scope: {},
  };
}

function withRoute(request: GuardRequest, routeConfig: RouteConfig): GuardRequest {
  (request.state as Record<string, unknown>)['_routeConfig'] = routeConfig;
  return request;
}

function geoRoute(limits: Record<string, [number, number]>): RouteConfig {
  const routeConfig = new RouteConfig();
  routeConfig.geoRateLimits = limits;
  return routeConfig;
}

async function build(
  geoHandler: GeoIPHandler | null,
  configOverrides: Record<string, unknown> = {},
): Promise<SecurityMiddlewareComponents> {
  const config = SecurityConfigSchema.parse({ enableRedis: false, ...configOverrides });
  return initializeSecurityMiddleware(config, defaultLogger, createMockResponseFactory(), null, geoHandler);
}

describe('geo rate limits are enforced (middleware level)', () => {
  const geComponents: SecurityMiddlewareComponents[] = [];
  let deComponents: SecurityMiddlewareComponents;
  let fallbackComponents: SecurityMiddlewareComponents;
  let noMatchComponents: SecurityMiddlewareComponents;
  let noHandlerComponents: SecurityMiddlewareComponents;
  let passiveComponents: SecurityMiddlewareComponents;

  beforeAll(async () => {
    deComponents = await build(makeGeoHandler('DE'), { rateLimit: 100, rateLimitWindow: 60 });
    fallbackComponents = await build(makeGeoHandler('FR'), { rateLimit: 100, rateLimitWindow: 60 });
    noMatchComponents = await build(makeGeoHandler('FR'), { rateLimit: 100, rateLimitWindow: 60 });
    noHandlerComponents = await build(null, { rateLimit: 3, rateLimitWindow: 60 });
    passiveComponents = await build(makeGeoHandler('DE'), {
      rateLimit: 100, rateLimitWindow: 60, passiveMode: true,
    });
    geComponents.push(deComponents, fallbackComponents, noMatchComponents, noHandlerComponents, passiveComponents);
    /* Warm each pipeline so the detection engine's one-time pattern-table
       compile lands inside the hook and every test's first execute is fast. */
    for (const components of geComponents) {
      await components.pipeline.execute(makeRequest('192.0.2.200'));
    }
  }, 60000);

  it('enforces a country-specific tier for the resolved country', async () => {
    const routeConfig = geoRoute({ DE: [2, 60] });

    expect(await deComponents.pipeline.execute(
      withRoute(makeRequest('203.0.113.1'), routeConfig),
    )).toBeNull();
    expect(await deComponents.pipeline.execute(
      withRoute(makeRequest('203.0.113.1'), routeConfig),
    )).toBeNull();
    const throttled = await deComponents.pipeline.execute(
      withRoute(makeRequest('203.0.113.1'), routeConfig),
    );

    expect(throttled).not.toBeNull();
    expect(throttled!.statusCode).toBe(429);
  });

  it('the geo tier counts per IP and endpoint like every endpoint-scoped tier', async () => {
    const routeConfig = geoRoute({ DE: [1, 60] });
    const ip = '203.0.113.2';

    expect(await deComponents.pipeline.execute(
      withRoute(makeRequest(ip, '/geo-a'), routeConfig),
    )).toBeNull();
    expect((await deComponents.pipeline.execute(
      withRoute(makeRequest(ip, '/geo-a'), routeConfig),
    ))!.statusCode).toBe(429);

    /* Another endpoint is a separate bucket for the same client. */
    expect(await deComponents.pipeline.execute(
      withRoute(makeRequest(ip, '/geo-b'), routeConfig),
    )).toBeNull();
  });

  it("falls back to the '*' tier when the resolved country has no entry", async () => {
    const routeConfig = geoRoute({ DE: [50, 60], '*': [2, 60] });
    const ip = '203.0.113.3';

    expect(await fallbackComponents.pipeline.execute(
      withRoute(makeRequest(ip), routeConfig),
    )).toBeNull();
    expect(await fallbackComponents.pipeline.execute(
      withRoute(makeRequest(ip), routeConfig),
    )).toBeNull();
    expect((await fallbackComponents.pipeline.execute(
      withRoute(makeRequest(ip), routeConfig),
    ))!.statusCode).toBe(429);
  });

  it('applies no geo tier when no entry and no fallback match, using the default limit', async () => {
    const routeConfig = geoRoute({ DE: [2, 60] });
    const ip = '203.0.113.4';

    for (let i = 0; i < 5; i++) {
      expect(await noMatchComponents.pipeline.execute(
        withRoute(makeRequest(ip), routeConfig),
      )).toBeNull();
    }
  });

  it('falls back to the default limit when no geo handler is configured', async () => {
    const routeConfig = geoRoute({ DE: [100, 60] });
    const ip = '203.0.113.5';

    /* The geo tier would have allowed 100 requests; the default limit is 3,
       proving the request resolves to the global tier. */
    expect(await noHandlerComponents.pipeline.execute(
      withRoute(makeRequest(ip), routeConfig),
    )).toBeNull();
    expect(await noHandlerComponents.pipeline.execute(
      withRoute(makeRequest(ip), routeConfig),
    )).toBeNull();
    expect(await noHandlerComponents.pipeline.execute(
      withRoute(makeRequest(ip), routeConfig),
    )).toBeNull();
    const throttled = await noHandlerComponents.pipeline.execute(
      withRoute(makeRequest(ip), routeConfig),
    );
    expect(throttled).not.toBeNull();
    expect(throttled!.statusCode).toBe(429);
  });

  it('an unresolved country uses the fallback tier when present', async () => {
    const unresolvedComponents = await build(makeGeoHandler(null), { rateLimit: 100, rateLimitWindow: 60 });
    const routeConfig = geoRoute({ '*': [1, 60] });
    const ip = '203.0.113.6';

    expect(await unresolvedComponents.pipeline.execute(
      withRoute(makeRequest(ip), routeConfig),
    )).toBeNull();
    expect((await unresolvedComponents.pipeline.execute(
      withRoute(makeRequest(ip), routeConfig),
    ))!.statusCode).toBe(429);
  });

  it('passive mode logs the geo tier violation but lets the request through', async () => {
    const routeConfig = geoRoute({ DE: [1, 60] });
    const ip = '203.0.113.7';

    expect(await passiveComponents.pipeline.execute(
      withRoute(makeRequest(ip), routeConfig),
    )).toBeNull();
    expect(await passiveComponents.pipeline.execute(
      withRoute(makeRequest(ip), routeConfig),
    )).toBeNull();
  });
});
