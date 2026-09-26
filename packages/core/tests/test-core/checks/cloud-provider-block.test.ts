/**
 * Middleware-level parity tests for the cloud-provider block (guard-core
 * CloudProviderCheck port).
 *
 * Every vector below goes through the real pipeline built by
 * initializeSecurityMiddleware, mirroring the reference acceptance semantics
 * (guard_core/core/checks/implementations/cloud_provider.py): a request IP
 * that resolves to a selected provider is blocked with 403 unless passive
 * mode, whitelist and exempt_ips matches skip the check entirely, route-level
 * bypass(["clouds"]) skips resolution, and the per-route blockCloudProviders
 * selector replaces the global list for that route. The CloudHandler ranges
 * are the network-refreshed side, which is out of scope here, so the
 * membership lookup is stubbed on the registry handler the same way the
 * refresh would have populated it.
 */

import { describe, it, expect, vi, beforeAll } from 'vitest';
import { initializeSecurityMiddleware } from '../../../src/middleware-support.js';
import type { SecurityMiddlewareComponents } from '../../../src/middleware-support.js';
import { SecurityConfigSchema } from '../../../src/models/config.js';
import { RouteConfig } from '../../../src/models/route-config.js';
import { defaultLogger } from '../../../src/models/logger.js';
import type { GuardRequest } from '../../../src/protocols/request.js';
import { createMockResponseFactory } from '../../helpers.js';

const CLIENT_IP = '203.0.113.10';

function makeRequest(overrides: Partial<GuardRequest> = {}): GuardRequest {
  return {
    urlPath: '/api/test',
    urlScheme: 'https',
    urlFull: 'https://example.com/api/test',
    urlReplaceScheme: (s: string) => `${s}://example.com/api/test`,
    method: 'GET',
    clientHost: CLIENT_IP,
    headers: { 'user-agent': 'TestAgent/1.0' },
    queryParams: {},
    body: async () => new Uint8Array(0),
    state: {},
    scope: {},
    ...overrides,
  };
}

async function build(configOverrides: Record<string, unknown> = {}): Promise<SecurityMiddlewareComponents> {
  const config = SecurityConfigSchema.parse({ enableRedis: false, ...configOverrides });
  return initializeSecurityMiddleware(config, defaultLogger, createMockResponseFactory());
}

describe('CloudProviderCheck blocks cloud IPs (middleware level)', () => {
  /* One shared pipeline for the vectors that only differ in the route config
     or the stubbed membership outcome; the whitelist, exempt and passive
     variants need their own config so they build their own. */
  let awsComponents: SecurityMiddlewareComponents;
  let whitelistComponents: SecurityMiddlewareComponents;
  let exemptComponents: SecurityMiddlewareComponents;
  let passiveComponents: SecurityMiddlewareComponents;

  beforeAll(async () => {
    awsComponents = await build({ blockCloudProviders: ['AWS'], enableRateLimiting: false });
    whitelistComponents = await build({ blockCloudProviders: ['AWS'], whitelist: [CLIENT_IP], enableRateLimiting: false });
    exemptComponents = await build({ blockCloudProviders: ['AWS'], exemptIps: [CLIENT_IP], enableRateLimiting: false });
    passiveComponents = await build({ blockCloudProviders: ['AWS'], passiveMode: true, enableRateLimiting: false });
    /* Warm each pipeline once from a different IP so the detection engine's
       one-time pattern-table compile lands inside the hook and every test's
       first execute is fast. */
    for (const components of [awsComponents, whitelistComponents, exemptComponents, passiveComponents]) {
      await components.pipeline.execute(makeRequest({ clientHost: '192.0.2.200' }));
    }
  }, 60000);

  it('blocks a request IP resolving to a globally selected provider with 403', async () => {
    vi.spyOn(awsComponents.registry.cloudHandler, 'isCloudIp').mockReturnValue(true);

    const response = await awsComponents.pipeline.execute(makeRequest());
    expect(response).not.toBeNull();
    expect(response!.statusCode).toBe(403);
  });

  it('passes a request IP outside every selected provider range', async () => {
    vi.spyOn(awsComponents.registry.cloudHandler, 'isCloudIp').mockReturnValue(false);

    expect(await awsComponents.pipeline.execute(makeRequest())).toBeNull();
  });

  it('the per-route selector replaces the global list for that route', async () => {
    const seen: Array<Set<string>> = [];
    vi.spyOn(awsComponents.registry.cloudHandler, 'isCloudIp').mockImplementation(
      (_ip: string, providers: Set<string>) => { seen.push(providers); return true; },
    );

    const routeConfig = new RouteConfig();
    routeConfig.blockCloudProviders = new Set(['GCP']);
    const response = await awsComponents.pipeline.execute(
      makeRequest({ state: { _routeConfig: routeConfig } }),
    );

    expect(response).not.toBeNull();
    expect(response!.statusCode).toBe(403);
    expect(seen).toEqual([new Set(['GCP'])]);
  });

  it('a whitelisted IP is not blocked and never resolves membership', async () => {
    const spy = vi.spyOn(whitelistComponents.registry.cloudHandler, 'isCloudIp').mockReturnValue(true);

    expect(await whitelistComponents.pipeline.execute(makeRequest())).toBeNull();
    expect(spy).not.toHaveBeenCalled();
  });

  it('an exempt IP is not blocked and never resolves membership', async () => {
    const spy = vi.spyOn(exemptComponents.registry.cloudHandler, 'isCloudIp').mockReturnValue(true);

    expect(await exemptComponents.pipeline.execute(makeRequest())).toBeNull();
    expect(spy).not.toHaveBeenCalled();
  });

  it('a route bypassing ["clouds"] skips provider resolution', async () => {
    const spy = vi.spyOn(awsComponents.registry.cloudHandler, 'isCloudIp').mockReturnValue(true);
    spy.mockClear();
    const routeConfig = new RouteConfig();
    routeConfig.bypassedChecks = new Set(['clouds']);

    expect(await awsComponents.pipeline.execute(
      makeRequest({ state: { _routeConfig: routeConfig } }),
    )).toBeNull();
    expect(spy).not.toHaveBeenCalled();
  });

  it('passive mode logs the detection but lets the cloud IP through', async () => {
    vi.spyOn(passiveComponents.registry.cloudHandler, 'isCloudIp').mockReturnValue(true);

    expect(await passiveComponents.pipeline.execute(makeRequest())).toBeNull();
  });

  it('config validation rejects providers outside the AWS/GCP/Azure set', () => {
    expect(() => SecurityConfigSchema.parse({ blockCloudProviders: ['Alibaba'] })).toThrow();
  });
});
