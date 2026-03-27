import { describe, it, expect } from 'vitest';
import { initializeSecurityMiddleware } from '../../src/middleware-support.js';
import { SecurityConfigSchema } from '../../src/models/config.js';
import { defaultLogger } from '../../src/models/logger.js';
import { createMockResponseFactory } from '../helpers.js';

describe('initializeSecurityMiddleware', () => {
  it('returns all components', async () => {
    const config = SecurityConfigSchema.parse({ enableRedis: false });
    const components = await initializeSecurityMiddleware(
      config, defaultLogger, createMockResponseFactory(),
    );

    expect(components.registry).toBeDefined();
    expect(components.pipeline).toBeDefined();
    expect(components.eventBus).toBeDefined();
    expect(components.metricsCollector).toBeDefined();
    expect(components.validator).toBeDefined();
    expect(components.routeResolver).toBeDefined();
    expect(components.bypassHandler).toBeDefined();
    expect(components.errorResponseFactory).toBeDefined();
    expect(components.behavioralProcessor).toBeDefined();
    expect(components.middlewareProtocol).toBeDefined();
  });

  it('pipeline has 17 checks', async () => {
    const config = SecurityConfigSchema.parse({ enableRedis: false });
    const components = await initializeSecurityMiddleware(
      config, defaultLogger, createMockResponseFactory(),
    );

    expect(components.pipeline.getCheckNames()).toHaveLength(17);
  });

  it('middlewareProtocol creates error responses', async () => {
    const config = SecurityConfigSchema.parse({ enableRedis: false });
    const components = await initializeSecurityMiddleware(
      config, defaultLogger, createMockResponseFactory(),
    );

    const response = await components.middlewareProtocol.createErrorResponse(403, 'Forbidden');
    expect(response.statusCode).toBe(403);
  });

  it('middlewareProtocol refreshCloudIpRanges does not throw', async () => {
    const config = SecurityConfigSchema.parse({ enableRedis: false });
    const components = await initializeSecurityMiddleware(
      config, defaultLogger, createMockResponseFactory(),
    );

    await components.middlewareProtocol.refreshCloudIpRanges();
  });

  it('sets guard decorator on route resolver', async () => {
    const config = SecurityConfigSchema.parse({ enableRedis: false });
    const decorator = { getRouteConfig: () => undefined };
    const components = await initializeSecurityMiddleware(
      config, defaultLogger, createMockResponseFactory(),
      null, null, decorator,
    );

    expect(components.routeResolver).toBeDefined();
  });

  it('middlewareProtocol exposes all properties', async () => {
    const config = SecurityConfigSchema.parse({ enableRedis: false });
    const components = await initializeSecurityMiddleware(
      config, defaultLogger, createMockResponseFactory(),
    );

    const mp = components.middlewareProtocol;
    expect(mp.config).toBe(config);
    expect(mp.logger).toBeDefined();
    expect(mp.lastCloudIpRefresh).toBe(0);
    expect(mp.suspiciousRequestCounts).toBeInstanceOf(Map);
    expect(mp.eventBus).toBeDefined();
    expect(mp.routeResolver).toBeDefined();
    expect(mp.responseFactory).toBeDefined();
    expect(mp.rateLimitHandler).toBeDefined();
    expect(mp.agentHandler).toBeNull();
    expect(mp.geoIpHandler).toBeNull();
    expect(mp.guardResponseFactory).toBeDefined();
  });

  it('middlewareProtocol refreshCloudIpRanges with cloud config', async () => {
    const config = SecurityConfigSchema.parse({
      enableRedis: false,
      blockCloudProviders: ['AWS'],
    });
    const components = await initializeSecurityMiddleware(
      config, defaultLogger, createMockResponseFactory(),
    );

    await components.middlewareProtocol.refreshCloudIpRanges();
  });

  it('sets behavioral processor guard decorator', async () => {
    const config = SecurityConfigSchema.parse({ enableRedis: false });
    const decorator = {
      getRouteConfig: () => undefined,
      behaviorTracker: { initializeRedis: async () => {}, initializeAgent: async () => {} },
    };
    const components = await initializeSecurityMiddleware(
      config, defaultLogger, createMockResponseFactory(),
      null, null, decorator,
    );
    expect(components.behavioralProcessor).toBeDefined();
  });
});
