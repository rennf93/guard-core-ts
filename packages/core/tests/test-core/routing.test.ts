import { describe, it, expect, vi } from 'vitest';
import { RouteConfigResolver } from '../../src/core/routing/resolver.js';
import { RouteConfig } from '../../src/models/route-config.js';
import { createTestConfig, createMockRequest } from '../helpers.js';

describe('RouteConfigResolver', () => {
  it('returns null when no decorator set', () => {
    const resolver = new RouteConfigResolver(createTestConfig());
    expect(resolver.getRouteConfig(createMockRequest())).toBeNull();
  });

  it('returns null when no route ID on request', () => {
    const resolver = new RouteConfigResolver(createTestConfig());
    const decorator = {
      getRouteConfig: () => new RouteConfig(),
    };
    resolver.setGuardDecorator(decorator);
    expect(resolver.getRouteConfig(createMockRequest())).toBeNull();
  });

  it('returns route config when route ID matches', () => {
    const resolver = new RouteConfigResolver(createTestConfig());
    const rc = new RouteConfig();
    rc.rateLimit = 42;
    const decorator = {
      getRouteConfig: (id: string) => id === 'route-1' ? rc : undefined,
    };
    resolver.setGuardDecorator(decorator);

    const req = createMockRequest();
    (req.state as Record<string, unknown>)['guardRouteId'] = 'route-1';
    const result = resolver.getRouteConfig(req);
    expect(result?.rateLimit).toBe(42);
  });

  describe('shouldBypassCheck', () => {
    it('returns false with no route config', () => {
      const resolver = new RouteConfigResolver(createTestConfig());
      expect(resolver.shouldBypassCheck('rate_limit', null)).toBe(false);
    });

    it('returns true for specific bypassed check', () => {
      const resolver = new RouteConfigResolver(createTestConfig());
      const rc = new RouteConfig();
      rc.bypassedChecks.add('rate_limit');
      expect(resolver.shouldBypassCheck('rate_limit', rc)).toBe(true);
    });

    it('returns true when all checks bypassed', () => {
      const resolver = new RouteConfigResolver(createTestConfig());
      const rc = new RouteConfig();
      rc.bypassedChecks.add('all');
      expect(resolver.shouldBypassCheck('any_check', rc)).toBe(true);
    });

    it('returns false for non-bypassed check', () => {
      const resolver = new RouteConfigResolver(createTestConfig());
      const rc = new RouteConfig();
      rc.bypassedChecks.add('rate_limit');
      expect(resolver.shouldBypassCheck('ip_security', rc)).toBe(false);
    });
  });

  describe('getCloudProvidersToCheck', () => {
    it('returns null when no providers configured', () => {
      const resolver = new RouteConfigResolver(createTestConfig());
      expect(resolver.getCloudProvidersToCheck(null)).toBeNull();
    });

    it('returns route-level providers when set', () => {
      const resolver = new RouteConfigResolver(createTestConfig());
      const rc = new RouteConfig();
      rc.blockCloudProviders.add('AWS');
      expect(resolver.getCloudProvidersToCheck(rc)).toEqual(['AWS']);
    });

    it('returns global providers when route has none', () => {
      const resolver = new RouteConfigResolver(createTestConfig({
        blockCloudProviders: ['GCP', 'Azure'],
      }));
      expect(resolver.getCloudProvidersToCheck(null)).toEqual(['GCP', 'Azure']);
    });

    it('route-level takes priority over global', () => {
      const resolver = new RouteConfigResolver(createTestConfig({
        blockCloudProviders: ['AWS', 'GCP', 'Azure'],
      }));
      const rc = new RouteConfig();
      rc.blockCloudProviders.add('AWS');
      expect(resolver.getCloudProvidersToCheck(rc)).toEqual(['AWS']);
    });
  });

  it('returns null when decorator.getRouteConfig is not a function', () => {
    const resolver = new RouteConfigResolver(createTestConfig());
    resolver.setGuardDecorator({ notAFunction: true });
    const req = createMockRequest();
    (req.state as Record<string, unknown>)['guardRouteId'] = 'some-id';
    expect(resolver.getRouteConfig(req)).toBeNull();
  });

  it('returns null when route ID is not a string', () => {
    const resolver = new RouteConfigResolver(createTestConfig());
    const decorator = { getRouteConfig: vi.fn() };
    resolver.setGuardDecorator(decorator);
    const req = createMockRequest();
    (req.state as Record<string, unknown>)['guardRouteId'] = 42;
    expect(resolver.getRouteConfig(req)).toBeNull();
  });

  it('returns undefined route config as null', () => {
    const resolver = new RouteConfigResolver(createTestConfig());
    const decorator = { getRouteConfig: () => undefined };
    resolver.setGuardDecorator(decorator);
    const req = createMockRequest();
    (req.state as Record<string, unknown>)['guardRouteId'] = 'nonexistent';
    expect(resolver.getRouteConfig(req)).toBeNull();
  });
});
