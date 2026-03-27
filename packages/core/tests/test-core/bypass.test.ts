import { describe, it, expect, vi } from 'vitest';
import { BypassHandler } from '../../src/core/bypass/handler.js';
import { RouteConfigResolver } from '../../src/core/routing/resolver.js';
import { SecurityEventBus } from '../../src/core/events/event-bus.js';
import { RequestValidator } from '../../src/core/validation/validator.js';
import { RouteConfig } from '../../src/models/route-config.js';
import { createTestConfig, createMockRequest, createMockResponse } from '../helpers.js';
import { defaultLogger } from '../../src/models/logger.js';
import type { GuardResponse } from '../../src/protocols/response.js';

function createBypassHandler(configOverrides: Record<string, unknown> = {}) {
  const config = createTestConfig(configOverrides);
  const eventBus = new SecurityEventBus(null, config, defaultLogger);
  const routeResolver = new RouteConfigResolver(config);
  const validator = new RequestValidator(config, defaultLogger, eventBus);
  const errorResponseFactory = {
    async applyModifier(response: GuardResponse) { return response; },
  };

  return new BypassHandler(
    config, eventBus, routeResolver,
    errorResponseFactory as never, validator,
  );
}

describe('BypassHandler', () => {
  describe('handlePassthrough', () => {
    it('bypasses when no clientHost', async () => {
      const handler = createBypassHandler();
      const req = createMockRequest({ clientHost: null });
      const callNext = vi.fn().mockResolvedValue(createMockResponse(200, 'ok'));

      const result = await handler.handlePassthrough(req, callNext);
      expect(result).not.toBeNull();
    });

    it('bypasses when path excluded', async () => {
      const handler = createBypassHandler({ excludePaths: ['/health'] });
      const req = createMockRequest({ urlPath: '/health' });
      const callNext = vi.fn().mockResolvedValue(createMockResponse(200, 'ok'));

      const result = await handler.handlePassthrough(req, callNext);
      expect(result).not.toBeNull();
    });

    it('returns null for normal request', async () => {
      const handler = createBypassHandler();
      const req = createMockRequest();
      const callNext = vi.fn();

      const result = await handler.handlePassthrough(req, callNext);
      expect(result).toBeNull();
    });
  });

  describe('handleSecurityBypass', () => {
    it('returns null with no route config', async () => {
      const handler = createBypassHandler();
      const callNext = vi.fn();
      const result = await handler.handleSecurityBypass(createMockRequest(), callNext, null);
      expect(result).toBeNull();
    });

    it('returns null when checks not bypassed', async () => {
      const handler = createBypassHandler();
      const rc = new RouteConfig();
      const result = await handler.handleSecurityBypass(createMockRequest(), vi.fn(), rc);
      expect(result).toBeNull();
    });

    it('bypasses when all checks bypassed (non-passive)', async () => {
      const handler = createBypassHandler();
      const rc = new RouteConfig();
      rc.bypassedChecks.add('all');
      const callNext = vi.fn().mockResolvedValue(createMockResponse(200, 'ok'));

      const result = await handler.handleSecurityBypass(createMockRequest(), callNext, rc);
      expect(result).not.toBeNull();
    });

    it('returns null in passive mode even with bypass', async () => {
      const handler = createBypassHandler({ passiveMode: true });
      const rc = new RouteConfig();
      rc.bypassedChecks.add('all');

      const result = await handler.handleSecurityBypass(createMockRequest(), vi.fn(), rc);
      expect(result).toBeNull();
    });
  });
});
