import { describe, it, expect, vi } from 'vitest';
import { BehavioralProcessor } from '../../src/core/behavioral/processor.js';
import { SecurityEventBus } from '../../src/core/events/event-bus.js';
import { BehaviorTracker } from '../../src/handlers/behavior.js';
import { BehaviorRule } from '../../src/models/behavior-rule.js';
import { RouteConfig } from '../../src/models/route-config.js';
import { createTestConfig, createMockRequest, createMockResponse } from '../helpers.js';
import { defaultLogger } from '../../src/models/logger.js';

function createProcessor() {
  const config = createTestConfig();
  const eventBus = new SecurityEventBus(null, config, defaultLogger);
  const processor = new BehavioralProcessor(defaultLogger, eventBus);
  const tracker = new BehaviorTracker(config, defaultLogger);
  processor.setGuardDecorator({ behaviorTracker: tracker });
  return { processor, tracker };
}

describe('BehavioralProcessor', () => {
  describe('processUsageRules', () => {
    it('does nothing without decorator', async () => {
      const config = createTestConfig();
      const eventBus = new SecurityEventBus(null, config, defaultLogger);
      const processor = new BehavioralProcessor(defaultLogger, eventBus);
      const rc = new RouteConfig();
      rc.behaviorRules = [new BehaviorRule('usage', 5)];
      await processor.processUsageRules(createMockRequest(), '1.2.3.4', rc);
    });

    it('tracks usage and applies action when exceeded', async () => {
      const { processor } = createProcessor();
      const rc = new RouteConfig();
      rc.behaviorRules = [new BehaviorRule('usage', 2, 3600, null, 'log')];

      for (let i = 0; i < 3; i++) {
        await processor.processUsageRules(createMockRequest(), '1.2.3.4', rc);
      }
    });

    it('skips non-usage rules', async () => {
      const { processor } = createProcessor();
      const rc = new RouteConfig();
      rc.behaviorRules = [new BehaviorRule('return_pattern', 5, 3600, 'status:200')];
      await processor.processUsageRules(createMockRequest(), '1.2.3.4', rc);
    });
  });

  describe('processReturnRules', () => {
    it('does nothing without decorator', async () => {
      const config = createTestConfig();
      const eventBus = new SecurityEventBus(null, config, defaultLogger);
      const processor = new BehavioralProcessor(defaultLogger, eventBus);
      const rc = new RouteConfig();
      rc.behaviorRules = [new BehaviorRule('return_pattern', 3, 3600, 'status:200')];
      await processor.processReturnRules(createMockRequest(), createMockResponse(200, 'ok'), '1.2.3.4', rc);
    });

    it('tracks return patterns', async () => {
      const { processor } = createProcessor();
      const rc = new RouteConfig();
      rc.behaviorRules = [new BehaviorRule('return_pattern', 2, 3600, 'status:200', 'log')];
      const response = createMockResponse(200, 'ok');

      for (let i = 0; i < 3; i++) {
        await processor.processReturnRules(createMockRequest(), response, '1.2.3.4', rc);
      }
    });

    it('skips non-return rules', async () => {
      const { processor } = createProcessor();
      const rc = new RouteConfig();
      rc.behaviorRules = [new BehaviorRule('usage', 5)];
      await processor.processReturnRules(createMockRequest(), createMockResponse(200), '1.2.3.4', rc);
    });
  });

  describe('getEndpointId', () => {
    it('uses state endpoint ID when present', () => {
      const { processor } = createProcessor();
      const req = createMockRequest();
      (req.state as Record<string, unknown>)['guardEndpointId'] = 'module.handler';
      expect(processor.getEndpointId(req)).toBe('module.handler');
    });

    it('falls back to method:path', () => {
      const { processor } = createProcessor();
      expect(processor.getEndpointId(createMockRequest())).toBe('GET:/api/test');
    });
  });
});
