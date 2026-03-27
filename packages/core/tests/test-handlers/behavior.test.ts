import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BehaviorTracker } from '../../src/handlers/behavior.js';
import { BehaviorRule } from '../../src/models/behavior-rule.js';
import { SecurityConfigSchema } from '../../src/models/config.js';
import { defaultLogger } from '../../src/models/logger.js';
import { createTestConfig, createMockResponse } from '../helpers.js';
import type { GuardResponse } from '../../src/protocols/response.js';
import type { AgentHandlerProtocol } from '../../src/protocols/agent.js';

function createBehaviorResponse(statusCode: number, body: string): GuardResponse {
  return {
    statusCode,
    headers: {},
    setHeader() {},
    body: new TextEncoder().encode(body),
    bodyText: body,
  };
}

function createMockAgent(): AgentHandlerProtocol {
  return {
    sendEvent: vi.fn().mockResolvedValue(undefined),
    sendMetric: vi.fn().mockResolvedValue(undefined),
    initializeRedis: vi.fn().mockResolvedValue(undefined),
    start: vi.fn().mockResolvedValue(undefined),
    stop: vi.fn().mockResolvedValue(undefined),
    flushBuffer: vi.fn().mockResolvedValue(undefined),
    getDynamicRules: vi.fn().mockResolvedValue(null),
    healthCheck: vi.fn().mockResolvedValue(true),
  };
}

describe('BehaviorTracker', () => {
  let tracker: BehaviorTracker;

  beforeEach(() => {
    const config = SecurityConfigSchema.parse({});
    tracker = new BehaviorTracker(config, defaultLogger);
  });

  describe('trackEndpointUsage', () => {
    it('returns false when below threshold', async () => {
      const rule = new BehaviorRule('usage', 5, 3600);
      const result = await tracker.trackEndpointUsage('/api/test', '1.2.3.4', rule);
      expect(result).toBe(false);
    });

    it('returns true when threshold exceeded', async () => {
      const rule = new BehaviorRule('usage', 3, 3600);
      for (let i = 0; i < 3; i++) {
        await tracker.trackEndpointUsage('/api/test', '1.2.3.4', rule);
      }
      const result = await tracker.trackEndpointUsage('/api/test', '1.2.3.4', rule);
      expect(result).toBe(true);
    });

    it('tracks different IPs independently', async () => {
      const rule = new BehaviorRule('usage', 2, 3600);
      await tracker.trackEndpointUsage('/api/test', '1.1.1.1', rule);
      await tracker.trackEndpointUsage('/api/test', '1.1.1.1', rule);
      await tracker.trackEndpointUsage('/api/test', '2.2.2.2', rule);

      const result1 = await tracker.trackEndpointUsage('/api/test', '1.1.1.1', rule);
      const result2 = await tracker.trackEndpointUsage('/api/test', '2.2.2.2', rule);
      expect(result1).toBe(true);
      expect(result2).toBe(false);
    });
  });

  describe('trackReturnPattern', () => {
    it('returns false when no pattern', async () => {
      const rule = new BehaviorRule('return_pattern', 3, 3600);
      const response = createBehaviorResponse(200, 'hello');
      const result = await tracker.trackReturnPattern('/api/test', '1.2.3.4', response, rule);
      expect(result).toBe(false);
    });

    it('matches status pattern', async () => {
      const rule = new BehaviorRule('return_pattern', 2, 3600, 'status:200');
      const response = createBehaviorResponse(200, 'ok');

      await tracker.trackReturnPattern('/api/test', '1.2.3.4', response, rule);
      await tracker.trackReturnPattern('/api/test', '1.2.3.4', response, rule);
      const result = await tracker.trackReturnPattern('/api/test', '1.2.3.4', response, rule);
      expect(result).toBe(true);
    });

    it('matches regex pattern', async () => {
      const rule = new BehaviorRule('return_pattern', 2, 3600, 'regex:rare_sword');
      const response = createBehaviorResponse(200, '{"item": "rare_sword"}');

      await tracker.trackReturnPattern('/api/test', '1.2.3.4', response, rule);
      await tracker.trackReturnPattern('/api/test', '1.2.3.4', response, rule);
      const result = await tracker.trackReturnPattern('/api/test', '1.2.3.4', response, rule);
      expect(result).toBe(true);
    });

    it('does not match non-matching status', async () => {
      const rule = new BehaviorRule('return_pattern', 2, 3600, 'status:404');
      const response = createBehaviorResponse(200, 'ok');

      const result = await tracker.trackReturnPattern('/api/test', '1.2.3.4', response, rule);
      expect(result).toBe(false);
    });

    it('matches substring pattern', async () => {
      const rule = new BehaviorRule('return_pattern', 1, 3600, 'win');
      const response = createBehaviorResponse(200, 'you win!');

      await tracker.trackReturnPattern('/api/test', '1.2.3.4', response, rule);
      const result = await tracker.trackReturnPattern('/api/test', '1.2.3.4', response, rule);
      expect(result).toBe(true);
    });
  });

  it('resets all tracked data', async () => {
    const rule = new BehaviorRule('usage', 1, 3600);
    await tracker.trackEndpointUsage('/api/test', '1.2.3.4', rule);
    await tracker.reset();

    const result = await tracker.trackEndpointUsage('/api/test', '1.2.3.4', rule);
    expect(result).toBe(false);
  });
});

describe('BehaviorTracker applyAction all branches', () => {
  let tracker: BehaviorTracker;

  beforeEach(() => {
    tracker = new BehaviorTracker(createTestConfig(), defaultLogger);
  });

  it('handles ban action', async () => {
    const logSpy = vi.spyOn(defaultLogger, 'warn');
    const rule = new BehaviorRule('usage', 5, 3600, null, 'ban');
    await tracker.applyAction(rule, '10.0.0.1', '/api/test', 'exceeded threshold');
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('Behavioral ban'));
  });

  it('handles log action', async () => {
    const logSpy = vi.spyOn(defaultLogger, 'info');
    const rule = new BehaviorRule('usage', 5, 3600, null, 'log');
    await tracker.applyAction(rule, '10.0.0.1', '/api/test', 'exceeded threshold');
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('Behavioral log'));
  });

  it('handles throttle action', async () => {
    const logSpy = vi.spyOn(defaultLogger, 'info');
    const rule = new BehaviorRule('usage', 5, 3600, null, 'throttle');
    await tracker.applyAction(rule, '10.0.0.1', '/api/test', 'exceeded threshold');
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('Behavioral throttle'));
  });

  it('handles alert action', async () => {
    const logSpy = vi.spyOn(defaultLogger, 'warn');
    const rule = new BehaviorRule('usage', 5, 3600, null, 'alert');
    await tracker.applyAction(rule, '10.0.0.1', '/api/test', 'exceeded threshold');
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('Behavioral alert'));
  });

  it('calls customAction callback when provided', async () => {
    const customFn = vi.fn();
    const rule = new BehaviorRule('usage', 5, 3600, null, 'log', customFn);
    await tracker.applyAction(rule, '10.0.0.1', '/api/test', 'exceeded threshold');
    expect(customFn).toHaveBeenCalledWith('log', '10.0.0.1', '/api/test', 'exceeded threshold');
  });

  it('does not throw when customAction throws', async () => {
    const customFn = vi.fn().mockImplementation(() => { throw new Error('custom error'); });
    const rule = new BehaviorRule('usage', 5, 3600, null, 'log', customFn);
    await expect(tracker.applyAction(rule, '10.0.0.1', '/api/test', 'test')).resolves.toBeUndefined();
  });

  it('logs passive mode message and returns early', async () => {
    const passiveTracker = new BehaviorTracker(createTestConfig({ passiveMode: true }), defaultLogger);
    const logSpy = vi.spyOn(defaultLogger, 'info');
    const rule = new BehaviorRule('usage', 5, 3600, null, 'ban');
    await passiveTracker.applyAction(rule, '10.0.0.1', '/api/test', 'exceeded threshold');
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('[PASSIVE]'));
  });

  it('sends agent event when agent is set', async () => {
    const agent = createMockAgent();
    await tracker.initializeAgent(agent);
    const rule = new BehaviorRule('usage', 5, 3600, null, 'ban');
    await tracker.applyAction(rule, '10.0.0.1', '/api/test', 'exceeded threshold');
    expect(agent.sendEvent).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: 'behavioral_action', actionTaken: 'ban' }),
    );
  });

  it('checkResponsePattern with json:path format', async () => {
    const response = createMockResponse(200, JSON.stringify({ data: { status: 'error' } }));
    const rule = new BehaviorRule('return_pattern', 1, 3600, 'json:data.status');
    const exceeded = await tracker.trackReturnPattern('/api/test', '10.0.0.1', response, rule);
    expect(typeof exceeded).toBe('boolean');
  });

  it('checkResponsePattern with json:path returns false for null body', async () => {
    const response = createMockResponse(200, '');
    response.bodyText = null;
    const rule = new BehaviorRule('return_pattern', 1, 3600, 'json:data.status');
    const exceeded = await tracker.trackReturnPattern('/api/test', '10.0.0.1', response, rule);
    expect(exceeded).toBe(false);
  });

  it('checkResponsePattern with status: pattern', async () => {
    const response = createMockResponse(404, 'Not found');
    const rule = new BehaviorRule('return_pattern', 0, 3600, 'status:404');
    const exceeded = await tracker.trackReturnPattern('/api/test', '10.0.0.1', response, rule);
    expect(exceeded).toBe(true);
  });

  it('checkResponsePattern with regex: pattern', async () => {
    const response = createMockResponse(200, 'error occurred in processing');
    const rule = new BehaviorRule('return_pattern', 0, 3600, 'regex:error.*processing');
    const exceeded = await tracker.trackReturnPattern('/api/test', '10.0.0.1', response, rule);
    expect(exceeded).toBe(true);
  });

  it('checkResponsePattern with plain text pattern', async () => {
    const response = createMockResponse(200, 'unauthorized access attempt');
    const rule = new BehaviorRule('return_pattern', 0, 3600, 'unauthorized');
    const exceeded = await tracker.trackReturnPattern('/api/test', '10.0.0.1', response, rule);
    expect(exceeded).toBe(true);
  });
});

describe('BehaviorTracker nested JSON matching', () => {
  it('matches json:path pattern', async () => {
    const config = createTestConfig();
    const tracker = new BehaviorTracker(config, defaultLogger);
    const rule = new BehaviorRule('return_pattern', 1, 3600, 'json:item');
    const response = createMockResponse(200, JSON.stringify({ item: 'rare_sword' }));

    await tracker.trackReturnPattern('/api/loot', '1.2.3.4', response, rule);
    const result = await tracker.trackReturnPattern('/api/loot', '1.2.3.4', response, rule);
    expect(result).toBe(true);
  });

  it('does not match json:path when field missing', async () => {
    const config = createTestConfig();
    const tracker = new BehaviorTracker(config, defaultLogger);
    const rule = new BehaviorRule('return_pattern', 1, 3600, 'json:missing_field');
    const response = createMockResponse(200, JSON.stringify({ other: 'value' }));

    const result = await tracker.trackReturnPattern('/api/test', '1.2.3.4', response, rule);
    expect(result).toBe(false);
  });

  it('handles invalid JSON gracefully', async () => {
    const config = createTestConfig();
    const tracker = new BehaviorTracker(config, defaultLogger);
    const rule = new BehaviorRule('return_pattern', 1, 3600, 'json:field');
    const response = createMockResponse(200, 'not json');

    const result = await tracker.trackReturnPattern('/api/test', '1.2.3.4', response, rule);
    expect(result).toBe(false);
  });
});

describe('BehaviorTracker remaining branches', () => {
  it('checkResponsePattern default fallback (no prefix)', async () => {
    const config = createTestConfig();
    const tracker = new BehaviorTracker(config, defaultLogger);
    const rule = new BehaviorRule('return_pattern', 1, 3600, 'rare_item');
    const response = createBehaviorResponse(200, 'You found a rare_item!');
    await tracker.trackReturnPattern('/api', '1.1.1.1', response, rule);
    const result = await tracker.trackReturnPattern('/api', '1.1.1.1', response, rule);
    expect(result).toBe(true);
  });

  it('checkResponsePattern bodyText null returns false', async () => {
    const config = createTestConfig();
    const tracker = new BehaviorTracker(config, defaultLogger);
    const rule = new BehaviorRule('return_pattern', 1, 3600, 'regex:test');
    const response = createBehaviorResponse(200, '');
    response.bodyText = null;
    const result = await tracker.trackReturnPattern('/api', '1.1.1.1', response, rule);
    expect(result).toBe(false);
  });

  it('applyAction with agent error does not throw', async () => {
    const config = createTestConfig();
    const tracker = new BehaviorTracker(config, defaultLogger);
    const agent = { sendEvent: vi.fn().mockRejectedValue(new Error('fail')) };
    await tracker.initializeAgent(agent as never);

    const rule = new BehaviorRule('usage', 5, 3600, null, 'alert');
    await tracker.applyAction(rule, '1.1.1.1', '/api', 'test');
  });
});
