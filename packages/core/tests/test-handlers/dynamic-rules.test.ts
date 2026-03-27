import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { DynamicRuleManager } from '../../src/handlers/dynamic-rules.js';
import { createTestConfig } from '../helpers.js';
import { defaultLogger } from '../../src/models/logger.js';

describe('DynamicRuleManager', () => {
  let manager: DynamicRuleManager;

  beforeEach(() => {
    manager = new DynamicRuleManager(createTestConfig(), defaultLogger);
  });

  afterEach(async () => {
    await manager.stop();
  });

  it('starts with no rules', () => {
    expect(manager.getCurrentRules()).toBeNull();
  });

  it('updateRules does nothing without agent', async () => {
    await manager.updateRules();
    expect(manager.getCurrentRules()).toBeNull();
  });

  it('applies valid rules from agent', async () => {
    const mockAgent = {
      getDynamicRules: vi.fn().mockResolvedValue({
        ruleId: 'rule-1',
        version: 1,
        timestamp: '2024-01-01T00:00:00Z',
      }),
      sendEvent: vi.fn(),
    };
    await manager.initializeAgent(mockAgent as never);
    await manager.updateRules();
    expect(manager.getCurrentRules()).not.toBeNull();
    expect(manager.getCurrentRules()!.ruleId).toBe('rule-1');
  });

  it('rejects invalid rules', async () => {
    const mockAgent = {
      getDynamicRules: vi.fn().mockResolvedValue({ invalid: true }),
      sendEvent: vi.fn(),
    };
    await manager.initializeAgent(mockAgent as never);
    await manager.updateRules();
    expect(manager.getCurrentRules()).toBeNull();
  });

  it('skips older version rules', async () => {
    const mockAgent = {
      getDynamicRules: vi.fn()
        .mockResolvedValueOnce({ ruleId: 'r1', version: 2, timestamp: '2024-01-01T00:00:00Z' })
        .mockResolvedValueOnce({ ruleId: 'r1', version: 1, timestamp: '2024-01-01T00:00:00Z' }),
      sendEvent: vi.fn(),
    };
    await manager.initializeAgent(mockAgent as never);
    await manager.updateRules();
    await manager.updateRules();
    expect(manager.getCurrentRules()!.version).toBe(2);
  });

  it('handles agent errors gracefully', async () => {
    const mockAgent = {
      getDynamicRules: vi.fn().mockRejectedValue(new Error('network error')),
      sendEvent: vi.fn(),
    };
    await manager.initializeAgent(mockAgent as never);
    await manager.updateRules();
    expect(manager.getCurrentRules()).toBeNull();
  });

  it('handles null return from agent', async () => {
    const mockAgent = {
      getDynamicRules: vi.fn().mockResolvedValue(null),
      sendEvent: vi.fn(),
    };
    await manager.initializeAgent(mockAgent as never);
    await manager.updateRules();
    expect(manager.getCurrentRules()).toBeNull();
  });

  it('forceUpdate triggers immediate update', async () => {
    const mockAgent = {
      getDynamicRules: vi.fn().mockResolvedValue({
        ruleId: 'forced', version: 1, timestamp: '2024-01-01T00:00:00Z',
      }),
      sendEvent: vi.fn(),
    };
    await manager.initializeAgent(mockAgent as never);
    await manager.forceUpdate();
    expect(manager.getCurrentRules()!.ruleId).toBe('forced');
  });

  it('stop cancels update loop', async () => {
    const config = createTestConfig({ enableDynamicRules: true, enableAgent: true, agentApiKey: 'key' });
    const mgr = new DynamicRuleManager(config, defaultLogger);
    const mockAgent = {
      getDynamicRules: vi.fn().mockResolvedValue(null),
      sendEvent: vi.fn(),
    };
    await mgr.initializeAgent(mockAgent as never);
    await mgr.stop();
  });

  it('startUpdateLoop only creates one timer', async () => {
    const config = createTestConfig({ enableDynamicRules: true, enableAgent: true, agentApiKey: 'k' });
    const mgr = new DynamicRuleManager(config, defaultLogger);
    const agent = { getDynamicRules: vi.fn().mockResolvedValue(null), sendEvent: vi.fn(), start: vi.fn(), stop: vi.fn(), initializeRedis: vi.fn(), sendMetric: vi.fn(), flushBuffer: vi.fn(), healthCheck: vi.fn() };
    await mgr.initializeAgent(agent as never);
    await mgr.stop();
  });

  it('agent send event failure in updateRules does not throw', async () => {
    const agent = {
      getDynamicRules: vi.fn().mockResolvedValue({ ruleId: 'r', version: 1, timestamp: '2024-01-01T00:00:00Z' }),
      sendEvent: vi.fn().mockRejectedValue(new Error('send fail')),
      start: vi.fn(), stop: vi.fn(), initializeRedis: vi.fn(),
      sendMetric: vi.fn(), flushBuffer: vi.fn(), healthCheck: vi.fn(),
    };
    const config = createTestConfig();
    const mgr = new DynamicRuleManager(config, defaultLogger);
    await mgr.initializeAgent(agent as never);
    await mgr.updateRules();
    await mgr.stop();
  });
});
