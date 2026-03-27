import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IPBanManager } from '../../src/handlers/ip-ban.js';
import { defaultLogger } from '../../src/models/logger.js';
import type { AgentHandlerProtocol } from '../../src/protocols/agent.js';

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

function createMockRedis() {
  const store = new Map<string, string>();
  return {
    getKey: vi.fn(async (_ns: string, key: string) => store.get(key) ?? null),
    setKey: vi.fn(async (_ns: string, key: string, value: unknown) => { store.set(key, String(value)); return true; }),
    delete: vi.fn(async (_ns: string, key: string) => { store.delete(key); return 1; }),
    deletePattern: vi.fn(async () => 0),
    keys: vi.fn(async () => []),
    initialize: vi.fn(),
    getRawClient: vi.fn(() => ({
      script: vi.fn().mockResolvedValue('sha'),
      evalsha: vi.fn().mockResolvedValue(1),
      zadd: vi.fn(),
      zremrangebyscore: vi.fn(),
      zcard: vi.fn().mockResolvedValue(1),
      eval: vi.fn(),
    })),
    getConnection: vi.fn(),
    initializeAgent: vi.fn(),
    prefix: 'guard_core:',
  };
}

describe('IPBanManager', () => {
  let manager: IPBanManager;

  beforeEach(() => {
    manager = new IPBanManager(defaultLogger);
  });

  it('bans an IP', async () => {
    await manager.banIp('1.2.3.4', 3600, 'test ban');
    expect(await manager.isIpBanned('1.2.3.4')).toBe(true);
  });

  it('returns false for non-banned IP', async () => {
    expect(await manager.isIpBanned('5.6.7.8')).toBe(false);
  });

  it('unbans an IP', async () => {
    await manager.banIp('1.2.3.4', 3600, 'test');
    await manager.unbanIp('1.2.3.4');
    expect(await manager.isIpBanned('1.2.3.4')).toBe(false);
  });

  it('detects expired bans', async () => {
    await manager.banIp('1.2.3.4', -1, 'already expired');
    expect(await manager.isIpBanned('1.2.3.4')).toBe(false);
  });

  it('resets all bans', async () => {
    await manager.banIp('1.2.3.4', 3600, 'test');
    await manager.banIp('5.6.7.8', 3600, 'test');
    await manager.reset();
    expect(await manager.isIpBanned('1.2.3.4')).toBe(false);
    expect(await manager.isIpBanned('5.6.7.8')).toBe(false);
  });

  it('handles multiple bans independently', async () => {
    await manager.banIp('1.1.1.1', 3600, 'ban1');
    await manager.banIp('2.2.2.2', 3600, 'ban2');
    expect(await manager.isIpBanned('1.1.1.1')).toBe(true);
    expect(await manager.isIpBanned('2.2.2.2')).toBe(true);
    expect(await manager.isIpBanned('3.3.3.3')).toBe(false);
  });
});

describe('IPBanManager agent event dispatch', () => {
  let manager: IPBanManager;
  let agent: AgentHandlerProtocol;

  beforeEach(() => {
    manager = new IPBanManager(defaultLogger);
    agent = createMockAgent();
  });

  it('sends ip_banned event when banning IP with agent', async () => {
    await manager.initializeAgent(agent);
    await manager.banIp('10.0.0.1', 60, 'test ban');
    expect(agent.sendEvent).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: 'ip_banned', ipAddress: '10.0.0.1' }),
    );
  });

  it('sends ip_unbanned event when unbanning IP with agent', async () => {
    await manager.initializeAgent(agent);
    await manager.banIp('10.0.0.1', 60, 'test ban');
    await manager.unbanIp('10.0.0.1');
    expect(agent.sendEvent).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: 'ip_unbanned', ipAddress: '10.0.0.1' }),
    );
  });

  it('does not throw when agent.sendEvent throws during ban', async () => {
    const failingAgent = createMockAgent();
    (failingAgent.sendEvent as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('network error'));
    await manager.initializeAgent(failingAgent);
    await expect(manager.banIp('10.0.0.1', 60, 'test')).resolves.toBeUndefined();
  });

  it('does not throw when agent.sendEvent throws during unban', async () => {
    const failingAgent = createMockAgent();
    (failingAgent.sendEvent as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('network error'));
    await manager.initializeAgent(failingAgent);
    await manager.banIp('10.0.0.1', 60, 'test');
    await expect(manager.unbanIp('10.0.0.1')).resolves.toBeUndefined();
  });
});

describe('IPBanManager with Redis', () => {
  it('writes ban to Redis', async () => {
    const manager = new IPBanManager(defaultLogger);
    const redis = createMockRedis();
    await manager.initializeRedis(redis as never);
    await manager.banIp('1.2.3.4', 3600, 'test');
    expect(redis.setKey).toHaveBeenCalled();
  });

  it('reads ban from Redis fallback', async () => {
    const manager = new IPBanManager(defaultLogger);
    const redis = createMockRedis();
    const futureExpiry = String(Date.now() / 1000 + 3600);
    redis.getKey.mockResolvedValue(futureExpiry);
    await manager.initializeRedis(redis as never);
    const isBanned = await manager.isIpBanned('5.6.7.8');
    expect(isBanned).toBe(true);
  });

  it('cleans expired Redis entry', async () => {
    const manager = new IPBanManager(defaultLogger);
    const redis = createMockRedis();
    redis.getKey.mockResolvedValue(String(Date.now() / 1000 - 100));
    await manager.initializeRedis(redis as never);
    const isBanned = await manager.isIpBanned('5.6.7.8');
    expect(isBanned).toBe(false);
    expect(redis.delete).toHaveBeenCalled();
  });

  it('unban removes from Redis', async () => {
    const manager = new IPBanManager(defaultLogger);
    const redis = createMockRedis();
    await manager.initializeRedis(redis as never);
    await manager.banIp('1.2.3.4', 3600, 'test');
    await manager.unbanIp('1.2.3.4');
    expect(redis.delete).toHaveBeenCalled();
  });

  it('reset clears Redis pattern', async () => {
    const manager = new IPBanManager(defaultLogger);
    const redis = createMockRedis();
    await manager.initializeRedis(redis as never);
    await manager.reset();
    expect(redis.deletePattern).toHaveBeenCalled();
  });
});

describe('IPBanManager max size eviction', () => {
  it('evicts oldest when exceeding max size', async () => {
    const manager = new IPBanManager(defaultLogger);
    (manager as unknown as Record<string, unknown>)['maxSize'] = 3;

    await manager.banIp('a', 3600, 'test');
    await manager.banIp('b', 3600, 'test');
    await manager.banIp('c', 3600, 'test');
    await manager.banIp('d', 3600, 'test');

    expect(await manager.isIpBanned('d')).toBe(true);
  });
});
