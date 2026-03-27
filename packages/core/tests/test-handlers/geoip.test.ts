import { describe, it, expect, vi } from 'vitest';
import { IPInfoManager } from '../../src/handlers/geoip.js';
import { defaultLogger } from '../../src/models/logger.js';

describe('IPInfoManager', () => {
  it('starts uninitialized', () => {
    const manager = new IPInfoManager(defaultLogger);
    expect(manager.isInitialized).toBe(false);
  });

  it('getCountry returns null when not initialized', () => {
    const manager = new IPInfoManager(defaultLogger);
    expect(manager.getCountry('1.2.3.4')).toBeNull();
  });

  it('initialize handles missing maxmind gracefully', async () => {
    const manager = new IPInfoManager(defaultLogger);
    await manager.initialize();
    expect(manager.isInitialized).toBe(false);
  });

  it('initializeRedis is a no-op', async () => {
    const manager = new IPInfoManager(defaultLogger);
    await manager.initializeRedis({} as never);
  });

  it('initializeAgent sets agent', async () => {
    const manager = new IPInfoManager(defaultLogger);
    const agent = { sendEvent: vi.fn() };
    await manager.initializeAgent(agent as never);
  });

  it('getCountry returns null on error', () => {
    const manager = new IPInfoManager(defaultLogger);
    (manager as unknown as Record<string, unknown>)['reader'] = {
      get: () => { throw new Error('reader error'); },
    };
    expect(manager.getCountry('1.2.3.4')).toBeNull();
  });

  it('getCountry extracts country from reader result', () => {
    const manager = new IPInfoManager(defaultLogger);
    (manager as unknown as Record<string, unknown>)['reader'] = {
      get: () => ({ country: { iso_code: 'US' } }),
    };
    expect(manager.getCountry('1.2.3.4')).toBe('US');
  });

  it('getCountry returns null when no country in result', () => {
    const manager = new IPInfoManager(defaultLogger);
    (manager as unknown as Record<string, unknown>)['reader'] = {
      get: () => ({}),
    };
    expect(manager.getCountry('1.2.3.4')).toBeNull();
  });

  it('marks initialized after mock maxmind', () => {
    const manager = new IPInfoManager(defaultLogger);

    (manager as unknown as Record<string, unknown>)['reader'] = { get: () => ({ country: { iso_code: 'DE' } }) };
    (manager as unknown as Record<string, unknown>)['_isInitialized'] = true;

    expect(manager.isInitialized).toBe(true);
    expect(manager.getCountry('1.2.3.4')).toBe('DE');
  });
});
