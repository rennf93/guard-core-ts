import { describe, it, expect, vi } from 'vitest';
import { defaultLogger } from '../../src/models/logger.js';

describe('defaultLogger', () => {
  it('has all required methods', () => {
    expect(typeof defaultLogger.info).toBe('function');
    expect(typeof defaultLogger.warn).toBe('function');
    expect(typeof defaultLogger.error).toBe('function');
    expect(typeof defaultLogger.debug).toBe('function');
  });

  it('logs to console with prefix', () => {
    const spy = vi.spyOn(console, 'info').mockImplementation(() => {});
    defaultLogger.info('test message');
    expect(spy).toHaveBeenCalledWith('[guard-core] test message');
    spy.mockRestore();
  });

  it('logs warnings', () => {
    const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    defaultLogger.warn('warning test');
    expect(spy).toHaveBeenCalledWith('[guard-core] warning test');
    spy.mockRestore();
  });

  it('logs errors', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    defaultLogger.error('error test');
    expect(spy).toHaveBeenCalledWith('[guard-core] error test');
    spy.mockRestore();
  });
});
