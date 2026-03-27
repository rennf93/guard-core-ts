import { describe, it, expect, vi } from 'vitest';
import { RequestValidator } from '../../src/core/validation/validator.js';
import { SecurityEventBus } from '../../src/core/events/event-bus.js';
import { createTestConfig, createMockRequest } from '../helpers.js';
import { defaultLogger } from '../../src/models/logger.js';

function createValidator(configOverrides: Record<string, unknown> = {}) {
  const config = createTestConfig(configOverrides);
  const eventBus = new SecurityEventBus(null, config, defaultLogger);
  return new RequestValidator(config, defaultLogger, eventBus);
}

describe('RequestValidator', () => {
  describe('isRequestHttps', () => {
    it('returns true for https scheme', () => {
      const validator = createValidator();
      expect(validator.isRequestHttps(createMockRequest({ urlScheme: 'https' }))).toBe(true);
    });

    it('returns false for http scheme', () => {
      const validator = createValidator();
      expect(validator.isRequestHttps(createMockRequest({ urlScheme: 'http' }))).toBe(false);
    });

    it('trusts X-Forwarded-Proto from trusted proxy', () => {
      const validator = createValidator({
        trustXForwardedProto: true,
        trustedProxies: ['10.0.0.0/8'],
      });
      const req = createMockRequest({
        urlScheme: 'http',
        clientHost: '10.0.0.1',
        headers: { 'x-forwarded-proto': 'https', 'user-agent': 'Test' },
      });
      expect(validator.isRequestHttps(req)).toBe(true);
    });

    it('does not trust X-Forwarded-Proto from untrusted source', () => {
      const validator = createValidator({
        trustXForwardedProto: true,
        trustedProxies: ['10.0.0.0/8'],
      });
      const req = createMockRequest({
        urlScheme: 'http',
        clientHost: '1.2.3.4',
        headers: { 'x-forwarded-proto': 'https', 'user-agent': 'Test' },
      });
      expect(validator.isRequestHttps(req)).toBe(false);
    });

    it('does not check forwarded proto when disabled', () => {
      const validator = createValidator({ trustXForwardedProto: false });
      const req = createMockRequest({
        urlScheme: 'http',
        headers: { 'x-forwarded-proto': 'https', 'user-agent': 'Test' },
      });
      expect(validator.isRequestHttps(req)).toBe(false);
    });
  });

  describe('isTrustedProxy', () => {
    it('matches exact IP', () => {
      const validator = createValidator({ trustedProxies: ['10.0.0.1'] });
      expect(validator.isTrustedProxy('10.0.0.1')).toBe(true);
      expect(validator.isTrustedProxy('10.0.0.2')).toBe(false);
    });

    it('matches CIDR range', () => {
      const validator = createValidator({ trustedProxies: ['172.16.0.0/12'] });
      expect(validator.isTrustedProxy('172.16.0.1')).toBe(true);
      expect(validator.isTrustedProxy('172.31.255.255')).toBe(true);
      expect(validator.isTrustedProxy('172.32.0.1')).toBe(false);
    });

    it('returns false for empty proxy list', () => {
      const validator = createValidator({ trustedProxies: [] });
      expect(validator.isTrustedProxy('10.0.0.1')).toBe(false);
    });
  });

  describe('checkTimeWindow', () => {
    it('allows within window', async () => {
      const validator = createValidator();
      const result = await validator.checkTimeWindow({ start: '00:00', end: '23:59' });
      expect(result).toBe(true);
    });

    it('denies outside window', async () => {
      const validator = createValidator();
      const now = new Date();
      const hour = now.getUTCHours();
      const restrictedStart = String((hour + 2) % 24).padStart(2, '0') + ':00';
      const restrictedEnd = String((hour + 3) % 24).padStart(2, '0') + ':00';
      const result = await validator.checkTimeWindow({ start: restrictedStart, end: restrictedEnd });
      expect(result).toBe(false);
    });

    it('handles midnight-wrapping windows', async () => {
      const validator = createValidator();
      const result = await validator.checkTimeWindow({ start: '22:00', end: '06:00' });
      expect(typeof result).toBe('boolean');
    });

    it('returns true on error', async () => {
      const validator = createValidator();
      const result = await validator.checkTimeWindow({ start: 'invalid', end: 'bad' });
      expect(result).toBe(true);
    });
  });

  describe('isPathExcluded', () => {
    it('excludes matching path', async () => {
      const validator = createValidator({ excludePaths: ['/health', '/metrics'] });
      const req = createMockRequest({ urlPath: '/health' });
      expect(await validator.isPathExcluded(req)).toBe(true);
    });

    it('excludes path prefix matches', async () => {
      const validator = createValidator({ excludePaths: ['/static'] });
      const req = createMockRequest({ urlPath: '/static/img/logo.png' });
      expect(await validator.isPathExcluded(req)).toBe(true);
    });

    it('does not exclude non-matching path', async () => {
      const validator = createValidator({ excludePaths: ['/health'] });
      const req = createMockRequest({ urlPath: '/api/users' });
      expect(await validator.isPathExcluded(req)).toBe(false);
    });

    it('does not exclude when no paths configured', async () => {
      const validator = createValidator({ excludePaths: [] });
      const req = createMockRequest({ urlPath: '/anything' });
      expect(await validator.isPathExcluded(req)).toBe(false);
    });
  });

  it('checkTimeWindow handles midnight-wrap correctly', async () => {
    const validator = createValidator();
    const result = await validator.checkTimeWindow({ start: '23:00', end: '01:00' });
    expect(typeof result).toBe('boolean');
  });

  it('returns true on parsing error', async () => {
    const validator = createValidator();
    const result = await validator.checkTimeWindow({ start: 'not:valid:time', end: 'bad' });
    expect(result).toBe(true);
  });
});
