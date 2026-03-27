import { describe, it, expect } from 'vitest';
import { isIpInBlacklist, isIpInWhitelist, validateAuthHeader, isReferrerDomainAllowed } from '../../../src/core/checks/helpers.js';

describe('check helpers', () => {
  describe('isIpInBlacklist', () => {
    it('matches exact IP', () => {
      expect(isIpInBlacklist('1.2.3.4', ['1.2.3.4', '5.6.7.8'])).toBe(true);
    });

    it('matches CIDR range', () => {
      expect(isIpInBlacklist('192.168.1.50', ['192.168.1.0/24'])).toBe(true);
    });

    it('returns false for non-matching IP', () => {
      expect(isIpInBlacklist('10.0.0.1', ['192.168.1.0/24'])).toBe(false);
    });

    it('returns false for empty blacklist', () => {
      expect(isIpInBlacklist('1.2.3.4', [])).toBe(false);
    });
  });

  describe('isIpInWhitelist', () => {
    it('returns null for empty whitelist', () => {
      expect(isIpInWhitelist('1.2.3.4', [])).toBeNull();
    });

    it('returns true for whitelisted IP', () => {
      expect(isIpInWhitelist('10.0.0.1', ['10.0.0.0/8'])).toBe(true);
    });

    it('returns false for non-whitelisted IP', () => {
      expect(isIpInWhitelist('192.168.1.1', ['10.0.0.0/8'])).toBe(false);
    });

    it('matches exact IP', () => {
      expect(isIpInWhitelist('1.2.3.4', ['1.2.3.4'])).toBe(true);
    });
  });

  describe('validateAuthHeader', () => {
    it('validates bearer token', () => {
      const [valid] = validateAuthHeader('Bearer abc123', 'bearer');
      expect(valid).toBe(true);
    });

    it('rejects missing bearer token', () => {
      const [valid, msg] = validateAuthHeader('', 'bearer');
      expect(valid).toBe(false);
      expect(msg).toContain('Bearer');
    });

    it('rejects wrong auth type', () => {
      const [valid] = validateAuthHeader('Bearer abc', 'basic');
      expect(valid).toBe(false);
    });

    it('validates basic auth', () => {
      const [valid] = validateAuthHeader('Basic dXNlcjpwYXNz', 'basic');
      expect(valid).toBe(true);
    });

    it('validates custom auth type', () => {
      const [valid] = validateAuthHeader('CustomToken xyz', 'custom');
      expect(valid).toBe(true);
    });

    it('rejects empty custom auth', () => {
      const [valid] = validateAuthHeader('', 'custom');
      expect(valid).toBe(false);
    });
  });

  describe('isReferrerDomainAllowed', () => {
    it('allows exact domain match', () => {
      expect(isReferrerDomainAllowed('https://example.com/page', ['example.com'])).toBe(true);
    });

    it('allows subdomain match', () => {
      expect(isReferrerDomainAllowed('https://sub.example.com/page', ['example.com'])).toBe(true);
    });

    it('rejects non-matching domain', () => {
      expect(isReferrerDomainAllowed('https://evil.com/page', ['example.com'])).toBe(false);
    });

    it('handles invalid URL gracefully', () => {
      expect(isReferrerDomainAllowed('not-a-url', ['example.com'])).toBe(false);
    });

    it('is case insensitive', () => {
      expect(isReferrerDomainAllowed('https://EXAMPLE.COM/page', ['example.com'])).toBe(true);
    });
  });
});
