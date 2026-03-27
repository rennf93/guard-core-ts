import { describe, it, expect, vi, beforeEach } from 'vitest';
import { sanitizeForLog, extractClientIp, isIpAllowed, isUserAgentAllowed, logActivity, detectPenetrationAttempt, checkIpCountry } from '../../src/utils.js';
import {
  checkCountryAccess,
  checkRouteIpAccess,
  checkUserAgentAllowed,
  detectPenetrationPatterns,
} from '../../src/core/checks/helpers.js';
import { SecurityConfigSchema } from '../../src/models/config.js';
import { RouteConfig } from '../../src/models/route-config.js';
import { defaultLogger } from '../../src/models/logger.js';
import { createTestConfig, createMockMiddleware } from '../helpers.js';
import type { GuardRequest, GuardRequestState } from '../../src/protocols/request.js';
import type { GeoIPHandler } from '../../src/protocols/geo-ip.js';

function createMockRequest(overrides: Partial<GuardRequest> = {}): GuardRequest {
  return {
    urlPath: '/api/test',
    urlScheme: 'https',
    urlFull: 'https://example.com/api/test',
    urlReplaceScheme: (s: string) => `${s}://example.com/api/test`,
    method: 'GET',
    clientHost: '1.2.3.4',
    headers: { 'user-agent': 'TestAgent/1.0' },
    queryParams: {},
    body: async () => new Uint8Array(0),
    state: {} as GuardRequestState,
    scope: {},
    ...overrides,
  };
}

describe('sanitizeForLog', () => {
  it('escapes newlines', () => {
    expect(sanitizeForLog('line1\nline2')).toBe('line1\\nline2');
  });

  it('escapes carriage returns', () => {
    expect(sanitizeForLog('line1\rline2')).toBe('line1\\rline2');
  });

  it('escapes tabs', () => {
    expect(sanitizeForLog('col1\tcol2')).toBe('col1\\tcol2');
  });

  it('escapes control characters', () => {
    expect(sanitizeForLog('hello\x00world')).toBe('hello\\x00world');
  });

  it('leaves normal text unchanged', () => {
    expect(sanitizeForLog('normal text')).toBe('normal text');
  });
});

describe('extractClientIp', () => {
  it('returns clientHost when no forwarded header', async () => {
    const request = createMockRequest();
    const config = SecurityConfigSchema.parse({});
    const ip = await extractClientIp(request, config);
    expect(ip).toBe('1.2.3.4');
  });

  it('returns unknown when no clientHost', async () => {
    const request = createMockRequest({ clientHost: null });
    const config = SecurityConfigSchema.parse({});
    const ip = await extractClientIp(request, config);
    expect(ip).toBe('unknown');
  });

  it('extracts from X-Forwarded-For with trusted proxy', async () => {
    const request = createMockRequest({
      clientHost: '10.0.0.1',
      headers: { 'x-forwarded-for': '203.0.113.50', 'user-agent': 'TestAgent' },
    });
    const config = SecurityConfigSchema.parse({
      trustedProxies: ['10.0.0.0/8'],
      trustedProxyDepth: 1,
    });
    const ip = await extractClientIp(request, config);
    expect(ip).toBe('203.0.113.50');
  });

  it('ignores X-Forwarded-For from untrusted source', async () => {
    const request = createMockRequest({
      clientHost: '1.2.3.4',
      headers: { 'x-forwarded-for': '10.0.0.1', 'user-agent': 'TestAgent' },
    });
    const config = SecurityConfigSchema.parse({});
    const ip = await extractClientIp(request, config);
    expect(ip).toBe('1.2.3.4');
  });
});

describe('isIpAllowed', () => {
  it('allows non-blacklisted IP', async () => {
    const config = SecurityConfigSchema.parse({ blacklist: ['5.6.7.8'] });
    expect(await isIpAllowed('1.2.3.4', config)).toBe(true);
  });

  it('blocks blacklisted IP', async () => {
    const config = SecurityConfigSchema.parse({ blacklist: ['1.2.3.4'] });
    expect(await isIpAllowed('1.2.3.4', config)).toBe(false);
  });

  it('blocks IP in blacklisted CIDR', async () => {
    const config = SecurityConfigSchema.parse({ blacklist: ['192.168.0.0/16'] });
    expect(await isIpAllowed('192.168.1.100', config)).toBe(false);
  });

  it('allows whitelisted IP', async () => {
    const config = SecurityConfigSchema.parse({ whitelist: ['1.2.3.4'] });
    expect(await isIpAllowed('1.2.3.4', config)).toBe(true);
  });

  it('blocks non-whitelisted IP when whitelist exists', async () => {
    const config = SecurityConfigSchema.parse({ whitelist: ['10.0.0.1'] });
    expect(await isIpAllowed('1.2.3.4', config)).toBe(false);
  });

  it('returns false for invalid IP', async () => {
    const config = SecurityConfigSchema.parse({});
    expect(await isIpAllowed('not-an-ip', config)).toBe(false);
  });
});

describe('isUserAgentAllowed', () => {
  it('allows non-matching user agent', async () => {
    const config = SecurityConfigSchema.parse({ blockedUserAgents: ['badbot'] });
    expect(await isUserAgentAllowed('Chrome/120', config)).toBe(true);
  });

  it('blocks matching user agent', async () => {
    const config = SecurityConfigSchema.parse({ blockedUserAgents: ['badbot'] });
    expect(await isUserAgentAllowed('badbot/1.0', config)).toBe(false);
  });

  it('is case insensitive', async () => {
    const config = SecurityConfigSchema.parse({ blockedUserAgents: ['BadBot'] });
    expect(await isUserAgentAllowed('BADBOT/2.0', config)).toBe(false);
  });

  it('supports regex patterns', async () => {
    const config = SecurityConfigSchema.parse({ blockedUserAgents: ['scrapy|crawl'] });
    expect(await isUserAgentAllowed('Scrapy/2.0', config)).toBe(false);
    expect(await isUserAgentAllowed('GoogleCrawler', config)).toBe(false);
    expect(await isUserAgentAllowed('Chrome/120', config)).toBe(true);
  });
});

describe('logActivity', () => {
  it('logs request activity', () => {
    const spy = vi.spyOn(defaultLogger, 'info').mockImplementation(() => {});
    const request = createMockRequest();
    logActivity(request, defaultLogger, 'request', '', false, '', 'INFO');
    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
  });

  it('does not log when level is null', () => {
    const spy = vi.spyOn(defaultLogger, 'warn').mockImplementation(() => {});
    const request = createMockRequest();
    logActivity(request, defaultLogger, 'request', '', false, '', null);
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it('logs suspicious activity with passive mode prefix', () => {
    const spy = vi.spyOn(defaultLogger, 'warn').mockImplementation(() => {});
    const request = createMockRequest();
    logActivity(request, defaultLogger, 'suspicious', 'SQL injection', true, 'UNION SELECT', 'WARNING');
    expect(spy).toHaveBeenCalled();
    const msg = spy.mock.calls[0][0];
    expect(msg).toContain('PASSIVE');
    expect(msg).toContain('SQL injection');
    spy.mockRestore();
  });
});

function createMockGeoIpHandler(countryMap: Record<string, string> = {}): GeoIPHandler {
  return {
    isInitialized: true,
    initialize: vi.fn().mockResolvedValue(undefined),
    initializeRedis: vi.fn().mockResolvedValue(undefined),
    initializeAgent: vi.fn().mockResolvedValue(undefined),
    getCountry: vi.fn().mockImplementation((ip: string) => countryMap[ip] ?? null),
  };
}

describe('detectPenetrationAttempt', () => {
  it('detects XSS in query params', async () => {
    const request = createMockRequest({
      queryParams: { q: '<script>alert(1)</script>' },
    });
    const [isThreat, info] = await detectPenetrationAttempt(request);
    expect(isThreat).toBe(true);
    expect(info).toContain('query_params');
  });

  it('detects path traversal in URL path', async () => {
    const request = createMockRequest({
      urlPath: '/files/../../etc/passwd',
    });
    const [isThreat, info] = await detectPenetrationAttempt(request);
    expect(isThreat).toBe(true);
    expect(info).toContain('url_path');
  });

  it('detects malicious header value', async () => {
    const request = createMockRequest({
      headers: {
        'user-agent': 'Mozilla/5.0',
        'x-custom': '<script>alert(1)</script>',
      },
    });
    const [isThreat, info] = await detectPenetrationAttempt(request);
    expect(isThreat).toBe(true);
    expect(info).toContain('header');
  });

  it('returns false for clean request', async () => {
    const request = createMockRequest({
      urlPath: '/api/users',
      queryParams: { page: '1', sort: 'name' },
      headers: { 'user-agent': 'Mozilla/5.0', 'accept': 'application/json' },
    });
    const [isThreat, info] = await detectPenetrationAttempt(request);
    expect(isThreat).toBe(false);
    expect(info).toBe('');
  });

  it('detects malicious JSON body', async () => {
    const encoder = new TextEncoder();
    const maliciousBody = JSON.stringify({ input: '<script>alert(1)</script>' });
    const request = createMockRequest({
      body: async () => encoder.encode(maliciousBody),
    });
    const [isThreat, info] = await detectPenetrationAttempt(request);
    expect(isThreat).toBe(true);
    expect(info).toContain('body');
  });

  it('detects SQL injection in query params', async () => {
    const request = createMockRequest({
      queryParams: { id: "1 UNION SELECT * FROM users" },
    });
    const [isThreat, info] = await detectPenetrationAttempt(request);
    expect(isThreat).toBe(true);
    expect(info).toContain('query_params');
  });

  it('handles body read failure gracefully', async () => {
    const request = createMockRequest({
      urlPath: '/api/safe',
      queryParams: {},
      headers: { 'user-agent': 'Mozilla/5.0' },
      body: async () => { throw new Error('read error'); },
    });
    const [isThreat] = await detectPenetrationAttempt(request);
    expect(isThreat).toBe(false);
  });
});

describe('checkIpCountry', () => {
  it('blocks IP from blocked country', async () => {
    const geoIp = createMockGeoIpHandler({ '10.0.0.1': 'CN' });
    const config = createTestConfig({ blockedCountries: ['CN'], geoIpHandler: geoIp });
    const result = await checkIpCountry('10.0.0.1', config, geoIp);
    expect(result).toBe(true);
  });

  it('allows IP from non-blocked country', async () => {
    const geoIp = createMockGeoIpHandler({ '10.0.0.1': 'US' });
    const config = createTestConfig({ blockedCountries: ['CN'], geoIpHandler: geoIp });
    const result = await checkIpCountry('10.0.0.1', config, geoIp);
    expect(result).toBe(false);
  });

  it('returns false when no country config', async () => {
    const geoIp = createMockGeoIpHandler({ '10.0.0.1': 'US' });
    const config = createTestConfig();
    const result = await checkIpCountry('10.0.0.1', config, geoIp);
    expect(result).toBe(false);
  });

  it('blocks IP not in whitelist countries', async () => {
    const geoIp = createMockGeoIpHandler({ '10.0.0.1': 'RU' });
    const config = createTestConfig({ whitelistCountries: ['US', 'GB'], geoIpHandler: geoIp });
    const result = await checkIpCountry('10.0.0.1', config, geoIp);
    expect(result).toBe(true);
  });

  it('allows IP in whitelist countries', async () => {
    const geoIp = createMockGeoIpHandler({ '10.0.0.1': 'US' });
    const config = createTestConfig({ whitelistCountries: ['US', 'GB'], geoIpHandler: geoIp });
    const result = await checkIpCountry('10.0.0.1', config, geoIp);
    expect(result).toBe(false);
  });

  it('calls initialize when geoIpHandler is not initialized', async () => {
    const geoIp = createMockGeoIpHandler({ '10.0.0.1': 'CN' });
    (geoIp as { isInitialized: boolean }).isInitialized = false;
    const config = createTestConfig({ blockedCountries: ['CN'], geoIpHandler: geoIp });
    await checkIpCountry('10.0.0.1', config, geoIp);
    expect(geoIp.initialize).toHaveBeenCalled();
  });

  it('returns false when country is null', async () => {
    const geoIp = createMockGeoIpHandler({});
    const config = createTestConfig({ blockedCountries: ['CN'], geoIpHandler: geoIp });
    const result = await checkIpCountry('10.0.0.1', config, geoIp);
    expect(result).toBe(false);
  });
});

describe('logActivity extended', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('logs suspicious activity with passive mode prefix', () => {
    const logSpy = vi.spyOn(defaultLogger, 'warn');
    const request = createMockRequest();
    logActivity(request, defaultLogger, 'suspicious', 'test reason', true, 'xss detected');
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('[PASSIVE MODE]'));
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('xss detected'));
  });

  it('logs generic message for other logType', () => {
    const logSpy = vi.spyOn(defaultLogger, 'warn');
    const request = createMockRequest();
    logActivity(request, defaultLogger, 'blocked', 'access denied');
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('blocked from'));
  });

  it('logs with ERROR level', () => {
    const logSpy = vi.spyOn(defaultLogger, 'error');
    const request = createMockRequest();
    logActivity(request, defaultLogger, 'request', '', false, '', 'ERROR');
    expect(logSpy).toHaveBeenCalled();
  });

  it('logs with DEBUG level', () => {
    const logSpy = vi.spyOn(defaultLogger, 'debug');
    const request = createMockRequest();
    logActivity(request, defaultLogger, 'request', '', false, '', 'DEBUG');
    expect(logSpy).toHaveBeenCalled();
  });

  it('logs with INFO level for request logType', () => {
    const logSpy = vi.spyOn(defaultLogger, 'info');
    const request = createMockRequest();
    logActivity(request, defaultLogger, 'request', '', false, '', 'INFO');
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('Request from'));
  });

  it('logs with CRITICAL level uses error', () => {
    const logSpy = vi.spyOn(defaultLogger, 'error');
    const request = createMockRequest();
    logActivity(request, defaultLogger, 'request', '', false, '', 'CRITICAL');
    expect(logSpy).toHaveBeenCalled();
  });

  it('returns early when level is null', () => {
    const infoSpy = vi.spyOn(defaultLogger, 'info');
    const warnSpy = vi.spyOn(defaultLogger, 'warn');
    const errorSpy = vi.spyOn(defaultLogger, 'error');
    const debugSpy = vi.spyOn(defaultLogger, 'debug');
    const request = createMockRequest();
    logActivity(request, defaultLogger, 'request', '', false, '', null);
    expect(infoSpy).not.toHaveBeenCalled();
    expect(warnSpy).not.toHaveBeenCalled();
    expect(errorSpy).not.toHaveBeenCalled();
    expect(debugSpy).not.toHaveBeenCalled();
  });
});

describe('checks/helpers - checkCountryAccess', () => {
  it('returns null when no geoIpHandler', () => {
    const routeConfig = new RouteConfig();
    const result = checkCountryAccess('10.0.0.1', routeConfig, null);
    expect(result).toBeNull();
  });

  it('returns false when IP is from blocked country', () => {
    const geoIp = createMockGeoIpHandler({ '10.0.0.1': 'CN' });
    const routeConfig = new RouteConfig();
    routeConfig.blockedCountries = ['CN', 'RU'];
    const result = checkCountryAccess('10.0.0.1', routeConfig, geoIp);
    expect(result).toBe(false);
  });

  it('returns true when IP is from whitelisted country', () => {
    const geoIp = createMockGeoIpHandler({ '10.0.0.1': 'US' });
    const routeConfig = new RouteConfig();
    routeConfig.whitelistCountries = ['US', 'GB'];
    const result = checkCountryAccess('10.0.0.1', routeConfig, geoIp);
    expect(result).toBe(true);
  });

  it('returns false when IP is not from whitelisted country', () => {
    const geoIp = createMockGeoIpHandler({ '10.0.0.1': 'RU' });
    const routeConfig = new RouteConfig();
    routeConfig.whitelistCountries = ['US', 'GB'];
    const result = checkCountryAccess('10.0.0.1', routeConfig, geoIp);
    expect(result).toBe(false);
  });

  it('returns false when country is unknown and whitelist is set', () => {
    const geoIp = createMockGeoIpHandler({});
    const routeConfig = new RouteConfig();
    routeConfig.whitelistCountries = ['US'];
    const result = checkCountryAccess('10.0.0.1', routeConfig, geoIp);
    expect(result).toBe(false);
  });

  it('returns null when no country restrictions', () => {
    const geoIp = createMockGeoIpHandler({ '10.0.0.1': 'US' });
    const routeConfig = new RouteConfig();
    const result = checkCountryAccess('10.0.0.1', routeConfig, geoIp);
    expect(result).toBeNull();
  });

  it('checks both blocked and whitelist, blocked takes priority', () => {
    const geoIp = createMockGeoIpHandler({ '10.0.0.1': 'CN' });
    const routeConfig = new RouteConfig();
    routeConfig.blockedCountries = ['CN'];
    routeConfig.whitelistCountries = ['US'];
    const result = checkCountryAccess('10.0.0.1', routeConfig, geoIp);
    expect(result).toBe(false);
  });
});

describe('checks/helpers - checkRouteIpAccess', () => {
  it('returns false for blacklisted IP', async () => {
    const middleware = createMockMiddleware();
    const routeConfig = new RouteConfig();
    routeConfig.ipBlacklist = ['10.0.0.1'];
    const result = await checkRouteIpAccess('10.0.0.1', routeConfig, middleware);
    expect(result).toBe(false);
  });

  it('returns true for whitelisted IP', async () => {
    const middleware = createMockMiddleware();
    const routeConfig = new RouteConfig();
    routeConfig.ipWhitelist = ['10.0.0.1'];
    const result = await checkRouteIpAccess('10.0.0.1', routeConfig, middleware);
    expect(result).toBe(true);
  });

  it('returns false for IP not in whitelist', async () => {
    const middleware = createMockMiddleware();
    const routeConfig = new RouteConfig();
    routeConfig.ipWhitelist = ['192.168.1.1'];
    const result = await checkRouteIpAccess('10.0.0.1', routeConfig, middleware);
    expect(result).toBe(false);
  });

  it('returns null when no restrictions', async () => {
    const middleware = createMockMiddleware();
    const routeConfig = new RouteConfig();
    const result = await checkRouteIpAccess('10.0.0.1', routeConfig, middleware);
    expect(result).toBeNull();
  });

  it('delegates to checkCountryAccess when geoIpHandler is present', async () => {
    const geoIp = createMockGeoIpHandler({ '10.0.0.1': 'CN' });
    const middleware = createMockMiddleware();
    (middleware as Record<string, unknown>)['geoIpHandler'] = geoIp;
    const routeConfig = new RouteConfig();
    routeConfig.blockedCountries = ['CN'];
    const result = await checkRouteIpAccess('10.0.0.1', routeConfig, middleware);
    expect(result).toBe(false);
  });

  it('returns null when country check returns null', async () => {
    const geoIp = createMockGeoIpHandler({ '10.0.0.1': 'US' });
    const middleware = createMockMiddleware();
    (middleware as Record<string, unknown>)['geoIpHandler'] = geoIp;
    const routeConfig = new RouteConfig();
    const result = await checkRouteIpAccess('10.0.0.1', routeConfig, middleware);
    expect(result).toBeNull();
  });
});

describe('checks/helpers - checkUserAgentAllowed', () => {
  it('blocks user agent matching route-level pattern', async () => {
    const routeConfig = new RouteConfig();
    routeConfig.blockedUserAgents = ['BadBot.*'];
    const config = createTestConfig();
    const result = await checkUserAgentAllowed('BadBot/1.0', routeConfig, config);
    expect(result).toBe(false);
  });

  it('blocks user agent matching config-level pattern', async () => {
    const config = createTestConfig({ blockedUserAgents: ['EvilCrawler'] });
    const result = await checkUserAgentAllowed('EvilCrawler/2.0', null, config);
    expect(result).toBe(false);
  });

  it('allows user agent not matching any pattern', async () => {
    const config = createTestConfig({ blockedUserAgents: ['BadBot'] });
    const result = await checkUserAgentAllowed('Mozilla/5.0', null, config);
    expect(result).toBe(true);
  });

  it('allows user agent when no patterns configured', async () => {
    const config = createTestConfig();
    const result = await checkUserAgentAllowed('Mozilla/5.0', null, config);
    expect(result).toBe(true);
  });
});

describe('checks/helpers - detectPenetrationPatterns', () => {
  it('returns disabled_by_decorator when route disables detection but config enables it', async () => {
    const routeConfig = new RouteConfig();
    routeConfig.enableSuspiciousDetection = false;
    const config = createTestConfig({ enablePenetrationDetection: true });
    const [isThreat, reason] = await detectPenetrationPatterns(
      createMockRequest(),
      routeConfig,
      config,
      () => false,
    );
    expect(isThreat).toBe(false);
    expect(reason).toBe('disabled_by_decorator');
  });

  it('returns not_enabled when detection is off globally', async () => {
    const config = createTestConfig({ enablePenetrationDetection: false });
    const [isThreat, reason] = await detectPenetrationPatterns(
      createMockRequest(),
      null,
      config,
      () => false,
    );
    expect(isThreat).toBe(false);
    expect(reason).toBe('not_enabled');
  });

  it('detects threats when enabled', async () => {
    const config = createTestConfig({ enablePenetrationDetection: true });
    const request = createMockRequest({ queryParams: { q: '<script>alert(1)</script>' } });
    const [isThreat] = await detectPenetrationPatterns(
      request,
      null,
      config,
      () => false,
    );
    expect(isThreat).toBe(true);
  });

  it('returns false when check is bypassed', async () => {
    const config = createTestConfig({ enablePenetrationDetection: true });
    const request = createMockRequest({ queryParams: { q: '<script>alert(1)</script>' } });
    const [isThreat, reason] = await detectPenetrationPatterns(
      request,
      null,
      config,
      () => true,
    );
    expect(isThreat).toBe(false);
    expect(reason).toBe('not_enabled');
  });
});

describe('detectPenetrationAttempt with nested JSON body', () => {
  it('detects XSS in nested JSON field', async () => {
    const req = createMockRequest({
      method: 'POST',
      headers: { 'content-type': 'application/json', 'user-agent': 'T' },
      body: async () => new TextEncoder().encode(JSON.stringify({ nested: { field: '<script>alert(1)</script>' } })),
    });
    const [isThreat] = await detectPenetrationAttempt(req);
    expect(isThreat).toBe(true);
  });

  it('returns false for clean nested JSON', async () => {
    const req = createMockRequest({
      method: 'POST',
      headers: { 'content-type': 'application/json', 'user-agent': 'T' },
      body: async () => new TextEncoder().encode(JSON.stringify({ user: { name: 'Alice', age: 30 } })),
    });
    const [isThreat] = await detectPenetrationAttempt(req);
    expect(isThreat).toBe(false);
  });
});

describe('helpers remaining branches', () => {
  it('checkUserAgentAllowed with empty route patterns', async () => {
    const config = createTestConfig({ blockedUserAgents: ['bad'] });
    const rc = new RouteConfig();
    rc.blockedUserAgents = [];
    expect(await checkUserAgentAllowed('Chrome', rc, config)).toBe(true);
  });
});

describe('logActivity CRITICAL level', () => {
  it('logs at CRITICAL level (maps to error)', () => {
    const spy = vi.spyOn(defaultLogger, 'error').mockImplementation(() => {});
    logActivity(createMockRequest(), defaultLogger, 'custom', 'reason', false, '', 'CRITICAL');
    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
  });
});
