/**
 * Middleware-level parity tests for the autoban engine (guard-core
 * suspicious-activity + rate-limit autoban port).
 *
 * Every vector below goes through the real pipeline built by
 * initializeSecurityMiddleware, mirroring the reference semantics
 * (guard_core/core/checks/helpers.py _increment_suspicious_counts /
 * _resolve_and_apply_threshold_ban / _try_threshold_ban, the
 * SuspiciousActivityCheck threshold stage, and RateLimitCheck's
 * _record_rate_limit_autoban): violations accumulate per IP and detection
 * category, threat_ban_config entries fire at their own threshold and
 * duration with the flat auto_ban_threshold/auto_ban_duration as fallback,
 * enable_ip_banning gates ban creation entirely, passive mode counts but
 * never bans, and a crossed rate limit feeds the 'rate_limit' pseudo-category
 * when enableRateLimitAutoBan is on. Enforcement of the resulting ban is the
 * IpSecurityCheck dynamic-ban stage (#73), which runs earlier in the
 * pipeline, so the request after the ban gets 403 'IP address banned'.
 */

import { describe, it, expect, vi, beforeAll } from 'vitest';
import { initializeSecurityMiddleware } from '../../../src/middleware-support.js';
import type { SecurityMiddlewareComponents } from '../../../src/middleware-support.js';
import { SecurityConfigSchema } from '../../../src/models/config.js';
import { defaultLogger } from '../../../src/models/logger.js';
import type { GuardRequest } from '../../../src/protocols/request.js';
import { createMockResponseFactory, createMockMiddleware } from '../../helpers.js';
import { incrementSuspiciousCounts, resolveThresholdBan } from '../../../src/core/checks/helpers.js';

const IP = '203.0.113.77';

function attackRequest(overrides: Partial<GuardRequest> = {}): GuardRequest {
  return {
    urlPath: '/api/test',
    urlScheme: 'https',
    urlFull: 'https://example.com/api/test',
    urlReplaceScheme: (s: string) => `${s}://example.com/api/test`,
    method: 'GET',
    clientHost: IP,
    headers: { 'user-agent': 'TestAgent/1.0' },
    queryParams: { q: '<script>alert(1)</script>' },
    body: async () => new Uint8Array(0),
    state: {},
    scope: {},
    ...overrides,
  };
}

async function build(configOverrides: Record<string, unknown> = {}): Promise<SecurityMiddlewareComponents> {
  const config = SecurityConfigSchema.parse({ enableRedis: false, ...configOverrides });
  return initializeSecurityMiddleware(config, defaultLogger, createMockResponseFactory());
}

describe('autoban engine (middleware level)', () => {
  it('crossing autoBanThreshold bans the IP; subsequent requests are blocked by ip-security', async () => {
    const components = await build({
      enableRateLimiting: false,
      autoBanThreshold: 3,
      autoBanDuration: 1800,
    });

    const first = await components.pipeline.execute(attackRequest());
    expect(first!.bodyText).toBe('Suspicious activity detected');
    const second = await components.pipeline.execute(attackRequest());
    expect(second!.bodyText).toBe('Suspicious activity detected');
    expect(await components.registry.ipBanHandler.isIpBanned(IP)).toBe(false);

    /* The crossing request is answered with the reference ban response. */
    const third = await components.pipeline.execute(attackRequest());
    expect(third!.bodyText).toBe('IP has been banned');
    expect(await components.registry.ipBanHandler.isIpBanned(IP)).toBe(true);

    /* The next request, even a clean one, dies in the ip-security ban stage. */
    const clean = await components.pipeline.execute(attackRequest({ queryParams: {} }));
    expect(clean!.statusCode).toBe(403);
    expect(clean!.bodyText).toBe('IP address banned');
  });

  it('a category without a threatBanConfig entry does not ban at the entry threshold', async () => {
    const components = await build({
      enableRateLimiting: false,
      threatBanConfig: { sqli: { threshold: 2, duration: 600 } },
      autoBanThreshold: 10,
    });

    for (let i = 0; i < 3; i++) {
      const response = await components.pipeline.execute(attackRequest());
      expect(response!.bodyText).toBe('Suspicious activity detected');
    }
    expect(await components.registry.ipBanHandler.isIpBanned(IP)).toBe(false);
  });

  it('a threatBanConfig entry bans at its own threshold with its own duration and reason', async () => {
    const components = await build({
      enableRateLimiting: false,
      threatBanConfig: { xss: { threshold: 2, duration: 600 } },
      autoBanThreshold: 10,
    });
    const banSpy = vi.spyOn(components.registry.ipBanHandler, 'banIp');

    const first = await components.pipeline.execute(attackRequest());
    expect(first!.bodyText).toBe('Suspicious activity detected');
    const second = await components.pipeline.execute(attackRequest());
    expect(second!.bodyText).toBe('IP has been banned');

    expect(banSpy).toHaveBeenCalledWith(IP, 600, 'penetration_attempt:xss');
    expect(await components.registry.ipBanHandler.isIpBanned(IP)).toBe(true);
  });

  it('enableIpBanning false never bans, no matter how many violations pile up', async () => {
    const components = await build({
      enableRateLimiting: false,
      enableIpBanning: false,
      autoBanThreshold: 1,
    });

    for (let i = 0; i < 3; i++) {
      const response = await components.pipeline.execute(attackRequest());
      expect(response!.bodyText).toBe('Suspicious activity detected');
    }
    expect(await components.registry.ipBanHandler.isIpBanned(IP)).toBe(false);
  });

  it('passive mode counts violations but never bans and never blocks', async () => {
    const components = await build({
      enableRateLimiting: false,
      passiveMode: true,
      autoBanThreshold: 1,
    });

    for (let i = 0; i < 2; i++) {
      expect(await components.pipeline.execute(attackRequest())).toBeNull();
    }
    expect(components.middlewareProtocol.suspiciousRequestCounts.get(IP)?.get('xss')).toBe(2);
    expect(await components.registry.ipBanHandler.isIpBanned(IP)).toBe(false);
  });

  it('enableRateLimitAutoBan bans a client that crosses the global rate limit', async () => {
    const components = await build({
      enablePenetrationDetection: false,
      enableRateLimitAutoBan: true,
      rateLimit: 2,
      rateLimitWindow: 60,
      autoBanThreshold: 1,
      autoBanDuration: 900,
    });

    expect(await components.pipeline.execute(attackRequest({ queryParams: {} }))).toBeNull();
    expect(await components.pipeline.execute(attackRequest({ queryParams: {} }))).toBeNull();
    expect(await components.registry.ipBanHandler.isIpBanned(IP)).toBe(false);

    /* Third request crosses the limit (429) and the autoban fires. */
    const throttled = await components.pipeline.execute(attackRequest({ queryParams: {} }));
    expect(throttled!.statusCode).toBe(429);
    expect(await components.registry.ipBanHandler.isIpBanned(IP)).toBe(true);

    /* The next request dies in the ip-security ban stage, not as a 429. */
    const banned = await components.pipeline.execute(attackRequest({ queryParams: {} }));
    expect(banned!.statusCode).toBe(403);
    expect(banned!.bodyText).toBe('IP address banned');
  });

  it('the threatBanConfig rate_limit pseudo-category overrides the flat threshold', async () => {
    const components = await build({
      enablePenetrationDetection: false,
      enableRateLimitAutoBan: true,
      rateLimit: 1,
      rateLimitWindow: 60,
      threatBanConfig: { rate_limit: { threshold: 2, duration: 7200 } },
      autoBanThreshold: 5,
    });
    const banSpy = vi.spyOn(components.registry.ipBanHandler, 'banIp');

    /* First crossing: rate_limit count 1 < 2 and the flat total 1 < 5, no ban. */
    expect(await components.pipeline.execute(attackRequest({ queryParams: {} }))).toBeNull();
    const firstCrossing = await components.pipeline.execute(attackRequest({ queryParams: {} }));
    expect(firstCrossing!.statusCode).toBe(429);
    expect(await components.registry.ipBanHandler.isIpBanned(IP)).toBe(false);

    /* Second crossing: rate_limit count 2 reaches the pseudo-category
       threshold and overrides the still-under-flat-threshold total. */
    const secondCrossing = await components.pipeline.execute(attackRequest({ queryParams: {} }));
    expect(secondCrossing!.statusCode).toBe(429);
    expect(banSpy).toHaveBeenCalledWith(IP, 7200, 'rate_limit_exceeded:rate_limit');
    expect(await components.registry.ipBanHandler.isIpBanned(IP)).toBe(true);
  });

  it('enableRateLimitAutoBan off (default) keeps rate limiting ban-free', async () => {
    const components = await build({
      enablePenetrationDetection: false,
      rateLimit: 1,
      rateLimitWindow: 60,
    });

    expect(await components.pipeline.execute(attackRequest({ queryParams: {} }))).toBeNull();
    for (let i = 0; i < 3; i++) {
      expect((await components.pipeline.execute(attackRequest({ queryParams: {} })))!.statusCode).toBe(429);
    }
    expect(await components.registry.ipBanHandler.isIpBanned(IP)).toBe(false);
  });
});

describe('threatBanConfig config validation', () => {
  it('defaults to an empty map with enableRateLimitAutoBan off', () => {
    const config = SecurityConfigSchema.parse({});
    expect(config.threatBanConfig).toEqual({});
    expect(config.enableRateLimitAutoBan).toBe(false);
    expect(config.enableIpBanning).toBe(true);
  });

  it('accepts detection categories and the rate_limit pseudo-category', () => {
    const config = SecurityConfigSchema.parse({
      threatBanConfig: {
        xss: { threshold: 5, duration: 300 },
        sqli: { threshold: 3, duration: 600 },
        rate_limit: { threshold: 2, duration: 7200 },
      },
    });
    expect(config.threatBanConfig['xss']).toEqual({ threshold: 5, duration: 300 });
    expect(config.threatBanConfig['rate_limit']).toEqual({ threshold: 2, duration: 7200 });
  });

  it('rejects unknown categories and non-positive threshold or duration', () => {
    expect(() => SecurityConfigSchema.parse({
      threatBanConfig: { not_a_category: { threshold: 1, duration: 60 } },
    })).toThrow();

    expect(() => SecurityConfigSchema.parse({
      threatBanConfig: { xss: { threshold: 0, duration: 60 } },
    })).toThrow();

    expect(() => SecurityConfigSchema.parse({
      threatBanConfig: { xss: { threshold: 1, duration: 0 } },
    })).toThrow();
  });
});

describe('suspicious count helpers', () => {
  it('incrementSuspiciousCounts collapses strings and empty category lists', () => {
    const middleware = createMockMiddleware();

    incrementSuspiciousCounts(middleware, IP, 'xss');
    expect(middleware.suspiciousRequestCounts.get(IP)?.get('xss')).toBe(1);

    incrementSuspiciousCounts(middleware, '192.0.2.9', []);
    expect(middleware.suspiciousRequestCounts.get('192.0.2.9')?.get('uncategorized')).toBe(1);
  });

  it('incrementSuspiciousCounts tracks categories separately and evicts the oldest IP at the cap', () => {
    const middleware = createMockMiddleware();

    incrementSuspiciousCounts(middleware, IP, ['xss', 'sqli']);
    incrementSuspiciousCounts(middleware, IP, ['xss']);
    expect(middleware.suspiciousRequestCounts.get(IP)?.get('xss')).toBe(2);
    expect(middleware.suspiciousRequestCounts.get(IP)?.get('sqli')).toBe(1);

    for (let i = 0; i < 10_000 - 1; i++) {
      middleware.suspiciousRequestCounts.set(`10.0.0.${i % 255}.${Math.floor(i / 255)}`, new Map([['xss', 1]]));
    }
    expect(middleware.suspiciousRequestCounts.size).toBe(10_000);
    incrementSuspiciousCounts(middleware, '192.0.2.99', 'xss');
    expect(middleware.suspiciousRequestCounts.size).toBe(10_000);
    expect(middleware.suspiciousRequestCounts.has('192.0.2.99')).toBe(true);
    /* The victim is the oldest tracked IP, not the newest arrival. */
    expect(middleware.suspiciousRequestCounts.has(IP)).toBe(false);
    expect(middleware.suspiciousRequestCounts.has('10.0.0.0.0')).toBe(true);
  });

  it('resolveThresholdBan tries category entries first and falls back to the flat threshold', async () => {
    const config = SecurityConfigSchema.parse({
      threatBanConfig: {
        xss: { threshold: 1, duration: 300 },
        sqli: { threshold: 5, duration: 600 },
      },
      autoBanThreshold: 3,
      autoBanDuration: 1800,
    });
    const middleware = createMockMiddleware();
    const banSpy = vi.fn<(ip: string, duration: number, reason: string) => Promise<boolean>>(
      async () => true,
    );
    const manager = { banIp: banSpy } as never;

    /* xss (first in category order) wins over sqli even though both crossed. */
    incrementSuspiciousCounts(middleware, IP, ['xss', 'sqli']);
    const byCategory = await resolveThresholdBan(
      middleware.suspiciousRequestCounts.get(IP)!, config, manager, IP, ['xss', 'sqli'], 'penetration_attempt',
    );
    expect(byCategory).toEqual([300, 'penetration_attempt:xss', 'xss']);

    /* No category entry matched: the flat path measures the category total. */
    incrementSuspiciousCounts(middleware, '192.0.2.10', ['dir_traversal', 'cmd_injection', 'ldap']);
    const flat = await resolveThresholdBan(
      middleware.suspiciousRequestCounts.get('192.0.2.10')!, config, manager, '192.0.2.10',
      ['dir_traversal', 'cmd_injection', 'ldap'], 'penetration_attempt',
    );
    expect(flat).toEqual([1800, 'penetration_attempt', null]);

    /* Under every threshold: no ban. */
    incrementSuspiciousCounts(middleware, '192.0.2.11', ['dir_traversal']);
    expect(await resolveThresholdBan(
      middleware.suspiciousRequestCounts.get('192.0.2.11')!, config, manager, '192.0.2.11',
      ['dir_traversal'], 'penetration_attempt',
    )).toBeNull();

    /* A refused ban reports no ban applied. */
    const refusingManager = { banIp: vi.fn(async () => false) } as never;
    expect(await resolveThresholdBan(
      middleware.suspiciousRequestCounts.get(IP)!, config, refusingManager, IP, ['xss'], 'penetration_attempt',
    )).toBeNull();

    /* Banning disabled or no manager: never a ban. */
    const noBanningConfig = SecurityConfigSchema.parse({ enableIpBanning: false });
    expect(await resolveThresholdBan(
      middleware.suspiciousRequestCounts.get(IP)!, noBanningConfig, manager, IP, ['xss'], 'penetration_attempt',
    )).toBeNull();
    expect(await resolveThresholdBan(
      middleware.suspiciousRequestCounts.get(IP)!, config, null, IP, ['xss'], 'penetration_attempt',
    )).toBeNull();
  });
});
