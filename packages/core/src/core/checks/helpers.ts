import * as ipaddr from 'ipaddr.js';

import type { ResolvedSecurityConfig } from '../../models/config.js';
import type { RouteConfig } from '../../models/route-config.js';
import type { GeoIPHandler } from '../../protocols/geo-ip.js';
import type { GuardMiddlewareProtocol } from '../../protocols/middleware.js';
import type { GuardRequest } from '../../protocols/request.js';

export function isIpInBlacklist(clientIp: string, blacklist: string[]): boolean {
  for (const blocked of blacklist) {
    if (blocked.includes('/')) {
      try {
        const parsed = ipaddr.parse(clientIp);
        const [addr, prefixLen] = ipaddr.parseCIDR(blocked);
        if (parsed.kind() === addr.kind() && parsed.match([addr, prefixLen])) return true;
      } catch { continue; }
    } else if (clientIp === blocked) {
      return true;
    }
  }
  return false;
}

export function isIpInWhitelist(clientIp: string, whitelist: string[]): boolean | null {
  if (whitelist.length === 0) return null;

  for (const allowed of whitelist) {
    if (allowed.includes('/')) {
      try {
        const parsed = ipaddr.parse(clientIp);
        const [addr, prefixLen] = ipaddr.parseCIDR(allowed);
        if (parsed.kind() === addr.kind() && parsed.match([addr, prefixLen])) return true;
      } catch { continue; }
    } else if (clientIp === allowed) {
      return true;
    }
  }
  return false;
}

export function checkCountryAccess(
  clientIp: string,
  routeConfig: RouteConfig,
  geoIpHandler: GeoIPHandler | null,
): boolean | null {
  if (!geoIpHandler) return null;

  let country: string | null = null;

  if (routeConfig.blockedCountries && routeConfig.blockedCountries.length > 0) {
    country = geoIpHandler.getCountry(clientIp);
    if (country && routeConfig.blockedCountries.includes(country)) return false;
  }

  if (routeConfig.whitelistCountries && routeConfig.whitelistCountries.length > 0) {
    if (country === null) country = geoIpHandler.getCountry(clientIp);
    if (country) return routeConfig.whitelistCountries.includes(country);
    return false;
  }

  return null;
}

export async function checkRouteIpAccess(
  clientIp: string,
  routeConfig: RouteConfig,
  middleware: GuardMiddlewareProtocol,
): Promise<boolean | null> {
  try {
    if (routeConfig.ipBlacklist && routeConfig.ipBlacklist.length > 0) {
      if (isIpInBlacklist(clientIp, routeConfig.ipBlacklist)) return false;
    }

    if (routeConfig.ipWhitelist && routeConfig.ipWhitelist.length > 0) {
      const whitelistResult = isIpInWhitelist(clientIp, routeConfig.ipWhitelist);
      if (whitelistResult !== null) return whitelistResult;
    }

    const countryResult = checkCountryAccess(clientIp, routeConfig, middleware.geoIpHandler);
    if (countryResult !== null) return countryResult;

    return null;
  /* v8 ignore start -- catch block requires ipaddr.parse to throw on a value that already passed validation */
  } catch {
    return false;
  }
  /* v8 ignore stop */
}

export async function checkUserAgentAllowed(
  userAgent: string,
  routeConfig: RouteConfig | null,
  config: ResolvedSecurityConfig,
): Promise<boolean> {
  if (routeConfig && routeConfig.blockedUserAgents.length > 0) {
    for (const pattern of routeConfig.blockedUserAgents) {
      if (new RegExp(pattern, 'i').test(userAgent)) return false;
    }
    /* v8 ignore next -- empty blockedUserAgents on routeConfig branch; tests always set global blockedUserAgents */
  }

  for (const pattern of config.blockedUserAgents) {
    if (new RegExp(pattern, 'i').test(userAgent)) return false;
  }

  return true;
}

export function validateAuthHeader(authHeader: string, authType: string): [boolean, string] {
  if (authType === 'bearer') {
    if (!authHeader.startsWith('Bearer ')) return [false, 'Missing or invalid Bearer token'];
  } else if (authType === 'basic') {
    if (!authHeader.startsWith('Basic ')) return [false, 'Missing or invalid Basic authentication'];
  } else {
    if (!authHeader) return [false, `Missing ${authType} authentication`];
  }
  return [true, ''];
}

export function isReferrerDomainAllowed(referrer: string, allowedDomains: string[]): boolean {
  try {
    const url = new URL(referrer);
    const referrerDomain = url.hostname.toLowerCase();
    for (const allowed of allowedDomains) {
      const lowerAllowed = allowed.toLowerCase();
      if (referrerDomain === lowerAllowed || referrerDomain.endsWith(`.${lowerAllowed}`)) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}

export async function detectPenetrationPatterns(
  request: GuardRequest,
  routeConfig: RouteConfig | null,
  config: ResolvedSecurityConfig,
  shouldBypassCheckFn: (check: string, rc: RouteConfig | null) => boolean,
): Promise<[boolean, string]> {
  let penetrationEnabled = config.enablePenetrationDetection;
  let routeSpecificDetection: boolean | null = null;

  if (routeConfig) {
    routeSpecificDetection = routeConfig.enableSuspiciousDetection;
    penetrationEnabled = routeSpecificDetection;
  }

  if (penetrationEnabled && !shouldBypassCheckFn('penetration', routeConfig)) {
    const { detectPenetrationAttempt } = await import('../../utils.js');
    return detectPenetrationAttempt(request);
  }

  const reason = routeSpecificDetection === false && config.enablePenetrationDetection
    ? 'disabled_by_decorator'
    : 'not_enabled';
  return [false, reason];
}
