import type { GuardRequest } from '../../../protocols/request.js';
import type { GuardResponse } from '../../../protocols/response.js';
import type { RouteConfig } from '../../../models/route-config.js';
import type { RateLimitManager } from '../../../handlers/rate-limit.js';
import { SecurityCheck } from '../base.js';

export class RateLimitCheck extends SecurityCheck {
  get checkName(): string { return 'rate_limit'; }

  async check(request: GuardRequest): Promise<GuardResponse | null> {
    /* Whitelist and exempt_ips matches skip rate limiting (reference
       RateLimitCheck.check). */
    if (request.state.isWhitelisted === true || request.state.isExempt === true) return null;

    if (!this.config.enableRateLimiting) return null;

    const clientIp = request.clientHost;
    if (!clientIp) return null;

    const rateLimitHandler = this.middleware.rateLimitHandler as RateLimitManager;
    const routeConfig = (request.state as Record<string, unknown>)['_routeConfig'] as RouteConfig | undefined;
    const createError = this.createErrorResponse.bind(this);

    /* v8 ignore next -- routeConfig?.rateLimit null check; rateLimit is always set in test fixtures */
    if (routeConfig?.rateLimit !== null && routeConfig?.rateLimit !== undefined) {
      const response = await rateLimitHandler.checkRateLimit(
        request, clientIp, createError, request.urlPath,
        routeConfig.rateLimit, routeConfig.rateLimitWindow ?? this.config.rateLimitWindow,
      );
      if (response) {
        if (this.isPassiveMode()) {
          this.logger.info(`[PASSIVE] Route rate limit exceeded for ${clientIp}`);
          return null;
        }
        return response;
      }
    }

    const endpointLimit = this.config.endpointRateLimits[request.urlPath];
    if (endpointLimit) {
      const [limit, window] = endpointLimit;
      const response = await rateLimitHandler.checkRateLimit(
        request, clientIp, createError, request.urlPath, limit, window,
      );
      if (response) {
        if (this.isPassiveMode()) {
          this.logger.info(`[PASSIVE] Endpoint rate limit exceeded for ${clientIp}`);
          return null;
        }
        return response;
      }
    }

    const geoResponse = await this.checkGeoRateLimit(request, clientIp, routeConfig ?? null);
    if (geoResponse) {
      if (this.isPassiveMode()) {
        this.logger.info(`[PASSIVE] Geo rate limit exceeded for ${clientIp}`);
        return null;
      }
      return geoResponse;
    }

    const response = await rateLimitHandler.checkRateLimit(
      request, clientIp, createError, null,
      this.config.rateLimit, this.config.rateLimitWindow,
    );
    if (response) {
      if (this.isPassiveMode()) {
        this.logger.info(`[PASSIVE] Global rate limit exceeded for ${clientIp}`);
        return null;
      }
      return response;
    }

    return null;
  }

  /* Reference RateLimitCheck._check_geo_rate_limit: the tier list is the
     route's geoRateLimits map, keyed by two-letter country code with the
     pseudo-code "*" as the fallback tier. The country resolves through the
     middleware's geoip handler; a country-specific entry wins over "*", and
     when geo resolution is unavailable (no handler) or no tier matches, no
     geo limit applies and the request falls through to the global limit.
     The tier counts per IP and endpoint, like every other endpoint-scoped
     tier. */
  private async checkGeoRateLimit(
    request: GuardRequest,
    clientIp: string,
    routeConfig: RouteConfig | null,
  ): Promise<GuardResponse | null> {
    const limits = routeConfig?.geoRateLimits;
    if (!limits || Object.keys(limits).length === 0) return null;

    const geoHandler = this.middleware.geoIpHandler;
    if (!geoHandler) return null;

    const country = geoHandler.getCountry(clientIp);
    let tier: [number, number] | undefined;
    if (country !== null && country in limits) {
      tier = limits[country];
    } else if ('*' in limits) {
      tier = limits['*'];
    }
    if (!tier) return null;

    const [limit, window] = tier;
    return (this.middleware.rateLimitHandler as RateLimitManager).checkRateLimit(
      request, clientIp, this.createErrorResponse.bind(this), request.urlPath, limit, window,
    );
  }
}
