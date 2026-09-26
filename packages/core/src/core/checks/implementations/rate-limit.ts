import type { GuardMiddlewareProtocol } from '../../../protocols/middleware.js';
import type { GuardRequest } from '../../../protocols/request.js';
import type { GuardResponse } from '../../../protocols/response.js';
import type { RouteConfig } from '../../../models/route-config.js';
import type { RateLimitManager } from '../../../handlers/rate-limit.js';
import type { IPBanManager } from '../../../handlers/ip-ban.js';
import { incrementSuspiciousCounts, tryThresholdBan } from '../helpers.js';
import { SecurityCheck } from '../base.js';

export class RateLimitCheck extends SecurityCheck {
  private readonly ipBanManager: IPBanManager | null;

  constructor(middleware: GuardMiddlewareProtocol, ipBanManager?: IPBanManager | null) {
    super(middleware);
    /* The manager from the handler initializer is shared across requests;
       when absent (direct construction in tests or standalone pipelines) the
       check leaves it null and the autoban stage skips instead of building
       one per request. */
    this.ipBanManager = ipBanManager ?? null;
  }

  get checkName(): string { return 'rate_limit'; }

  /* Reference RateLimitCheck._record_rate_limit_autoban
     (guard_core/core/checks/implementations/rate_limit.py): with
     enableRateLimitAutoBan on, each active-mode (non-passive) violation
     feeds the 'rate_limit' pseudo-category of the shared suspicious-count
     structure and runs the same threshold logic as penetration detection
     (threatBanConfig['rate_limit'] override first, then the flat
     autoBanThreshold/autoBanDuration). Passive mode never reaches the
     autoban: the caller returns before it. */
  private async recordRateLimitAutoBan(
    request: GuardRequest,
    clientIp: string,
    triggerInfo: string,
  ): Promise<void> {
    if (!this.config.enableRateLimitAutoBan) return;
    incrementSuspiciousCounts(this.middleware, clientIp, 'rate_limit');
    await tryThresholdBan(
      request, this.config, this.ipBanManager, this.middleware,
      clientIp, triggerInfo, this.logger, ['rate_limit'], 'rate_limit_exceeded',
    );
  }

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
        await this.recordRateLimitAutoBan(request, clientIp, 'Route-specific rate limit exceeded');
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
        await this.recordRateLimitAutoBan(request, clientIp, 'Endpoint-specific rate limit exceeded');
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
      await this.recordRateLimitAutoBan(request, clientIp, 'Global rate limit exceeded');
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
