import type { GuardRequest } from '../../../protocols/request.js';
import type { GuardResponse } from '../../../protocols/response.js';
import type { RouteConfig } from '../../../models/route-config.js';
import type { RateLimitManager } from '../../../handlers/rate-limit.js';
import { SecurityCheck } from '../base.js';

export class RateLimitCheck extends SecurityCheck {
  get checkName(): string { return 'rate_limit'; }

  async check(request: GuardRequest): Promise<GuardResponse | null> {
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
}
