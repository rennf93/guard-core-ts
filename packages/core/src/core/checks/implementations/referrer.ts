import type { RouteConfig } from '../../../models/route-config.js';
import type { GuardRequest } from '../../../protocols/request.js';
import type { GuardResponse } from '../../../protocols/response.js';
import { isReferrerDomainAllowed } from '../helpers.js';
import { SecurityCheck } from '../base.js';

export class ReferrerCheck extends SecurityCheck {
  get checkName(): string { return 'referrer'; }

  async check(request: GuardRequest): Promise<GuardResponse | null> {
    const routeConfig = (request.state as Record<string, unknown>)['_routeConfig'] as RouteConfig | undefined;
    if (!routeConfig?.requireReferrer || routeConfig.requireReferrer.length === 0) return null;

    const referrer = request.headers['referer'] ?? request.headers['referrer'] ?? '';
    if (!referrer || !isReferrerDomainAllowed(referrer, routeConfig.requireReferrer)) {
      if (this.isPassiveMode()) {
        this.logger.info(`[PASSIVE] Invalid referrer: ${referrer}`);
        return null;
      }
      return this.createErrorResponse(403, 'Invalid referrer');
    }

    return null;
  }
}
