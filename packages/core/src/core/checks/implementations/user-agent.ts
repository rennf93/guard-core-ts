import type { GuardRequest } from '../../../protocols/request.js';
import type { GuardResponse } from '../../../protocols/response.js';
import type { RouteConfig } from '../../../models/route-config.js';
import { checkUserAgentAllowed } from '../helpers.js';
import { SecurityCheck } from '../base.js';

export class UserAgentCheck extends SecurityCheck {
  get checkName(): string { return 'user_agent'; }

  async check(request: GuardRequest): Promise<GuardResponse | null> {
    const userAgent = request.headers['user-agent'] ?? '';
    if (!userAgent) return null;

    const routeConfig = (request.state as Record<string, unknown>)['_routeConfig'] as RouteConfig | undefined;
    const allowed = await checkUserAgentAllowed(userAgent, routeConfig ?? null, this.config);

    if (!allowed) {
      if (this.isPassiveMode()) {
        this.logger.info(`[PASSIVE] Blocked user agent: ${userAgent}`);
        return null;
      }
      await this.sendEvent('ua_blocked', request, 'request_blocked', `Blocked user agent: ${userAgent}`);
      return this.createErrorResponse(403, 'Access denied');
    }

    return null;
  }
}
