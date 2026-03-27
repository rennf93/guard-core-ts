import type { GuardRequest } from '../../../protocols/request.js';
import type { GuardResponse } from '../../../protocols/response.js';
import type { RouteConfig } from '../../../models/route-config.js';
import type { IPBanManager } from '../../../handlers/ip-ban.js';
import { isIpAllowed } from '../../../utils.js';
import { checkRouteIpAccess } from '../helpers.js';
import { SecurityCheck } from '../base.js';

export class IpSecurityCheck extends SecurityCheck {
  get checkName(): string { return 'ip_security'; }

  async check(request: GuardRequest): Promise<GuardResponse | null> {
    const clientIp = request.clientHost;
    if (!clientIp) return null;

    const ipBanHandler = this.middleware.rateLimitHandler as unknown as {
      ipBanHandler?: IPBanManager;
    };

    const routeConfig = (request.state as Record<string, unknown>)['_routeConfig'] as RouteConfig | undefined;

    if (routeConfig) {
      const routeResult = await checkRouteIpAccess(clientIp, routeConfig, this.middleware);
      if (routeResult === false) {
        if (this.isPassiveMode()) {
          this.logger.info(`[PASSIVE] IP blocked by route config: ${clientIp}`);
          return null;
        }
        await this.sendEvent('ip_blocked', request, 'request_blocked', `IP ${clientIp} blocked by route config`);
        return this.createErrorResponse(403, 'Access denied');
      }
    }

    const allowed = await isIpAllowed(clientIp, this.config, this.middleware.geoIpHandler);
    if (!allowed) {
      if (this.isPassiveMode()) {
        this.logger.info(`[PASSIVE] IP not allowed: ${clientIp}`);
        return null;
      }
      await this.sendEvent('ip_blocked', request, 'request_blocked', `IP ${clientIp} not allowed`);
      return this.createErrorResponse(403, 'Access denied');
    }

    return null;
  }
}
