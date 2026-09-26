import type { GuardMiddlewareProtocol } from '../../../protocols/middleware.js';
import type { GuardRequest } from '../../../protocols/request.js';
import type { GuardResponse } from '../../../protocols/response.js';
import type { RouteConfig } from '../../../models/route-config.js';
import type { IPBanManager } from '../../../handlers/ip-ban.js';
import type { RouteConfigResolver } from '../../routing/resolver.js';
import { isIpAllowed } from '../../../utils.js';
import { checkRouteIpAccess, isIpInWhitelist } from '../helpers.js';
import { SecurityCheck } from '../base.js';

export class IpSecurityCheck extends SecurityCheck {
  private readonly ipBanManager: IPBanManager | null;

  constructor(middleware: GuardMiddlewareProtocol, ipBanManager?: IPBanManager | null) {
    super(middleware);
    /* The manager from the handler initializer is shared across requests;
       when absent (direct construction in tests or standalone pipelines) the
       check leaves it null and skips the dynamic-ban stage instead of
       building one per request. */
    this.ipBanManager = ipBanManager ?? null;
  }

  get checkName(): string { return 'ip_security'; }

  private async checkBannedIp(
    request: GuardRequest,
    clientIp: string,
    routeConfig: RouteConfig | undefined,
  ): Promise<GuardResponse | null> {
    if (!this.ipBanManager) return null;

    const resolver = this.middleware.routeResolver as RouteConfigResolver;
    if (resolver.shouldBypassCheck('ip_ban', routeConfig ?? null)) return null;

    if (!await this.ipBanManager.isIpBanned(clientIp)) return null;

    if (this.isPassiveMode()) {
      this.logger.info(`[PASSIVE] Banned IP attempted access: ${clientIp}`);
      return null;
    }
    await this.sendEvent('ip_blocked', request, 'request_blocked', `Banned IP attempted access: ${clientIp}`);
    return this.createErrorResponse(403, 'IP address banned');
  }

  async check(request: GuardRequest): Promise<GuardResponse | null> {
    const clientIp = request.clientHost;
    if (!clientIp) return null;

    const routeConfig = (request.state as Record<string, unknown>)['_routeConfig'] as RouteConfig | undefined;

    const banResponse = await this.checkBannedIp(request, clientIp, routeConfig);
    if (banResponse) return banResponse;

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

    /* Mirror of the reference _resolve_is_whitelisted/_resolve_is_exempt
       (guard_core/core/checks/implementations/ip_security.py): both flags
       require the deny checks (blacklist, whitelist, country) to have passed
       first, so exemption never adds or relaxes a deny path. A route-level
       ipWhitelist takes over the global lists and clears both flags, exactly
       like the reference skip_ip_lists gate. The exempt match reuses the
       whitelist matcher so exact, CIDR and family semantics stay identical. */
    const routeOverridesIpLists = Boolean(routeConfig?.ipWhitelist && routeConfig.ipWhitelist.length > 0);
    const whitelist = this.config.whitelist;
    const exemptIps = this.config.exemptIps;
    const allowed = await isIpAllowed(clientIp, this.config, this.middleware.geoIpHandler);

    request.state.isWhitelisted = allowed && !routeOverridesIpLists && whitelist !== null && whitelist.length > 0;
    request.state.isExempt = allowed && !routeOverridesIpLists
      && exemptIps.length > 0
      && isIpInWhitelist(clientIp, exemptIps) === true;

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
