import type { GuardRequest } from '../../../protocols/request.js';
import type { GuardResponse } from '../../../protocols/response.js';
import type { RouteConfig } from '../../../models/route-config.js';
import type { RouteConfigResolver } from '../../routing/resolver.js';
import { detectPenetrationPatterns } from '../helpers.js';
import { logActivity } from '../../../utils.js';
import { SecurityCheck } from '../base.js';

export class SuspiciousActivityCheck extends SecurityCheck {
  get checkName(): string { return 'suspicious_activity'; }

  async check(request: GuardRequest): Promise<GuardResponse | null> {
    if (!this.config.enablePenetrationDetection) return null;

    const clientIp = request.clientHost;
    if (!clientIp) return null;

    const routeConfig = (request.state as Record<string, unknown>)['_routeConfig'] as RouteConfig | undefined;
    const resolver = this.middleware.routeResolver as RouteConfigResolver;

    const [isThreat, triggerInfo] = await detectPenetrationPatterns(
      request,
      routeConfig ?? null,
      this.config,
      (check, rc) => resolver.shouldBypassCheck(check, rc),
    );

    if (!isThreat) return null;

    const counts = this.middleware.suspiciousRequestCounts;
    const currentCount = (counts.get(clientIp) ?? 0) + 1;
    counts.set(clientIp, currentCount);

    logActivity(request, this.logger, 'suspicious', 'Suspicious activity detected',
      this.config.passiveMode, triggerInfo, this.config.logSuspiciousLevel);

    await this.sendEvent('penetration_attempt', request, 'request_blocked',
      `Suspicious activity: ${triggerInfo}`, { triggerInfo, requestCount: currentCount });

    if (this.isPassiveMode()) return null;

    return this.createErrorResponse(403, 'Suspicious activity detected');
  }
}
