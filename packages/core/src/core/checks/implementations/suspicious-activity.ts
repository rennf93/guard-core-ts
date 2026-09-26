import type { GuardMiddlewareProtocol } from '../../../protocols/middleware.js';
import type { GuardRequest } from '../../../protocols/request.js';
import type { GuardResponse } from '../../../protocols/response.js';
import type { SusPatternsManager } from '../../../handlers/sus-patterns.js';
import type { IPBanManager } from '../../../handlers/ip-ban.js';
import type { RouteConfig } from '../../../models/route-config.js';
import type { RouteConfigResolver } from '../../routing/resolver.js';
import { detectPenetrationPatterns, incrementSuspiciousCounts, totalSuspiciousCount, tryThresholdBan } from '../helpers.js';
import { logActivity } from '../../../utils.js';
import { SecurityCheck } from '../base.js';

export class SuspiciousActivityCheck extends SecurityCheck {
  private readonly susPatterns: SusPatternsManager | null;
  private readonly ipBanManager: IPBanManager | null;

  constructor(
    middleware: GuardMiddlewareProtocol,
    susPatternsManager?: SusPatternsManager | null,
    ipBanManager?: IPBanManager | null,
  ) {
    super(middleware);
    /* The managers from the handler initializer are shared across requests;
       when absent (direct construction in tests or standalone pipelines) the
       check leaves the pattern manager null and detectPenetrationPatterns
       falls back to the shared default manager, and leaves the ban manager
       null so the threshold-ban stage skips instead of building one per
       request. */
    this.susPatterns = susPatternsManager ?? null;
    this.ipBanManager = ipBanManager ?? null;
  }

  get checkName(): string { return 'suspicious_activity'; }

  async check(request: GuardRequest): Promise<GuardResponse | null> {
    /* Whitelist matches skip penetration detection entirely (reference
       SuspiciousActivityCheck.check). An exempt_ips match deliberately does
       NOT skip here: detection, its violation counting and its escalation
       still run for exempt IPs, exactly like the reference. */
    if (request.state.isWhitelisted === true) return null;

    if (!this.config.enablePenetrationDetection) return null;

    const clientIp = request.clientHost;
    if (!clientIp) return null;

    const routeConfig = (request.state as Record<string, unknown>)['_routeConfig'] as RouteConfig | undefined;
    const resolver = this.middleware.routeResolver as RouteConfigResolver;

    const [isThreat, triggerInfo, threatCategories] = await detectPenetrationPatterns(
      request,
      routeConfig ?? null,
      this.config,
      (check, rc) => resolver.shouldBypassCheck(check, rc),
      this.susPatterns,
    );

    if (!isThreat) return null;

    /* The reference counts violations in both modes before branching
       (guard_core/core/checks/implementations/suspicious_activity.py), so
       passive mode still accumulates toward a later active-mode ban. */
    incrementSuspiciousCounts(this.middleware, clientIp, threatCategories);
    const requestCount = totalSuspiciousCount(this.middleware, clientIp);

    if (this.isPassiveMode()) {
      logActivity(request, this.logger, 'suspicious', 'Suspicious activity detected',
        true, triggerInfo, this.config.logSuspiciousLevel);
      await this.sendEvent('penetration_attempt', request, 'logged_only',
        `Suspicious pattern detected (passive mode): ${triggerInfo}`,
        { triggerInfo, requestCount });
      return null;
    }

    const banned = await tryThresholdBan(
      request, this.config, this.ipBanManager, this.middleware,
      clientIp, triggerInfo, this.logger, threatCategories,
    );
    if (banned) {
      return this.createErrorResponse(403, 'IP has been banned');
    }

    logActivity(request, this.logger, 'suspicious', 'Suspicious activity detected',
      this.config.passiveMode, triggerInfo, this.config.logSuspiciousLevel);

    await this.sendEvent('penetration_attempt', request, 'request_blocked',
      `Penetration attempt detected: ${triggerInfo}`, { triggerInfo, requestCount });

    return this.createErrorResponse(403, 'Suspicious activity detected');
  }
}
