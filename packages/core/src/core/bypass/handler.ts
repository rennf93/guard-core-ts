import type { ResolvedSecurityConfig } from '../../models/config.js';
import type { RouteConfig } from '../../models/route-config.js';
import type { GuardRequest } from '../../protocols/request.js';
import type { GuardResponse } from '../../protocols/response.js';
import type { SecurityEventBus } from '../events/event-bus.js';
import type { ErrorResponseFactory } from '../responses/factory.js';
import type { RouteConfigResolver } from '../routing/resolver.js';
import type { RequestValidator } from '../validation/validator.js';

export class BypassHandler {
  constructor(
    private readonly config: ResolvedSecurityConfig,
    private readonly eventBus: SecurityEventBus,
    private readonly routeResolver: RouteConfigResolver,
    private readonly responseFactory: ErrorResponseFactory,
    private readonly validator: RequestValidator,
  ) {}

  async handlePassthrough(
    request: GuardRequest,
    callNext: (req: GuardRequest) => Promise<GuardResponse>,
  ): Promise<GuardResponse | null> {
    if (!request.clientHost) {
      const response = await callNext(request);
      return this.responseFactory.applyModifier(response);
    }

    if (await this.validator.isPathExcluded(request)) {
      const response = await callNext(request);
      return this.responseFactory.applyModifier(response);
    }

    return null;
  }

  async handleSecurityBypass(
    request: GuardRequest,
    callNext: (req: GuardRequest) => Promise<GuardResponse>,
    routeConfig: RouteConfig | null,
  ): Promise<GuardResponse | null> {
    if (!routeConfig || !this.routeResolver.shouldBypassCheck('all', routeConfig)) {
      return null;
    }

    await this.eventBus.sendMiddlewareEvent(
      'security_bypass', request, 'all_checks_bypassed',
      'Route configured to bypass all security checks',
      { bypassedChecks: [...routeConfig.bypassedChecks], endpoint: request.urlPath },
    );

    if (!this.config.passiveMode) {
      const response = await callNext(request);
      return this.responseFactory.applyModifier(response);
    }

    return null;
  }
}
