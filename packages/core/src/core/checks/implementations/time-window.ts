import type { RouteConfig } from '../../../models/route-config.js';
import type { GuardMiddlewareProtocol } from '../../../protocols/middleware.js';
import type { GuardRequest } from '../../../protocols/request.js';
import type { GuardResponse } from '../../../protocols/response.js';
import type { RequestValidator } from '../../validation/validator.js';
import { SecurityCheck } from '../base.js';

export class TimeWindowCheck extends SecurityCheck {
  private readonly validator: RequestValidator;

  constructor(middleware: GuardMiddlewareProtocol, validator: RequestValidator) {
    super(middleware);
    this.validator = validator;
  }

  get checkName(): string { return 'time_window'; }

  async check(request: GuardRequest): Promise<GuardResponse | null> {
    const routeConfig = (request.state as Record<string, unknown>)['_routeConfig'] as RouteConfig | undefined;
    if (!routeConfig?.timeRestrictions) return null;

    const withinWindow = await this.validator.checkTimeWindow(routeConfig.timeRestrictions);
    if (!withinWindow) {
      if (this.isPassiveMode()) {
        this.logger.info('[PASSIVE] Request outside time window');
        return null;
      }
      return this.createErrorResponse(403, 'Access denied: outside allowed time window');
    }

    return null;
  }
}
