import type { RouteConfig } from '../../../models/route-config.js';
import type { GuardRequest } from '../../../protocols/request.js';
import type { GuardResponse } from '../../../protocols/response.js';
import { SecurityCheck } from '../base.js';

export class CustomValidatorsCheck extends SecurityCheck {
  get checkName(): string { return 'custom_validators'; }

  async check(request: GuardRequest): Promise<GuardResponse | null> {
    const routeConfig = (request.state as Record<string, unknown>)['_routeConfig'] as RouteConfig | undefined;
    if (!routeConfig || routeConfig.customValidators.length === 0) return null;

    for (const validator of routeConfig.customValidators) {
      const response = await validator(request);
      if (response !== null) return response;
    }

    return null;
  }
}
