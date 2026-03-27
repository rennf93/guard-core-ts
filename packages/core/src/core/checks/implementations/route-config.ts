import type { GuardRequest } from '../../../protocols/request.js';
import type { GuardResponse } from '../../../protocols/response.js';
import { SecurityCheck } from '../base.js';

export class RouteConfigCheck extends SecurityCheck {
  get checkName(): string { return 'route_config'; }

  async check(request: GuardRequest): Promise<GuardResponse | null> {
    const routeResolver = this.middleware.routeResolver as {
      getRouteConfig(request: GuardRequest): unknown;
    };
    const routeConfig = routeResolver.getRouteConfig(request);

    if (routeConfig) {
      (request.state as Record<string, unknown>)['_routeConfig'] = routeConfig;
    }

    return null;
  }
}
