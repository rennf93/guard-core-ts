import type { ResolvedSecurityConfig } from '../../models/config.js';
import type { RouteConfig } from '../../models/route-config.js';
import type { GuardRequest } from '../../protocols/request.js';

export class RouteConfigResolver {
  private guardDecorator: unknown = null;

  constructor(
    private readonly config: ResolvedSecurityConfig,
  ) {}

  setGuardDecorator(decorator: unknown): void {
    this.guardDecorator = decorator;
  }

  getRouteConfig(request: GuardRequest): RouteConfig | null {
    const decorator = this.guardDecorator ?? request.state.guardDecorator;
    if (!decorator) return null;

    const routeId = request.state.guardRouteId;
    if (!routeId) return null;

    const getConfig = (decorator as { getRouteConfig(id: string): RouteConfig | undefined }).getRouteConfig;
    if (typeof getConfig !== 'function') return null;

    return getConfig.call(decorator, routeId) ?? null;
  }

  shouldBypassCheck(checkName: string, routeConfig: RouteConfig | null): boolean {
    if (!routeConfig) return false;
    return routeConfig.bypassedChecks.has(checkName) || routeConfig.bypassedChecks.has('all');
  }

  getCloudProvidersToCheck(routeConfig: RouteConfig | null): string[] | null {
    if (routeConfig && routeConfig.blockCloudProviders.size > 0) {
      return [...routeConfig.blockCloudProviders];
    }
    if (this.config.blockCloudProviders.size > 0) {
      return [...this.config.blockCloudProviders];
    }
    return null;
  }
}
