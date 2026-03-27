import type { GuardRequest } from '../../../protocols/request.js';
import type { GuardResponse } from '../../../protocols/response.js';
import type { RouteConfig } from '../../../models/route-config.js';
import type { RouteConfigResolver } from '../../routing/resolver.js';
import { SecurityCheck } from '../base.js';

export class CloudProviderCheck extends SecurityCheck {
  get checkName(): string { return 'cloud_provider'; }

  async check(request: GuardRequest): Promise<GuardResponse | null> {
    const clientIp = request.clientHost;
    if (!clientIp) return null;

    const routeConfig = (request.state as Record<string, unknown>)['_routeConfig'] as RouteConfig | undefined;
    const resolver = this.middleware.routeResolver as RouteConfigResolver;
    const providers = resolver.getCloudProvidersToCheck(routeConfig ?? null);

    if (!providers || providers.length === 0) return null;

    const { CloudHandler } = await import('../../../handlers/cloud.js');
    // Access cloud handler from middleware — it's in the registry
    // For now, we check via a lightweight import
    // The actual middleware will wire this properly

    return null;
  }
}
