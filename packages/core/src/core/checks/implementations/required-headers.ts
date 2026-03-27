import type { RouteConfig } from '../../../models/route-config.js';
import type { GuardRequest } from '../../../protocols/request.js';
import type { GuardResponse } from '../../../protocols/response.js';
import { SecurityCheck } from '../base.js';

export class RequiredHeadersCheck extends SecurityCheck {
  get checkName(): string { return 'required_headers'; }

  async check(request: GuardRequest): Promise<GuardResponse | null> {
    const routeConfig = (request.state as Record<string, unknown>)['_routeConfig'] as RouteConfig | undefined;
    if (!routeConfig || Object.keys(routeConfig.requiredHeaders).length === 0) return null;

    for (const [headerName, expectedValue] of Object.entries(routeConfig.requiredHeaders)) {
      const actualValue = request.headers[headerName.toLowerCase()];
      if (!actualValue || (expectedValue && actualValue !== expectedValue)) {
        if (this.isPassiveMode()) {
          this.logger.info(`[PASSIVE] Missing required header: ${headerName}`);
          return null;
        }
        return this.createErrorResponse(400, `Missing or invalid required header: ${headerName}`);
      }
    }

    return null;
  }
}
