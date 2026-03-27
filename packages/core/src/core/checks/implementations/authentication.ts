import type { RouteConfig } from '../../../models/route-config.js';
import type { GuardRequest } from '../../../protocols/request.js';
import type { GuardResponse } from '../../../protocols/response.js';
import { validateAuthHeader } from '../helpers.js';
import { SecurityCheck } from '../base.js';

export class AuthenticationCheck extends SecurityCheck {
  get checkName(): string { return 'authentication'; }

  async check(request: GuardRequest): Promise<GuardResponse | null> {
    const routeConfig = (request.state as Record<string, unknown>)['_routeConfig'] as RouteConfig | undefined;
    if (!routeConfig) return null;

    if (routeConfig.authRequired) {
      const authHeader = request.headers['authorization'] ?? '';
      const [isValid, message] = validateAuthHeader(authHeader, routeConfig.authRequired);
      if (!isValid) {
        if (this.isPassiveMode()) {
          this.logger.info(`[PASSIVE] Auth failed: ${message}`);
          return null;
        }
        await this.sendEvent('authentication_failed', request, 'request_blocked', message);
        return this.createErrorResponse(401, message);
      }
    }

    if (routeConfig.apiKeyRequired) {
      const apiKey = request.headers['x-api-key'] ?? '';
      if (!apiKey) {
        if (this.isPassiveMode()) {
          this.logger.info('[PASSIVE] Missing API key');
          return null;
        }
        return this.createErrorResponse(401, 'API key required');
      }
    }

    return null;
  }
}
