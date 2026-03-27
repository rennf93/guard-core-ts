import type { RouteConfig } from '../../../models/route-config.js';
import type { GuardRequest } from '../../../protocols/request.js';
import type { GuardResponse } from '../../../protocols/response.js';
import { SecurityCheck } from '../base.js';

export class RequestSizeContentCheck extends SecurityCheck {
  get checkName(): string { return 'request_size_content'; }

  async check(request: GuardRequest): Promise<GuardResponse | null> {
    const routeConfig = (request.state as Record<string, unknown>)['_routeConfig'] as RouteConfig | undefined;
    if (!routeConfig) return null;

    if (routeConfig.maxRequestSize !== null) {
      const contentLength = parseInt(request.headers['content-length'] ?? '0', 10);
      if (contentLength > routeConfig.maxRequestSize) {
        if (this.isPassiveMode()) {
          this.logger.info(`[PASSIVE] Request too large: ${contentLength} > ${routeConfig.maxRequestSize}`);
          return null;
        }
        return this.createErrorResponse(413, 'Request entity too large');
      }
    }

    if (routeConfig.allowedContentTypes !== null) {
      const contentType = request.headers['content-type'] ?? '';
      if (contentType && !routeConfig.allowedContentTypes.some((t) => contentType.includes(t))) {
        if (this.isPassiveMode()) {
          this.logger.info(`[PASSIVE] Invalid content type: ${contentType}`);
          return null;
        }
        return this.createErrorResponse(415, 'Unsupported media type');
      }
    }

    return null;
  }
}
