import type { GuardMiddlewareProtocol } from '../../../protocols/middleware.js';
import type { GuardRequest } from '../../../protocols/request.js';
import type { GuardResponse } from '../../../protocols/response.js';
import type { RequestValidator } from '../../validation/validator.js';
import type { ErrorResponseFactory } from '../../responses/factory.js';
import { SecurityCheck } from '../base.js';

export class HttpsEnforcementCheck extends SecurityCheck {
  private readonly validator: RequestValidator;
  private readonly responseFactory: ErrorResponseFactory;

  constructor(
    middleware: GuardMiddlewareProtocol,
    validator: RequestValidator,
    responseFactory: ErrorResponseFactory,
  ) {
    super(middleware);
    this.validator = validator;
    this.responseFactory = responseFactory;
  }

  get checkName(): string { return 'https_enforcement'; }

  async check(request: GuardRequest): Promise<GuardResponse | null> {
    if (!this.config.enforceHttps) return null;
    if (this.validator.isRequestHttps(request)) return null;

    if (this.isPassiveMode()) {
      this.logger.info(`[PASSIVE] Would redirect to HTTPS: ${request.urlPath}`);
      return null;
    }

    return this.responseFactory.createHttpsRedirect(request);
  }
}
