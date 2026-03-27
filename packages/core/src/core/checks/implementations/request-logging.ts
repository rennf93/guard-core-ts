import type { GuardRequest } from '../../../protocols/request.js';
import type { GuardResponse } from '../../../protocols/response.js';
import { logActivity } from '../../../utils.js';
import { SecurityCheck } from '../base.js';

export class RequestLoggingCheck extends SecurityCheck {
  get checkName(): string { return 'request_logging'; }

  async check(request: GuardRequest): Promise<GuardResponse | null> {
    if (this.config.logRequestLevel) {
      logActivity(request, this.logger, 'request', '', false, '', this.config.logRequestLevel);
      await this.sendEvent('request_logged', request, 'logged', 'Request logged');
    }
    return null;
  }
}
