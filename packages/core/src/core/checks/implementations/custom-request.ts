import type { GuardRequest } from '../../../protocols/request.js';
import type { GuardResponse } from '../../../protocols/response.js';
import { SecurityCheck } from '../base.js';

export class CustomRequestCheck extends SecurityCheck {
  get checkName(): string { return 'custom_request'; }

  async check(request: GuardRequest): Promise<GuardResponse | null> {
    if (!this.config.customRequestCheck) return null;
    return this.config.customRequestCheck(request);
  }
}
