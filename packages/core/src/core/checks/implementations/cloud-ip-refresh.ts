import type { GuardRequest } from '../../../protocols/request.js';
import type { GuardResponse } from '../../../protocols/response.js';
import { SecurityCheck } from '../base.js';

export class CloudIpRefreshCheck extends SecurityCheck {
  get checkName(): string { return 'cloud_ip_refresh'; }

  async check(_request: GuardRequest): Promise<GuardResponse | null> {
    if (this.config.blockCloudProviders.size === 0) return null;

    const now = Date.now() / 1000;
    const elapsed = now - this.middleware.lastCloudIpRefresh;

    if (elapsed >= this.config.cloudIpRefreshInterval) {
      this.middleware.lastCloudIpRefresh = now;
      try {
        await this.middleware.refreshCloudIpRanges();
      } catch (e) {
        this.logger.error(`Cloud IP refresh failed: ${e}`);
      }
    }

    return null;
  }
}
