import type { ResolvedSecurityConfig } from '../../models/config.js';
import type { Logger } from '../../models/logger.js';
import type { AgentHandlerProtocol } from '../../protocols/agent.js';
import type { GuardRequest } from '../../protocols/request.js';

export class MetricsCollector {
  constructor(
    private readonly agentHandler: AgentHandlerProtocol | null,
    private readonly config: ResolvedSecurityConfig,
    private readonly logger: Logger,
  ) {}

  async sendMetric(
    metricType: string,
    value: number,
    tags?: Record<string, string>,
  ): Promise<void> {
    if (!this.agentHandler || !this.config.agentEnableMetrics) return;

    try {
      await this.agentHandler.sendMetric({
        timestamp: new Date(),
        metricType,
        value,
        tags: tags ?? {},
      });
    } catch (e) {
      this.logger.error(`Failed to send metric: ${e}`);
    }
  }

  async collectRequestMetrics(
    request: GuardRequest,
    responseTime: number,
    statusCode: number,
  ): Promise<void> {
    if (!this.agentHandler || !this.config.agentEnableMetrics) return;

    const endpoint = request.urlPath;
    const method = request.method;
    const tags = { endpoint, method, status: String(statusCode) };

    await this.sendMetric('response_time', responseTime, tags);
    await this.sendMetric('request_count', 1.0, { endpoint, method });

    if (statusCode >= 400) {
      await this.sendMetric('error_rate', 1.0, tags);
    }
  }
}
