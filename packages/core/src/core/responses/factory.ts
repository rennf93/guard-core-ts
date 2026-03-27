import type { ResolvedSecurityConfig } from '../../models/config.js';
import type { Logger } from '../../models/logger.js';
import type { RouteConfig } from '../../models/route-config.js';
import type { AgentHandlerProtocol } from '../../protocols/agent.js';
import type { GuardRequest } from '../../protocols/request.js';
import type { GuardResponse, GuardResponseFactory } from '../../protocols/response.js';
import type { SecurityHeadersManager } from '../../handlers/security-headers.js';
import type { MetricsCollector } from '../events/metrics.js';

export class ErrorResponseFactory {
  constructor(
    private readonly config: ResolvedSecurityConfig,
    private readonly logger: Logger,
    private readonly metricsCollector: MetricsCollector,
    private readonly guardResponseFactory: GuardResponseFactory,
    private readonly securityHeadersManager: SecurityHeadersManager,
    private readonly agentHandler: AgentHandlerProtocol | null = null,
  ) {}

  async createErrorResponse(statusCode: number, defaultMessage: string): Promise<GuardResponse> {
    const message = this.config.customErrorResponses[statusCode] ?? defaultMessage;
    const response = this.guardResponseFactory.createResponse(message, statusCode);

    await this.applySecurityHeaders(response, undefined);
    return this.applyModifier(response);
  }

  async createHttpsRedirect(request: GuardRequest): Promise<GuardResponse> {
    const httpsUrl = request.urlReplaceScheme('https');
    const response = this.guardResponseFactory.createRedirectResponse(httpsUrl, 301);
    return this.applyModifier(response);
  }

  async applySecurityHeaders(response: GuardResponse, requestPath?: string): Promise<GuardResponse> {
    const headersConfig = this.config.securityHeaders;
    if (headersConfig && headersConfig.enabled) {
      const securityHeaders = await this.securityHeadersManager.getHeaders(requestPath ?? '/');
      for (const [name, value] of Object.entries(securityHeaders)) {
        response.setHeader(name, value);
      }
    }
    return response;
  }

  async applyCorsHeaders(response: GuardResponse, origin: string): Promise<GuardResponse> {
    const corsHeaders = this.securityHeadersManager.getCorsHeaders(origin);
    for (const [name, value] of Object.entries(corsHeaders)) {
      response.setHeader(name, value);
    }
    return response;
  }

  async applyModifier(response: GuardResponse): Promise<GuardResponse> {
    if (this.config.customResponseModifier) {
      return this.config.customResponseModifier(response);
    }
    return response;
  }

  async processResponse(
    request: GuardRequest,
    response: GuardResponse,
    responseTime: number,
    routeConfig: RouteConfig | null,
    processBehavioralRules?: (
      request: GuardRequest,
      response: GuardResponse,
      clientIp: string,
      routeConfig: RouteConfig,
    ) => Promise<void>,
  ): Promise<GuardResponse> {
    /* v8 ignore next -- requires all 3 conditions (routeConfig, behaviorRules.length, callback) true simultaneously */
    if (routeConfig && routeConfig.behaviorRules.length > 0 && processBehavioralRules) {
      const clientIp = request.clientHost ?? 'unknown';
      await processBehavioralRules(request, response, clientIp, routeConfig);
    }

    await this.metricsCollector.collectRequestMetrics(request, responseTime, response.statusCode);

    await this.applySecurityHeaders(response, request.urlPath);

    const origin = request.headers['origin'];
    if (origin) {
      await this.applyCorsHeaders(response, origin);
    }

    return this.applyModifier(response);
  }
}
