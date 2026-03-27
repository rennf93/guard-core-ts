import type { ResolvedSecurityConfig } from '../models/config.js';
import type { Logger } from '../models/logger.js';
import type { AgentHandlerProtocol } from './agent.js';
import type { GeoIPHandler } from './geo-ip.js';
import type { GuardResponse, GuardResponseFactory } from './response.js';

export interface GuardMiddlewareProtocol {
  readonly config: ResolvedSecurityConfig;
  readonly logger: Logger;
  lastCloudIpRefresh: number;
  suspiciousRequestCounts: Map<string, number>;
  readonly eventBus: unknown;
  readonly routeResolver: unknown;
  readonly responseFactory: unknown;
  readonly rateLimitHandler: unknown;
  readonly agentHandler: AgentHandlerProtocol | null;
  readonly geoIpHandler: GeoIPHandler | null;
  readonly guardResponseFactory: GuardResponseFactory;
  createErrorResponse(statusCode: number, defaultMessage: string): Promise<GuardResponse>;
  refreshCloudIpRanges(): Promise<void>;
}
