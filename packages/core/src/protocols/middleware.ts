import type { ResolvedSecurityConfig } from '../models/config.js';
import type { Logger } from '../models/logger.js';
import type { AgentHandlerProtocol } from './agent.js';
import type { GeoIPHandler } from './geo-ip.js';
import type { GuardResponse, GuardResponseFactory } from './response.js';

export interface GuardMiddlewareProtocol {
  readonly config: ResolvedSecurityConfig;
  readonly logger: Logger;
  lastCloudIpRefresh: number;
  /* Per-IP per-detection-category violation counters, the TS twin of the
     reference middleware.suspicious_request_counts dict-of-dicts
     (guard_core/core/checks/helpers.py): the autoban engine reads the
     category totals against autoBanThreshold and threatBanConfig. */
  suspiciousRequestCounts: Map<string, Map<string, number>>;
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
