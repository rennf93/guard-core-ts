export type {
  AgentHandlerProtocol,
  GeoIPHandler,
  GuardMiddlewareProtocol,
  GuardRequest,
  GuardRequestState,
  GuardResponse,
  GuardResponseFactory,
  RedisHandlerProtocol,
} from './protocols/index.js';

export {
  BehaviorRule,
  defaultLogger,
  DynamicRulesSchema,
  RouteConfig,
  SecurityConfigSchema,
} from './models/index.js';

export type {
  BehaviorAction,
  BehaviorRuleType,
  DynamicRules,
  Logger,
  ResolvedSecurityConfig,
  SecurityConfig,
} from './models/index.js';

export {
  ContentPreprocessor,
  PatternCompiler,
  PerformanceMonitor,
  SemanticAnalyzer,
} from './detection-engine/index.js';

export type {
  PatternReport,
  PatternStats,
  PerformanceMetric,
  SemanticAnalysis,
} from './detection-engine/index.js';

export { initializeSecurityMiddleware } from './middleware-support.js';
export type { SecurityMiddlewareComponents } from './middleware-support.js';
export { SecurityCheckPipeline, SecurityEventBus, MetricsCollector, RequestValidator,
  RouteConfigResolver, BypassHandler, ErrorResponseFactory, BehavioralProcessor,
} from './middleware-support.js';
export type { HandlerRegistry } from './middleware-support.js';

export { BaseSecurityDecorator, SecurityDecorator, getRouteDecoratorConfig } from './decorators/index.js';

export { extractClientIp, isIpAllowed, isUserAgentAllowed, checkIpCountry,
  detectPenetrationAttempt, sanitizeForLog, logActivity, sendAgentEvent,
} from './utils.js';
