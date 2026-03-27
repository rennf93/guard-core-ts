import type { ResolvedSecurityConfig } from '../models/config.js';
import type { BehaviorRule } from '../models/behavior-rule.js';
import { RouteConfig } from '../models/route-config.js';
import type { AgentHandlerProtocol } from '../protocols/agent.js';
import type { RedisHandlerProtocol } from '../protocols/redis.js';
import type { GuardRequest } from '../protocols/request.js';
import type { GuardResponse } from '../protocols/response.js';
import { BehaviorTracker } from '../handlers/behavior.js';
import type { Logger } from '../models/logger.js';
import { defaultLogger } from '../models/logger.js';

type Constructor<T = object> = new (...args: unknown[]) => T;

const routeIdMap = new WeakMap<Function, string>();
let routeIdCounter = 0;

export class BaseSecurityDecorator {
  routeConfigs = new Map<string, RouteConfig>();
  behaviorTracker: BehaviorTracker;
  agentHandler: AgentHandlerProtocol | null = null;
  readonly config: ResolvedSecurityConfig;
  readonly logger: Logger;

  constructor(config: ResolvedSecurityConfig, logger?: Logger) {
    this.config = config;
    this.logger = logger ?? defaultLogger;
    this.behaviorTracker = new BehaviorTracker(config, this.logger);
  }

  getRouteConfig(routeId: string): RouteConfig | undefined {
    return this.routeConfigs.get(routeId);
  }

  ensureRouteConfig(fn: Function): RouteConfig {
    const id = this.getRouteId(fn);
    if (!this.routeConfigs.has(id)) {
      const rc = new RouteConfig();
      rc.enableSuspiciousDetection = this.config.enablePenetrationDetection;
      this.routeConfigs.set(id, rc);
    }
    return this.routeConfigs.get(id)!;
  }

  applyRouteConfig<T extends Function>(fn: T): T {
    (fn as Record<string, unknown>)['_guardRouteId'] = this.getRouteId(fn);
    return fn;
  }

  getRouteId(fn: Function): string {
    if (!routeIdMap.has(fn)) {
      routeIdMap.set(fn, `guard_route_${++routeIdCounter}`);
    }
    return routeIdMap.get(fn)!;
  }

  async initializeBehaviorTracking(redisHandler?: RedisHandlerProtocol): Promise<void> {
    if (redisHandler) await this.behaviorTracker.initializeRedis(redisHandler as unknown as import('../handlers/redis.js').RedisManager);
  }

  async initializeAgent(agentHandler: AgentHandlerProtocol): Promise<void> {
    this.agentHandler = agentHandler;
    await this.behaviorTracker.initializeAgent(agentHandler);
  }

  async sendDecoratorEvent(
    eventType: string,
    _request: GuardRequest,
    actionTaken: string,
    reason: string,
    decoratorType: string,
    meta?: Record<string, unknown>,
  ): Promise<void> {
    if (!this.agentHandler) return;
    try {
      await this.agentHandler.sendEvent({
        timestamp: new Date(),
        eventType,
        actionTaken,
        reason,
        decoratorType,
        metadata: meta ?? {},
      });
    } catch { /* never throw */ }
  }

  async sendAccessDeniedEvent(
    request: GuardRequest,
    reason: string,
    decoratorType: string,
    meta?: Record<string, unknown>,
  ): Promise<void> {
    await this.sendDecoratorEvent('access_denied', request, 'request_blocked', reason, decoratorType, meta);
  }

  async sendAuthenticationFailedEvent(
    request: GuardRequest,
    reason: string,
    authType: string,
    meta?: Record<string, unknown>,
  ): Promise<void> {
    await this.sendDecoratorEvent('authentication_failed', request, 'request_blocked', reason, 'authentication', { authType, ...meta });
  }

  async sendRateLimitEvent(
    request: GuardRequest,
    limit: number,
    window: number,
    meta?: Record<string, unknown>,
  ): Promise<void> {
    await this.sendDecoratorEvent('rate_limit_exceeded', request, 'request_blocked', `Rate limit ${limit}/${window}s exceeded`, 'rate_limit', { limit, window, ...meta });
  }

  async sendDecoratorViolationEvent(
    request: GuardRequest,
    violationType: string,
    reason: string,
    meta?: Record<string, unknown>,
  ): Promise<void> {
    await this.sendDecoratorEvent('decorator_violation', request, 'request_blocked', reason, violationType, meta);
  }
}

export function getRouteDecoratorConfig(
  request: GuardRequest,
  decoratorHandler: BaseSecurityDecorator,
): RouteConfig | undefined {
  const routeId = request.state.guardRouteId;
  if (!routeId || typeof routeId !== 'string') return undefined;
  return decoratorHandler.getRouteConfig(routeId);
}
