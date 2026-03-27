import type { Logger } from '../../models/logger.js';
import type { RouteConfig } from '../../models/route-config.js';
import type { GuardRequest } from '../../protocols/request.js';
import type { GuardResponse } from '../../protocols/response.js';
import type { BehaviorTracker } from '../../handlers/behavior.js';
import type { SecurityEventBus } from '../events/event-bus.js';

export class BehavioralProcessor {
  private guardDecorator: { behaviorTracker: BehaviorTracker } | null = null;

  constructor(
    private readonly logger: Logger,
    private readonly eventBus: SecurityEventBus,
  ) {}

  setGuardDecorator(decorator: { behaviorTracker: BehaviorTracker }): void {
    this.guardDecorator = decorator;
  }

  async processUsageRules(
    request: GuardRequest,
    clientIp: string,
    routeConfig: RouteConfig,
  ): Promise<void> {
    if (!this.guardDecorator) return;

    const endpointId = this.getEndpointId(request);
    const tracker = this.guardDecorator.behaviorTracker;

    for (const rule of routeConfig.behaviorRules) {
      if (rule.ruleType === 'usage' || rule.ruleType === 'frequency') {
        const exceeded = await tracker.trackEndpointUsage(endpointId, clientIp, rule);
        if (exceeded) {
          const details = `${rule.threshold} calls in ${rule.window}s`;

          await this.eventBus.sendMiddlewareEvent(
            'decorator_violation', request, 'behavioral_action_triggered',
            `Behavioral ${rule.ruleType} threshold exceeded: ${details}`,
            {
              decoratorType: 'behavioral',
              violationType: rule.ruleType,
              threshold: rule.threshold,
              window: rule.window,
              action: rule.action,
              endpointId,
            },
          );

          await tracker.applyAction(rule, clientIp, endpointId, `Usage threshold exceeded: ${details}`);
        }
      }
    }
  }

  async processReturnRules(
    request: GuardRequest,
    response: GuardResponse,
    clientIp: string,
    routeConfig: RouteConfig,
  ): Promise<void> {
    if (!this.guardDecorator) return;

    const endpointId = this.getEndpointId(request);
    const tracker = this.guardDecorator.behaviorTracker;

    for (const rule of routeConfig.behaviorRules) {
      if (rule.ruleType === 'return_pattern') {
        const detected = await tracker.trackReturnPattern(endpointId, clientIp, response, rule);
        if (detected) {
          const details = `${rule.threshold} for '${rule.pattern}' in ${rule.window}s`;

          await this.eventBus.sendMiddlewareEvent(
            'decorator_violation', request, 'behavioral_action_triggered',
            `Return pattern threshold exceeded: ${details}`,
            {
              decoratorType: 'behavioral',
              violationType: 'return_pattern',
              threshold: rule.threshold,
              window: rule.window,
              pattern: rule.pattern,
              action: rule.action,
              endpointId,
            },
          );

          await tracker.applyAction(rule, clientIp, endpointId, `Return pattern threshold exceeded: ${details}`);
        }
      }
    }
  }

  getEndpointId(request: GuardRequest): string {
    const endpointId = request.state.guardEndpointId;
    if (typeof endpointId === 'string') return endpointId;
    return `${request.method}:${request.urlPath}`;
  }
}
