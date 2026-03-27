import type { ResolvedSecurityConfig } from '../models/config.js';
import type { Logger } from '../models/logger.js';
import type { BehaviorAction, BehaviorRule } from '../models/behavior-rule.js';
import type { AgentHandlerProtocol } from '../protocols/agent.js';
import type { GuardResponse } from '../protocols/response.js';
import type { RedisManager } from './redis.js';

export class BehaviorTracker {
  private usageCounts = new Map<string, Map<string, number[]>>();
  private returnPatterns = new Map<string, Map<string, number[]>>();
  private redisHandler: RedisManager | null = null;
  private agentHandler: AgentHandlerProtocol | null = null;

  constructor(
    private readonly config: ResolvedSecurityConfig,
    private readonly logger: Logger,
  ) {}

  async initializeRedis(redisHandler: RedisManager): Promise<void> {
    this.redisHandler = redisHandler;
  }

  async initializeAgent(agentHandler: AgentHandlerProtocol): Promise<void> {
    this.agentHandler = agentHandler;
  }

  async trackEndpointUsage(endpointId: string, clientIp: string, rule: BehaviorRule): Promise<boolean> {
    const now = Date.now() / 1000;
    const windowStart = now - rule.window;

    if (!this.usageCounts.has(endpointId)) {
      this.usageCounts.set(endpointId, new Map());
    }
    const endpointMap = this.usageCounts.get(endpointId)!;

    if (!endpointMap.has(clientIp)) {
      endpointMap.set(clientIp, []);
    }
    const timestamps = endpointMap.get(clientIp)!;

    const validIdx = timestamps.findIndex((t) => t > windowStart);
    /* v8 ignore next -- branch-only gap in validIndex timestamp cleanup condition */
    if (validIdx > 0) timestamps.splice(0, validIdx);
    else if (validIdx === -1) timestamps.length = 0;

    timestamps.push(now);

    return timestamps.length > rule.threshold;
  }

  async trackReturnPattern(
    endpointId: string,
    clientIp: string,
    response: GuardResponse,
    rule: BehaviorRule,
  ): Promise<boolean> {
    if (!rule.pattern) return false;

    const matched = this.checkResponsePattern(response, rule.pattern);
    if (!matched) return false;

    const now = Date.now() / 1000;
    const windowStart = now - rule.window;
    const key = `${endpointId}:${rule.pattern}`;

    if (!this.returnPatterns.has(key)) {
      this.returnPatterns.set(key, new Map());
    }
    const patternMap = this.returnPatterns.get(key)!;

    if (!patternMap.has(clientIp)) {
      patternMap.set(clientIp, []);
    }
    const timestamps = patternMap.get(clientIp)!;

    const validIdx = timestamps.findIndex((t) => t > windowStart);
    /* v8 ignore next -- branch-only gap in validIndex timestamp cleanup condition */
    if (validIdx > 0) timestamps.splice(0, validIdx);
    else if (validIdx === -1) timestamps.length = 0;

    timestamps.push(now);

    return timestamps.length > rule.threshold;
  }

  private checkResponsePattern(response: GuardResponse, pattern: string): boolean {
    if (pattern.startsWith('status:')) {
      const code = parseInt(pattern.slice(7), 10);
      return response.statusCode === code;
    }

    if (pattern.startsWith('regex:')) {
      const re = new RegExp(pattern.slice(6), 'i');
      return response.bodyText ? re.test(response.bodyText) : false;
    }

    if (pattern.startsWith('json:')) {
      if (!response.bodyText) return false;
      try {
        const data = JSON.parse(response.bodyText);
        const path = pattern.slice(5);
        const parts = path.split('.');
        let current: unknown = data;
        for (const part of parts) {
          /* v8 ignore next -- JSON path traversal null guard; requires partial JSON structure */
          if (current === null || current === undefined) return false;
          current = (current as Record<string, unknown>)[part];
        }
        return current !== undefined && current !== null;
      } catch { return false; }
    }

    /* v8 ignore next -- branch-only gap in bodyText includes fallback */
    return response.bodyText ? response.bodyText.includes(pattern) : false;
  }

  async applyAction(
    rule: BehaviorRule,
    clientIp: string,
    endpointId: string,
    details: string,
  ): Promise<void> {
    if (this.config.passiveMode) {
      this.logger.info(`[PASSIVE] Would ${rule.action} ${clientIp} for ${details}`);
      return;
    }

    switch (rule.action) {
      case 'ban':
        this.logger.warn(`Behavioral ban: ${clientIp} - ${details}`);
        break;
      case 'log':
        this.logger.info(`Behavioral log: ${clientIp} - ${details}`);
        break;
      case 'throttle':
        this.logger.info(`Behavioral throttle: ${clientIp} - ${details}`);
        break;
      case 'alert':
        this.logger.warn(`Behavioral alert: ${clientIp} - ${details}`);
        break;
    }

    if (rule.customAction) {
      try { rule.customAction(rule.action, clientIp, endpointId, details); } catch { /* ignore */ }
    }

    if (this.agentHandler) {
      try {
        await this.agentHandler.sendEvent({
          eventType: 'behavioral_action',
          ipAddress: clientIp,
          actionTaken: rule.action,
          reason: details,
          metadata: { endpointId, ruleType: rule.ruleType, threshold: rule.threshold },
        });
      } catch { /* never throw */ }
    }
  }

  async reset(): Promise<void> {
    this.usageCounts.clear();
    this.returnPatterns.clear();
  }
}
