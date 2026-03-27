import type { RedisHandlerProtocol } from './redis.js';

export interface AgentHandlerProtocol {
  initializeRedis(redisHandler: RedisHandlerProtocol): Promise<void>;
  sendEvent(event: unknown): Promise<void>;
  sendMetric(metric: unknown): Promise<void>;
  start(): Promise<void>;
  stop(): Promise<void>;
  flushBuffer(): Promise<void>;
  getDynamicRules(): Promise<unknown | null>;
  healthCheck(): Promise<boolean>;
}
