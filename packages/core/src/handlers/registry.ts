import type { IPBanManager } from './ip-ban.js';
import type { RateLimitManager } from './rate-limit.js';
import type { RedisManager } from './redis.js';

export interface HandlerRegistry {
  redisHandler: RedisManager | null;
  ipBanHandler: IPBanManager;
  rateLimitHandler: RateLimitManager;
}
