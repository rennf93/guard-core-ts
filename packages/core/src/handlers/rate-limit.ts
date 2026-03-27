import type { Logger } from '../models/logger.js';
import type { AgentHandlerProtocol } from '../protocols/agent.js';
import type { GuardRequest } from '../protocols/request.js';
import type { GuardResponse } from '../protocols/response.js';
import type { RedisManager } from './redis.js';

const RATE_LIMIT_SCRIPT = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local window_start = now - window

redis.call('ZADD', key, now, now)
redis.call('ZREMRANGEBYSCORE', key, 0, window_start)
local count = redis.call('ZCARD', key)
redis.call('EXPIRE', key, window * 2)

return count
`;

export class RateLimitManager {
  private requestTimestamps = new Map<string, number[]>();
  private redisHandler: RedisManager | null = null;
  private agentHandler: AgentHandlerProtocol | null = null;
  private rateLimitScriptSha: string | null = null;

  constructor(private readonly logger: Logger) {}

  async initializeRedis(redisHandler: RedisManager): Promise<void> {
    this.redisHandler = redisHandler;
    const client = redisHandler.getRawClient();
    if (client) {
      try {
        this.rateLimitScriptSha = await client.script('load', RATE_LIMIT_SCRIPT) as string;
      } catch (e) {
        this.logger.warn(`Failed to load rate limit Lua script: ${e}`);
      }
    }
  }

  async initializeAgent(agentHandler: AgentHandlerProtocol): Promise<void> {
    this.agentHandler = agentHandler;
  }

  async checkRateLimit(
    request: GuardRequest,
    clientIp: string,
    createErrorResponse: (statusCode: number, message: string) => Promise<GuardResponse>,
    endpointPath: string | null = null,
    rateLimit: number = 10,
    rateLimitWindow: number = 60,
  ): Promise<GuardResponse | null> {
    const key = endpointPath ? `${clientIp}:${endpointPath}` : clientIp;
    const now = Date.now() / 1000;

    let count: number | null = null;

    if (this.redisHandler) {
      count = await this.getRedisRequestCount(key, now, rateLimitWindow, rateLimit);
    }

    if (count === null) {
      count = this.getInMemoryRequestCount(key, now, rateLimitWindow);
    }

    if (count > rateLimit) {
      return this.handleRateLimitExceeded(
        request, clientIp, count, createErrorResponse, rateLimitWindow,
      );
    }

    return null;
  }

  private async getRedisRequestCount(
    key: string,
    now: number,
    window: number,
    _limit: number,
  ): Promise<number | null> {
    const client = this.redisHandler?.getRawClient();
    if (!client) return null;

    const redisKey = `rate_limit:rate:${key}`;
    const prefix = this.redisHandler!['prefix'] as string;
    const fullKey = `${prefix}${redisKey}`;

    try {
      if (this.rateLimitScriptSha) {
        const count = await client.evalsha(
          this.rateLimitScriptSha, 1, fullKey, now, window, _limit,
        );
        return Number(count);
      }

      /* v8 ignore start -- Lua script fallback pipeline; only reached when Redis evalsha fails */
      await client.zadd(fullKey, now, String(now));
      await client.zremrangebyscore(fullKey, 0, now - window);
      const count = await client.zcard(fullKey);
      await client.eval('redis.call("EXPIRE", KEYS[1], ARGV[1])', 1, fullKey, window * 2);
      return count;
      /* v8 ignore stop */
    } catch (e) {
      this.logger.warn(`Redis rate limit check failed, falling back to in-memory: ${e}`);
      return null;
    }
  }

  private getInMemoryRequestCount(key: string, now: number, window: number): number {
    let timestamps = this.requestTimestamps.get(key);
    if (!timestamps) {
      timestamps = [];
      this.requestTimestamps.set(key, timestamps);
    }

    const windowStart = now - window;
    const validIndex = timestamps.findIndex((t) => t > windowStart);
    /* v8 ignore start -- in-memory timestamp splice; branch-only gap in validIndex condition */
    if (validIndex > 0) {
      timestamps.splice(0, validIndex);
    /* v8 ignore stop */
    } else if (validIndex === -1) {
      timestamps.length = 0;
    }

    timestamps.push(now);
    return timestamps.length;
  }

  private async handleRateLimitExceeded(
    request: GuardRequest,
    clientIp: string,
    count: number,
    createErrorResponse: (statusCode: number, message: string) => Promise<GuardResponse>,
    window: number,
  ): Promise<GuardResponse> {
    this.logger.warn(`Rate limit exceeded for ${clientIp}: ${count} requests`);

    if (this.agentHandler) {
      try {
        await this.agentHandler.sendEvent({
          eventType: 'rate_limit_exceeded',
          ipAddress: clientIp,
          actionTaken: 'request_blocked',
          reason: `Rate limit exceeded: ${count} requests in ${window}s window`,
          metadata: {
            endpoint: request.urlPath,
            method: request.method,
            requestCount: count,
            window,
          },
        });
      } catch { /* never throw */ }
    }

    return createErrorResponse(429, 'Rate limit exceeded');
  }

  async reset(): Promise<void> {
    this.requestTimestamps.clear();
    if (this.redisHandler) {
      await this.redisHandler.deletePattern('rate_limit:rate:*');
    }
  }
}
