import type { Logger } from '../models/logger.js';
import type { AgentHandlerProtocol } from '../protocols/agent.js';
import type { RedisManager } from './redis.js';

interface BanEntry {
  expiresAt: number;
  reason: string;
  bannedAt: number;
}

export class IPBanManager {
  private bannedIps = new Map<string, BanEntry>();
  private redisHandler: RedisManager | null = null;
  private agentHandler: AgentHandlerProtocol | null = null;
  private readonly maxSize = 10000;

  constructor(private readonly logger: Logger) {}

  async initializeRedis(redisHandler: RedisManager): Promise<void> {
    this.redisHandler = redisHandler;
  }

  async initializeAgent(agentHandler: AgentHandlerProtocol): Promise<void> {
    this.agentHandler = agentHandler;
  }

  async banIp(ip: string, duration: number, reason: string): Promise<void> {
    const now = Date.now() / 1000;
    const expiresAt = now + duration;

    if (this.bannedIps.size >= this.maxSize) {
      const oldestKey = this.bannedIps.keys().next().value;
      if (oldestKey) this.bannedIps.delete(oldestKey);
    }

    this.bannedIps.set(ip, { expiresAt, reason, bannedAt: now });

    if (this.redisHandler) {
      await this.redisHandler.setKey('banned_ips', ip, String(expiresAt), duration);
    }

    if (this.agentHandler) {
      try {
        await this.agentHandler.sendEvent({
          eventType: 'ip_banned',
          ipAddress: ip,
          actionTaken: 'ip_banned',
          reason,
          metadata: { duration, expiresAt },
        });
      } catch { /* never throw from event dispatch */ }
    }

    this.logger.info(`IP banned: ${ip} for ${duration}s - ${reason}`);
  }

  async isIpBanned(ip: string): Promise<boolean> {
    const now = Date.now() / 1000;

    const entry = this.bannedIps.get(ip);
    if (entry) {
      if (now <= entry.expiresAt) return true;
      this.bannedIps.delete(ip);
    }

    if (this.redisHandler) {
      const expiryStr = await this.redisHandler.getKey('banned_ips', ip);
      if (typeof expiryStr === 'string') {
        const expiresAt = parseFloat(expiryStr);
        if (now <= expiresAt) {
          this.bannedIps.set(ip, {
            expiresAt,
            reason: 'restored_from_redis',
            bannedAt: now,
          });
          return true;
        }
        await this.redisHandler.delete('banned_ips', ip);
      }
    }

    return false;
  }

  async unbanIp(ip: string): Promise<void> {
    this.bannedIps.delete(ip);

    if (this.redisHandler) {
      await this.redisHandler.delete('banned_ips', ip);
    }

    if (this.agentHandler) {
      try {
        await this.agentHandler.sendEvent({
          eventType: 'ip_unbanned',
          ipAddress: ip,
          actionTaken: 'ip_unbanned',
          reason: 'Manual unban',
        });
      } catch { /* never throw */ }
    }

    this.logger.info(`IP unbanned: ${ip}`);
  }

  async reset(): Promise<void> {
    this.bannedIps.clear();
    if (this.redisHandler) {
      await this.redisHandler.deletePattern('banned_ips:*');
    }
  }
}
