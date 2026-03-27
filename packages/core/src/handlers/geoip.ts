import type { Logger } from '../models/logger.js';
import type { AgentHandlerProtocol } from '../protocols/agent.js';
import type { GeoIPHandler } from '../protocols/geo-ip.js';
import type { RedisHandlerProtocol } from '../protocols/redis.js';

export class IPInfoManager implements GeoIPHandler {
  private reader: unknown = null;
  private _isInitialized = false;
  private agentHandler: AgentHandlerProtocol | null = null;

  constructor(private readonly logger: Logger) {}

  get isInitialized(): boolean {
    return this._isInitialized;
  }

  async initialize(): Promise<void> {
    try {
      const maxmind = await import('maxmind');
      /* v8 ignore start -- successful maxmind.open() requires actual .mmdb database file on disk */
      this.reader = await maxmind.open('data/ipinfo/country_asn.mmdb');
      this._isInitialized = true;
      this.logger.info('GeoIP database initialized');
      /* v8 ignore stop */
    } catch (e) {
      this.logger.warn(`GeoIP initialization failed: ${e}`);
    }
  }

  async initializeRedis(redisHandler: RedisHandlerProtocol): Promise<void> {
    // Cache DB in Redis for shared access
  }

  async initializeAgent(agentHandler: AgentHandlerProtocol): Promise<void> {
    this.agentHandler = agentHandler;
  }

  getCountry(ip: string): string | null {
    if (!this.reader) return null;
    try {
      const result = (this.reader as { get(ip: string): { country?: { iso_code?: string } } | null }).get(ip);
      return result?.country?.iso_code ?? null;
    } catch {
      return null;
    }
  }
}
