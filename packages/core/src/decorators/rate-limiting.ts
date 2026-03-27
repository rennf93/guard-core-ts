import type { BaseSecurityDecorator } from './base.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- TS mixin pattern requires any[]
type AnyConstructor = new (...args: any[]) => BaseSecurityDecorator;

export function RateLimiting<T extends AnyConstructor>(Base: T) {
  return class extends Base {
    rateLimit(requests: number, window = 60) {
      return <F extends Function>(fn: F): F => {
        const rc = this.ensureRouteConfig(fn);
        rc.rateLimit = requests;
        rc.rateLimitWindow = window;
        return this.applyRouteConfig(fn);
      };
    }

    geoRateLimit(limits: Record<string, [number, number]>) {
      return <F extends Function>(fn: F): F => {
        const rc = this.ensureRouteConfig(fn);
        rc.geoRateLimits = limits;
        return this.applyRouteConfig(fn);
      };
    }
  };
}
