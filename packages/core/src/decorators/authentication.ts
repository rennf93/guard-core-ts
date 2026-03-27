import type { BaseSecurityDecorator } from './base.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- TS mixin pattern requires any[]
type AnyConstructor = new (...args: any[]) => BaseSecurityDecorator;

export function Authentication<T extends AnyConstructor>(Base: T) {
  return class extends Base {
    requireHttps() {
      return <F extends Function>(fn: F): F => {
        const rc = this.ensureRouteConfig(fn);
        rc.requireHttps = true;
        return this.applyRouteConfig(fn);
      };
    }

    requireAuth(type = 'bearer') {
      return <F extends Function>(fn: F): F => {
        const rc = this.ensureRouteConfig(fn);
        rc.authRequired = type;
        return this.applyRouteConfig(fn);
      };
    }

    apiKeyAuth(headerName = 'X-API-Key') {
      return <F extends Function>(fn: F): F => {
        const rc = this.ensureRouteConfig(fn);
        rc.apiKeyRequired = true;
        rc.requiredHeaders[headerName] = '';
        return this.applyRouteConfig(fn);
      };
    }

    requireHeaders(headers: Record<string, string>) {
      return <F extends Function>(fn: F): F => {
        const rc = this.ensureRouteConfig(fn);
        Object.assign(rc.requiredHeaders, headers);
        return this.applyRouteConfig(fn);
      };
    }
  };
}
