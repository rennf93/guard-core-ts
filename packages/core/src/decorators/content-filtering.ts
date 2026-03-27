import type { GuardRequest } from '../protocols/request.js';
import type { GuardResponse } from '../protocols/response.js';
import type { BaseSecurityDecorator } from './base.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- TS mixin pattern requires any[]
type AnyConstructor = new (...args: any[]) => BaseSecurityDecorator;

export function ContentFiltering<T extends AnyConstructor>(Base: T) {
  return class extends Base {
    blockUserAgents(patterns: string[]) {
      return <F extends Function>(fn: F): F => {
        const rc = this.ensureRouteConfig(fn);
        rc.blockedUserAgents.push(...patterns);
        return this.applyRouteConfig(fn);
      };
    }

    contentTypeFilter(allowedTypes: string[]) {
      return <F extends Function>(fn: F): F => {
        const rc = this.ensureRouteConfig(fn);
        rc.allowedContentTypes = allowedTypes;
        return this.applyRouteConfig(fn);
      };
    }

    maxRequestSize(sizeBytes: number) {
      return <F extends Function>(fn: F): F => {
        const rc = this.ensureRouteConfig(fn);
        rc.maxRequestSize = sizeBytes;
        return this.applyRouteConfig(fn);
      };
    }

    requireReferrer(allowedDomains: string[]) {
      return <F extends Function>(fn: F): F => {
        const rc = this.ensureRouteConfig(fn);
        rc.requireReferrer = allowedDomains;
        return this.applyRouteConfig(fn);
      };
    }

    customValidation(validator: (request: GuardRequest) => Promise<GuardResponse | null>) {
      return <F extends Function>(fn: F): F => {
        const rc = this.ensureRouteConfig(fn);
        rc.customValidators.push(validator);
        return this.applyRouteConfig(fn);
      };
    }
  };
}
