import type { BaseSecurityDecorator } from './base.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- TS mixin pattern requires any[]
type AnyConstructor = new (...args: any[]) => BaseSecurityDecorator;

export function AccessControl<T extends AnyConstructor>(Base: T) {
  return class extends Base {
    requireIp(whitelist?: string[], blacklist?: string[]) {
      return <F extends Function>(fn: F): F => {
        const rc = this.ensureRouteConfig(fn);
        if (whitelist) rc.ipWhitelist = whitelist;
        if (blacklist) rc.ipBlacklist = blacklist;
        return this.applyRouteConfig(fn);
      };
    }

    blockCountries(countries: string[]) {
      return <F extends Function>(fn: F): F => {
        const rc = this.ensureRouteConfig(fn);
        rc.blockedCountries = countries;
        return this.applyRouteConfig(fn);
      };
    }

    allowCountries(countries: string[]) {
      return <F extends Function>(fn: F): F => {
        const rc = this.ensureRouteConfig(fn);
        rc.whitelistCountries = countries;
        return this.applyRouteConfig(fn);
      };
    }

    blockClouds(providers?: string[]) {
      return <F extends Function>(fn: F): F => {
        const rc = this.ensureRouteConfig(fn);
        rc.blockCloudProviders = new Set(providers ?? ['AWS', 'GCP', 'Azure']);
        return this.applyRouteConfig(fn);
      };
    }

    bypass(checks: string[]) {
      return <F extends Function>(fn: F): F => {
        const rc = this.ensureRouteConfig(fn);
        for (const check of checks) rc.bypassedChecks.add(check);
        return this.applyRouteConfig(fn);
      };
    }
  };
}
