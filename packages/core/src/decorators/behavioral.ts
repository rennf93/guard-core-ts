import { BehaviorRule } from '../models/behavior-rule.js';
import type { BehaviorAction } from '../models/behavior-rule.js';
import type { BaseSecurityDecorator } from './base.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- TS mixin pattern requires any[]
type AnyConstructor = new (...args: any[]) => BaseSecurityDecorator;

export function Behavioral<T extends AnyConstructor>(Base: T) {
  return class extends Base {
    usageMonitor(maxCalls: number, window = 3600, action: BehaviorAction = 'ban') {
      return <F extends Function>(fn: F): F => {
        const rc = this.ensureRouteConfig(fn);
        rc.behaviorRules.push(new BehaviorRule('usage', maxCalls, window, null, action));
        return this.applyRouteConfig(fn);
      };
    }

    returnMonitor(pattern: string, maxOccurrences: number, window = 86400, action: BehaviorAction = 'ban') {
      return <F extends Function>(fn: F): F => {
        const rc = this.ensureRouteConfig(fn);
        rc.behaviorRules.push(new BehaviorRule('return_pattern', maxOccurrences, window, pattern, action));
        return this.applyRouteConfig(fn);
      };
    }

    behaviorAnalysis(rules: BehaviorRule[]) {
      return <F extends Function>(fn: F): F => {
        const rc = this.ensureRouteConfig(fn);
        rc.behaviorRules.push(...rules);
        return this.applyRouteConfig(fn);
      };
    }

    suspiciousFrequency(maxFrequency: number, window = 300, action: BehaviorAction = 'ban') {
      return <F extends Function>(fn: F): F => {
        const rc = this.ensureRouteConfig(fn);
        rc.behaviorRules.push(new BehaviorRule('frequency', maxFrequency, window, null, action));
        return this.applyRouteConfig(fn);
      };
    }
  };
}
