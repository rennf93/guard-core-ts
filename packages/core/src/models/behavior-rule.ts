export type BehaviorRuleType = 'usage' | 'return_pattern' | 'frequency';
export type BehaviorAction = 'ban' | 'log' | 'throttle' | 'alert';

export class BehaviorRule {
  readonly ruleType: BehaviorRuleType;
  readonly threshold: number;
  readonly window: number;
  readonly pattern: string | null;
  readonly action: BehaviorAction;
  readonly customAction: ((...args: unknown[]) => unknown) | null;

  constructor(
    ruleType: BehaviorRuleType,
    threshold: number,
    window = 3600,
    pattern: string | null = null,
    action: BehaviorAction = 'log',
    customAction: ((...args: unknown[]) => unknown) | null = null,
  ) {
    this.ruleType = ruleType;
    this.threshold = threshold;
    this.window = window;
    this.pattern = pattern;
    this.action = action;
    this.customAction = customAction;
  }
}
