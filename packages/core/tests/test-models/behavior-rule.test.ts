import { describe, it, expect } from 'vitest';
import { BehaviorRule } from '../../src/models/behavior-rule.js';

describe('BehaviorRule', () => {
  it('creates with required params and defaults', () => {
    const rule = new BehaviorRule('usage', 10);

    expect(rule.ruleType).toBe('usage');
    expect(rule.threshold).toBe(10);
    expect(rule.window).toBe(3600);
    expect(rule.pattern).toBeNull();
    expect(rule.action).toBe('log');
    expect(rule.customAction).toBeNull();
  });

  it('creates with all params', () => {
    const customFn = () => {};
    const rule = new BehaviorRule('return_pattern', 5, 86400, 'status:200', 'ban', customFn);

    expect(rule.ruleType).toBe('return_pattern');
    expect(rule.threshold).toBe(5);
    expect(rule.window).toBe(86400);
    expect(rule.pattern).toBe('status:200');
    expect(rule.action).toBe('ban');
    expect(rule.customAction).toBe(customFn);
  });

  it('supports frequency rule type', () => {
    const rule = new BehaviorRule('frequency', 100, 300, null, 'throttle');
    expect(rule.ruleType).toBe('frequency');
    expect(rule.action).toBe('throttle');
  });

  it('supports alert action', () => {
    const rule = new BehaviorRule('usage', 50, 600, null, 'alert');
    expect(rule.action).toBe('alert');
  });
});
