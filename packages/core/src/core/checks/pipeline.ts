import type { GuardRequest } from '../../protocols/request.js';
import type { GuardResponse } from '../../protocols/response.js';
import type { Logger } from '../../models/logger.js';
import type { SecurityCheck } from './base.js';

export class SecurityCheckPipeline {
  constructor(
    private checks: SecurityCheck[],
    private readonly logger: Logger,
  ) {}

  async execute(request: GuardRequest): Promise<GuardResponse | null> {
    for (const check of this.checks) {
      try {
        const response = await check.check(request);
        if (response !== null) return response;
      } catch (e) {
        this.logger.error(`Security check '${check.checkName}' failed: ${e}`);
      }
    }
    return null;
  }

  add(check: SecurityCheck): void {
    this.checks.push(check);
  }

  insert(index: number, check: SecurityCheck): void {
    this.checks.splice(index, 0, check);
  }

  remove(name: string): boolean {
    const idx = this.checks.findIndex((c) => c.checkName === name);
    if (idx === -1) return false;
    this.checks.splice(idx, 1);
    return true;
  }

  getCheckNames(): string[] {
    return this.checks.map((c) => c.checkName);
  }

  get length(): number {
    return this.checks.length;
  }
}
