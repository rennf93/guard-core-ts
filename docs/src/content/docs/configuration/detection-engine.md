---
title: "Detection Engine"
description: "PatternCompiler, ContentPreprocessor, SemanticAnalyzer, PerformanceMonitor, and tuning knobs"
---

The detection engine is a four-stage pipeline that analyzes request content for attack patterns. It combines regex matching, content normalization, semantic analysis, and performance monitoring.

## Architecture

```
Content → ContentPreprocessor → PatternCompiler → SemanticAnalyzer → PerformanceMonitor → DetectionResult
```

## PatternCompiler

Compiles and caches regex patterns with ReDoS protection.

**Primary engine**: `re2-wasm` -- a WebAssembly port of Google's RE2 that guarantees linear-time matching. Works in Node.js and edge runtimes (Cloudflare Workers, Deno).

**Fallback chain**:
1. `re2-wasm` (linear time, ReDoS-safe)
2. `worker_threads` timeout wrapper (native RegExp in a worker with configurable timeout)
3. Native `RegExp` (last resort, no timeout protection)

```typescript
import { PatternCompiler } from '@guardcore/core';

const compiler = new PatternCompiler(2000, 1000);

const result = await compiler.safeMatch(
  String.raw`<script[^>]*>[^<]*<\/script\s*>`,
  userInput,
);

if (result) {
  console.log('XSS pattern matched:', result[0]);
}
```

**Pattern safety validation**:

```typescript
const [isSafe, message] = compiler.validatePatternSafety(
  '(a+)+$',
);
// isSafe: false
// message: "Pattern contains dangerous construct: (.*)+""
```

The validator checks for catastrophic backtracking patterns like `(.*)+`, `(.+)+`, nested quantifiers, and measures actual execution time against test strings.

**Cache**: LRU cache of compiled patterns, configurable max size (default 1000, max 5000).

## ContentPreprocessor

Normalizes input before pattern matching to defeat encoding-based bypasses.

**Processing pipeline**:
1. **Unicode normalization** (NFKC) + lookalike character replacement (e.g., `\u2044` -> `/`, `\uff1c` -> `<`)
2. **Encoding decoding** -- up to 3 iterations of URL decoding + HTML entity decoding
3. **Null byte removal** + control character stripping
4. **Whitespace normalization**
5. **Safe truncation** -- preserves attack-containing regions when truncating long content

```typescript
import { ContentPreprocessor } from '@guardcore/core';

const preprocessor = new ContentPreprocessor(10000, true);

const normalized = await preprocessor.preprocess(
  '%3Cscript%3Ealert%281%29%3C%2Fscript%3E',
);
// "<script>alert(1)</script>"
```

**Attack-preserving truncation**: When content exceeds `maxContentLength`, the preprocessor extracts regions containing attack indicators (e.g., `<script`, `../`, `eval(`) and prioritizes keeping those in the truncated output.

## SemanticAnalyzer

Analyzes content semantically to catch attacks that bypass regex patterns.

**Analysis produces**:

| Metric | Description |
|--------|-------------|
| `attackProbabilities` | Per-category scores (xss, sql, command, path, template) from 0 to 1 |
| `entropy` | Shannon entropy of the content (high entropy suggests obfuscation) |
| `encodingLayers` | Count of detected encoding types (URL, base64, hex, unicode, HTML entities) |
| `isObfuscated` | Boolean based on entropy > 4.5, encoding layers > 2, special char ratio > 0.4, or 100+ consecutive non-space characters |
| `codeInjectionRisk` | Score from 0 to 1 based on code structure patterns and AST parsing (via `acorn`) |
| `suspiciousPatterns` | Array of detected structural patterns (tags, function calls, command chains, path traversal, URLs) |
| `tokenCount` | Number of extracted tokens |

```typescript
import { SemanticAnalyzer } from '@guardcore/core';

const analyzer = new SemanticAnalyzer();
const analysis = analyzer.analyze(userInput);
const threatScore = analyzer.getThreatScore(analysis);

if (threatScore >= 0.7) {
  console.log('Semantic threat detected:', analysis.attackProbabilities);
}
```

**Threat score formula**:
- Max attack probability * 0.3
- Obfuscation detected: +0.2
- Encoding layers: +0.1 per layer (max 0.2)
- Code injection risk * 0.2
- Suspicious patterns: +0.05 per pattern (max 0.1)
- Total capped at 1.0

## PerformanceMonitor

Tracks regex execution times and detects anomalies using z-score analysis.

**What it tracks per pattern**:
- Total executions, matches, and timeouts
- Average, min, and max execution times
- Recent execution time history (sliding window)

**Anomaly detection**:
- **Timeout**: pattern exceeded the configured timeout
- **Slow execution**: execution time > `slowPatternThreshold`
- **Statistical anomaly**: execution time z-score > `anomalyThreshold` (default 3.0)

```typescript
import { PerformanceMonitor } from '@guardcore/core';

const monitor = new PerformanceMonitor(3.0, 0.1, 1000, 1000);

monitor.registerAnomalyCallback((anomaly) => {
  console.log('Pattern anomaly:', anomaly.type, anomaly.pattern);
});
```

## 75 Pattern Categories

The engine ships with 75 built-in patterns across 15 attack categories:

| Category | Patterns | Contexts |
|----------|----------|----------|
| XSS | 8 | query_param, header, request_body |
| SQL Injection | 9 | query_param, request_body |
| Directory Traversal | 5 | url_path, query_param, request_body |
| Command Injection | 5 | query_param, request_body |
| File Inclusion | 2 | url_path, query_param, request_body |
| LDAP Injection | 3 | query_param, request_body |
| XML/XXE | 3 | header, request_body |
| SSRF | 2 | query_param, request_body |
| NoSQL Injection | 2 | query_param, request_body |
| File Upload | 1 | header, request_body |
| Path Traversal (encoded) | 1 | url_path, query_param, request_body |
| Template Injection | 2 | query_param, request_body |
| HTTP Splitting | 1 | header, query_param, request_body |
| Sensitive Files | 5 | url_path, request_body |
| CMS Probing | 4 | url_path, request_body |
| Reconnaissance | 22 | url_path |

Each pattern is only checked against relevant contexts -- a SQL injection pattern is not tested against URL paths, and reconnaissance patterns are not tested against request bodies.

## Tuning Knobs

| Config Field | Default | Effect |
|-------------|---------|--------|
| `detectionCompilerTimeout` | `2.0` | Seconds before regex compilation times out |
| `detectionMaxContentLength` | `10000` | Max characters to scan per request |
| `detectionPreserveAttackPatterns` | `true` | Keep attack regions when truncating |
| `detectionSemanticThreshold` | `0.7` | Minimum semantic score to flag as threat |
| `detectionAnomalyThreshold` | `3.0` | Z-score standard deviations for anomaly |
| `detectionSlowPatternThreshold` | `0.1` | Seconds before a pattern is "slow" |
| `detectionMonitorHistorySize` | `1000` | Metrics history buffer size |
| `detectionMaxTrackedPatterns` | `1000` | Max patterns tracked by monitor |

**Lowering `detectionSemanticThreshold`** catches more attacks but increases false positives.
**Raising `detectionMaxContentLength`** scans more of large request bodies but increases CPU time.
**Lowering `detectionCompilerTimeout`** fails faster on complex patterns but may miss legitimate matches.
