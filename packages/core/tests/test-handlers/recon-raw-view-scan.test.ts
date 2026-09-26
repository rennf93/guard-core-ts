/**
 * Recon raw-view membership, ported from guard-core
 * tests/test_sus_patterns/test_recon_raw_view_scan.py (upstream commit
 * 81cf07f1, guard-core PR #121; sibling ports: guard-core-rs #21,
 * guard-core-go #16, guard-core-php #16).
 *
 * The configured pipeline's preprocessor folds LDAP hex escapes (`\de` ->
 * `Þ`) before the pattern tables run, so a recon probe such as `\default`
 * arrives mangled on the processed views, and the recon-category rows were
 * excluded from the raw-view pattern set, so the original input was never
 * scanned against them. The raw view now carries the recon rows too: the
 * original value is scanned against them IN ADDITION to the processed
 * views, with the #116 leading-separator gate applied unchanged (bare words
 * stay innocent outside `url_path`/`unknown`) and a (pattern, match)
 * deduplication on merge so a row matching in both views is counted once.
 *
 * Unlike recon-bare-word-context.test.ts (which pins the raw scan pass),
 * these tests go through the full SusPatternsManager.detect pipeline,
 * because the whole point is that the pipeline's own preprocessor mangles
 * backslash probes on the processed views and only the signal-preserving
 * raw view still carries them.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { SusPatternsManager } from '../../src/handlers/sus-patterns.js';
import type { DetectionResult } from '../../src/handlers/sus-patterns.js';
import { PATTERN_DEFINITIONS, DETECTION_RECON_RAW_VIEW_PATTERN_SOURCES } from '../../src/detection-engine/patterns/pattern-table.js';
import { scanRequestWithManager } from '../../src/utils.js';
import { createTestConfig, createMockRequest } from '../helpers.js';
import { defaultLogger } from '../../src/models/logger.js';
import type { GuardRequest } from '../../src/protocols/request.js';

// The recon source registry is derived from the table itself in the tests so
// the membership assertions stay independent of the implementation export.
const RECON_SOURCES: ReadonlySet<string> = new Set(
  PATTERN_DEFINITIONS.filter((entry) => entry.category === 'recon').map((entry) => entry.source),
);

// Separator-prefixed probes the processed views mangle or gate away: the LDAP
// hex decoder folds "\de" into "Þ", so "\default" arrives as "Þfault" and only
// the raw view still sees the original value.
const BACKSLASH_PROBES = ['\\default', '\\report.asp', '\\README.md'];
const BARE_WORDS = ['default', 'SAP', 'actuator', 'README.md'];

let manager: SusPatternsManager;

beforeEach(() => {
  manager = new SusPatternsManager(createTestConfig(), defaultLogger);
});

async function detect(content: string, context: string): Promise<DetectionResult> {
  return manager.detect(content, '1.2.3.4', context);
}

function reconThreats(result: DetectionResult): Array<{ match: string; pattern: string }> {
  return result.threats
    .filter((threat) => threat.detectionMethod === 'regex' && RECON_SOURCES.has(threat.pattern))
    .map((threat) => ({ match: threat.matchedContent, pattern: threat.pattern }));
}

function bodyRequest(contentType: string, body: string): GuardRequest {
  return createMockRequest({
    method: 'POST',
    headers: { 'content-type': contentType },
    body: async () => new TextEncoder().encode(body),
  });
}

describe('recon raw-view scan (backslash probes through the pipeline)', () => {
  it('detects a backslash probe value in query_param', async () => {
    for (const probe of BACKSLASH_PROBES) {
      const result = await detect(probe, 'query_param');
      expect(reconThreats(result).length, `probe "${probe}" in query_param`).toBeGreaterThan(0);
      expect(result.isThreat, `probe "${probe}" in query_param`).toBe(true);
    }
  });

  it('detects a backslash probe value in request_body', async () => {
    for (const probe of BACKSLASH_PROBES) {
      const result = await detect(probe, 'request_body');
      expect(reconThreats(result).length, `probe "${probe}" in request_body`).toBeGreaterThan(0);
      expect(result.isThreat, `probe "${probe}" in request_body`).toBe(true);
    }
  });

  it('detects a backslash probe in a urlencoded form field through the body scan', async () => {
    for (const probe of BACKSLASH_PROBES) {
      const request = bodyRequest('application/x-www-form-urlencoded', `system=${encodeURIComponent(probe)}`);
      const [isThreat, info] = await scanRequestWithManager(manager, request);
      expect(isThreat, `probe "${probe}" in form field`).toBe(true);
      expect(info, `probe "${probe}" in form field`).toContain("Request body field 'system':");
    }
  });

  it('detects a backslash probe in a JSON body leaf through the body scan', async () => {
    for (const probe of BACKSLASH_PROBES) {
      const request = bodyRequest('application/json', JSON.stringify({ system: probe }));
      const [isThreat, info] = await scanRequestWithManager(manager, request);
      expect(isThreat, `probe "${probe}" in json body`).toBe(true);
      expect(info, `probe "${probe}" in json body`).toContain("Request body field 'system':");
    }
  });

  it('detects a backslash probe as the url_path value', async () => {
    // The #116 reference semantics: a backslash-prefixed probe is recon as a
    // URL path value; the raw view must not lose it to the hex decoder.
    const result = await detect('\\default', 'url_path');
    expect(reconThreats(result).length).toBeGreaterThan(0);
    expect(result.isThreat).toBe(true);
  });

  it('keeps case folding intact on raw-view matches', async () => {
    const result = await detect('\\SAP', 'query_param');
    expect(reconThreats(result).length).toBeGreaterThan(0);
  });
});

describe('recon raw-view scan (bare words stay innocent)', () => {
  it('does not flag bare word values in query/body contexts', async () => {
    for (const word of BARE_WORDS) {
      for (const context of ['query_param', 'request_body']) {
        const result = await detect(word, context);
        expect(result.threats, `bare word "${word}" in ${context}`).toEqual([]);
        expect(result.isThreat, `bare word "${word}" in ${context}`).toBe(false);
      }
    }
  });

  it('keeps a bare word innocent through the request surfaces', async () => {
    for (const word of BARE_WORDS) {
      const queryRequest = createMockRequest({ queryParams: { system: word } });
      expect(await scanRequestWithManager(manager, queryRequest), `query bare "${word}"`).toEqual([false, '']);
      const formRequest = bodyRequest('application/x-www-form-urlencoded', `system=${word}`);
      expect(await scanRequestWithManager(manager, formRequest), `form bare "${word}"`).toEqual([false, '']);
      const jsonRequest = bodyRequest('application/json', JSON.stringify({ system: word }));
      expect(await scanRequestWithManager(manager, jsonRequest), `json bare "${word}"`).toEqual([false, '']);
    }
  });
});

describe('recon raw-view scan (embedded JSON leaves)', () => {
  it('follows the probe gate on the :embedded_json leaf contexts', async () => {
    for (const context of ['query_param:embedded_json', 'request_body:embedded_json']) {
      const probe = await detect('\\default', context);
      expect(reconThreats(probe).length, `probe in ${context}`).toBeGreaterThan(0);
      const bare = await detect('default', context);
      expect(bare.threats, `bare word in ${context}`).toEqual([]);
    }
  });

  it('follows the probe gate through the query param embedded-JSON routing', async () => {
    // The #68 routing: a query param value that parses to an object has its
    // leaves scanned under the :embedded_json context.
    const probeRequest = createMockRequest({ queryParams: { v: JSON.stringify({ system: '\\default' }) } });
    const [probeHit, probeInfo] = await scanRequestWithManager(manager, probeRequest);
    expect(probeHit).toBe(true);
    expect(probeInfo).toContain("Request body field 'system':");

    const bareRequest = createMockRequest({ queryParams: { v: JSON.stringify({ system: 'default' }) } });
    expect(await scanRequestWithManager(manager, bareRequest)).toEqual([false, '']);
  });
});

describe('recon raw-view scan (view merge semantics)', () => {
  it('counts a row matching both views once', async () => {
    // `\report.asp` survives preprocessing intact: the processed views and
    // the raw view both match it, and the raw-view merge must not
    // double-count it.
    const result = await detect('\\report.asp', 'query_param');
    const recon = reconThreats(result);
    expect(recon.length).toBe(1);
    expect(recon[0]?.match).toBe('\\report.asp');
    expect(result.isThreat).toBe(true);
  });

  it('keeps the decoded single-hit semantics for the hex-encoded separator', async () => {
    // `\2fdefault` decodes to `/default` on the processed views; the raw view
    // does not match it, and the decoded sighting stays a single recon hit.
    const result = await detect('\\2fdefault', 'query_param');
    const recon = reconThreats(result);
    expect(recon.length).toBe(1);
    expect(recon[0]?.match).toBe('/default');
  });

  it('keeps the two-row reference multiset for both separator forms', async () => {
    // Both separator forms hit the default-page row and the extension row,
    // exactly the threat multiset the reference produces.
    for (const value of ['/default.asp', '\\default.asp']) {
      const result = await detect(value, 'query_param');
      const recon = reconThreats(result);
      expect(recon.length, `multiset drift for "${value}"`).toBe(2);
      for (const threat of recon) {
        expect(threat.match, `match texts drifted for "${value}"`).toBe(value);
      }
    }
  });

  it('stays clean when no view yields a probe shape', async () => {
    // `/\default` is not a probe shape on any view: the leading slash already
    // satisfies the path prefix, so the row cannot rematch on `\default`.
    const slashBackslash = await detect('/\\default', 'url_path');
    expect(slashBackslash.isThreat).toBe(false);
    expect(slashBackslash.threats).toEqual([]);

    // `\de\ad\be\ef` folds to non-ASCII text on the processed views and is
    // not a probe on the raw view either; folding must not create a hit.
    const folded = await detect('\\de\\ad\\be\\ef', 'query_param');
    expect(folded.isThreat).toBe(false);
    expect(folded.threats).toEqual([]);
  });
});

describe('recon raw-view registry derivation', () => {
  it('derives exactly the recon rows of the pattern table', () => {
    const expected = PATTERN_DEFINITIONS
      .filter((entry) => entry.category === 'recon')
      .map((entry) => entry.source);
    expect(expected.length).toBe(21);
    expect(new Set(expected).size).toBe(expected.length);
    expect([...DETECTION_RECON_RAW_VIEW_PATTERN_SOURCES].sort()).toEqual([...new Set(expected)].sort());
  });

  it('includes the optional-separator and required-separator recon rows alike', () => {
    for (const entry of PATTERN_DEFINITIONS) {
      if (entry.category !== 'recon') continue;
      expect(DETECTION_RECON_RAW_VIEW_PATTERN_SOURCES.has(entry.source), entry.source).toBe(true);
    }
    // Non-recon rows never join the raw-view recon set.
    for (const entry of PATTERN_DEFINITIONS) {
      if (entry.category === 'recon') continue;
      expect(DETECTION_RECON_RAW_VIEW_PATTERN_SOURCES.has(entry.source), entry.source).toBe(false);
    }
  });
});
