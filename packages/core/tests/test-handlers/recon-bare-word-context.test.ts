/**
 * Recon leading-separator rule, ported from guard-core
 * tests/test_sus_patterns/test_recon_bare_word_context.py (upstream #115/#116,
 * merged as commit 08f79d67).
 *
 * The whole-value recon rows whose leading "/" is optional must only count as
 * probes where the scanned value reads as a URL path (url_path/unknown
 * context) or when the match itself is separator-prefixed; in query/body
 * contexts a bare word such as "default" or "README.md" is an ordinary field
 * value.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { SusPatternsManager } from '../../src/handlers/sus-patterns.js';
import {
  PATTERN_DEFINITIONS,
  RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES,
} from '../../src/detection-engine/patterns/pattern-table.js';
import { _TOP_LEVEL_PATH_PREFIX_RE } from '../../src/detection-engine/patterns/canonical-sources.generated.js';
import { reconPathValueIsProbe } from '../../src/detection-engine/patterns/sources.js';
import { createTestConfig } from '../helpers.js';
import { defaultLogger } from '../../src/models/logger.js';

// Ordinary field values that the whole-value recon rows match when the
// leading "/" is optional: product names, enum values, file names.
const BARE_WORDS = [
  'default',
  'SAP',
  'ise',
  'language',
  'autodiscover',
  'confluence',
  'actuator',
  'cgi-bin',
  'lms/db',
  'README.md',
  'CHANGELOG',
  'Makefile',
  'credentials.json',
  'report.asp',
];

// Separator-prefixed paths stay probes in every field-value context. The
// upstream vector set also contains "\default" (guard-core
// test_recon_bare_word_context.py pins the legacy unconfigured handler for
// that one): in the configured pipeline the LDAP hex-escape decode stage
// rewrites the "\de" byte run, so Python configured mode returns no threat for
// it too and the vector is not applicable to this surface.
const PROBE_PATHS = [
  '/default.asp',
  '/sap',
  '/actuator/health',
  '/cgi-bin/test.cgi',
  '/README.md',
];

// Field-value contexts where a bare word must stay benign. The `:embedded_json`
// suffixed contexts are what the manager uses for JSON leaf values.
const VALUE_CONTEXTS = [
  'query_param',
  'request_body',
  'query_param:embedded_json',
  'request_body:embedded_json',
];

describe('recon bare-word context rule', () => {
  let manager: SusPatternsManager;

  beforeEach(() => {
    manager = new SusPatternsManager(createTestConfig(), defaultLogger);
  });

  const detect = (content: string, context: string) =>
    manager.detect(content, '1.2.3.4', context);

  it('does not flag bare word values in query/body contexts', async () => {
    for (const value of BARE_WORDS) {
      for (const context of VALUE_CONTEXTS) {
        const result = await detect(value, context);
        expect(
          result.threats.map((t) => `${context}:${t.pattern}`),
          `bare word "${value}" in ${context}`,
        ).toEqual([]);
        expect(result.isThreat, `bare word "${value}" in ${context}`).toBe(false);
      }
    }
  });

  it('still flags separator-prefixed probe paths in query/body contexts', async () => {
    for (const value of PROBE_PATHS) {
      for (const context of VALUE_CONTEXTS) {
        const result = await detect(value, context);
        expect(
          result.isThreat,
          `probe path "${value}" in ${context}`,
        ).toBe(true);
        expect(
          result.threats.length,
          `probe path "${value}" in ${context}`,
        ).toBeGreaterThan(0);
      }
    }
  });

  it('still flags a bare word as the url_path', async () => {
    for (const value of ['default', 'sap', 'README.md', 'actuator']) {
      const result = await detect(value, 'url_path');
      expect(result.isThreat, `bare word "${value}" as url_path`).toBe(true);
    }
  });

  it('still flags a bare word in the unknown context', async () => {
    const result = await detect('default', 'unknown');
    expect(result.isThreat).toBe(true);
  });

  it('checks the probe decision on the context before any :suffix', () => {
    expect(reconPathValueIsProbe('default', 'url_path')).toBe(true);
    expect(reconPathValueIsProbe('default', 'unknown')).toBe(true);
    expect(reconPathValueIsProbe('default', 'query_param')).toBe(false);
    expect(reconPathValueIsProbe('default', 'query_param:embedded_json')).toBe(false);
    expect(reconPathValueIsProbe('default', 'request_body:embedded_json')).toBe(false);
    expect(reconPathValueIsProbe('/default', 'query_param:embedded_json')).toBe(true);
    expect(reconPathValueIsProbe('\\default', 'query_param')).toBe(true);
  });
});

describe('recon optional-separator registry derivation', () => {
  it('derives exactly the recon sources with the optional-separator anchor', () => {
    const expected = PATTERN_DEFINITIONS
      .filter((entry) => entry.category === 'recon' && entry.source.startsWith(_TOP_LEVEL_PATH_PREFIX_RE))
      .map((entry) => entry.source);
    expect([...RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES].sort()).toEqual([...new Set(expected)].sort());
  });

  it('holds the 17 optional-separator rows', () => {
    expect(RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES.size).toBe(17);
  });

  it('excludes required-separator recon rows', () => {
    const requiredSeparatorRows = PATTERN_DEFINITIONS
      .filter((entry) => entry.category === 'recon' && entry.source.startsWith('\\A[/\\\\]('))
      .map((entry) => entry.source);
    expect(requiredSeparatorRows.length).toBe(2);
    for (const source of requiredSeparatorRows) {
      expect(RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES.has(source)).toBe(false);
    }
  });

  it('excludes non-anchored and required-separator recon rows', () => {
    for (const entry of PATTERN_DEFINITIONS) {
      if (entry.category !== 'recon') continue;
      const optionalSeparator = entry.source.startsWith(_TOP_LEVEL_PATH_PREFIX_RE);
      expect(
        RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES.has(entry.source),
        entry.source,
      ).toBe(optionalSeparator);
    }
    // The excluded kinds really exist in the table: required-separator rows
    // ("\A[/\\]" without the optional quantifier) and non-anchored rows.
    expect(
      PATTERN_DEFINITIONS.filter(
        (entry) => entry.category === 'recon' && entry.source.startsWith('\\A[/\\\\]('),
      ).length,
    ).toBe(2);
    expect(
      PATTERN_DEFINITIONS.filter(
        (entry) => entry.category === 'recon' && !entry.source.startsWith('\\A'),
      ).length,
    ).toBe(2);
  });
});
