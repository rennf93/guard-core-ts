/**
 * Registry-truth test for the 4.0.3 binary-body noise gate, ported from
 * guard-core tests/test_sus_patterns/test_pattern_binary_noise_gate.py
 * (upstream commit 436d6f72, test_noise_prone_registry_is_truthful).
 *
 * With the density gate disabled, every pattern in the frozen noise-prone
 * registry must actually fire on at least one random binary noise view. If a
 * registry entry stopped matching entirely, the gate would be hiding real
 * detection capability rather than binary-body false positives.
 */

import { describe, it, expect, vi } from 'vitest';
import { SusPatternsManager } from '../../src/handlers/sus-patterns.js';
import { NOISE_PRONE_PATTERN_SOURCES } from '../../src/detection-engine/patterns/pattern-table.js';
import { createTestConfig } from '../helpers.js';
import { defaultLogger } from '../../src/models/logger.js';

vi.mock('../../src/detection-engine/binary.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/detection-engine/binary.js')>();
  return { ...actual, matchIsBinaryDensity: () => false };
});

const MULTIPART_FIELD_CONTEXT = 'request_body:multipart_field';
const NOISE_SEEDS = [1, 2, 3, 42, 1337];
const NOISE_SIZE = 262144;

function latin1Decode(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += String.fromCharCode(b);
  return out;
}

function utf8DecodeSurrogateescape(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  const isCont = (b: number | undefined): b is number => b !== undefined && b >= 0x80 && b <= 0xbf;
  while (i < bytes.length) {
    const b0 = bytes[i] as number;
    if (b0 < 0x80) {
      out += String.fromCharCode(b0);
      i += 1;
    } else if (b0 >= 0xc2 && b0 <= 0xdf && isCont(bytes[i + 1])) {
      out += String.fromCharCode(((b0 & 0x1f) << 6) | ((bytes[i + 1] as number) & 0x3f));
      i += 2;
    } else if (
      b0 >= 0xe0 &&
      b0 <= 0xef &&
      isCont(bytes[i + 1]) &&
      isCont(bytes[i + 2]) &&
      !(b0 === 0xe0 && (bytes[i + 1] as number) < 0xa0) &&
      !(b0 === 0xed && (bytes[i + 1] as number) >= 0xa0)
    ) {
      out += String.fromCharCode(
        ((b0 & 0x0f) << 12) | (((bytes[i + 1] as number) & 0x3f) << 6) | ((bytes[i + 2] as number) & 0x3f),
      );
      i += 3;
    } else {
      out += String.fromCharCode(0xdc00 + b0);
      i += 1;
    }
  }
  return out;
}

function noiseBytes(seed: number): Uint8Array {
  let state = seed >>> 0;
  const bytes = new Uint8Array(NOISE_SIZE);
  for (let i = 0; i < NOISE_SIZE; i++) {
    state = (state + 0x6d2b79f5) | 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    bytes[i] = ((t ^ (t >>> 14)) & 0xff) as number;
  }
  return bytes;
}

describe('binary noise gate registry truth (gate disabled)', () => {
  it('every noise-prone pattern fires on random binary noise with the gate disabled', async () => {
    const manager = new SusPatternsManager(
      createTestConfig({
        detectionCompilerTimeout: 2.0,
        detectionMaxContentLength: 10000,
        detectionPreserveAttackPatterns: true,
        detectionSemanticThreshold: 0.7,
        detectionAnomalyThreshold: 3.0,
        detectionSlowPatternThreshold: 0.1,
        detectionMonitorHistorySize: 1000,
        detectionMaxTrackedPatterns: 1000,
      }),
      defaultLogger,
    );
    const matchedSources = new Set<string>();
    for (const seed of NOISE_SEEDS) {
      for (const decode of [latin1Decode, utf8DecodeSurrogateescape]) {
        const result = await manager.detect(decode(noiseBytes(seed)), '127.0.0.1', MULTIPART_FIELD_CONTEXT);
        for (const threat of result.threats) {
          if (threat.detectionMethod === 'regex') {
            matchedSources.add(threat.pattern);
          }
        }
      }
    }
    const missing = [...NOISE_PRONE_PATTERN_SOURCES].filter((source) => !matchedSources.has(source));
    expect(missing).toEqual([]);
  });
});
