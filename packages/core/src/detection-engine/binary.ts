/**
 * Binary-content detection ported from
 * guard_core/detection_engine/binary_prefix.py and semantic.py
 * (looks_like_binary_content), spec 4.0.2.
 */

import { isPrintableCodePoint } from './base64-decode.js';

const BINARY_ARTIFACT_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x00, 0x08],
  [0x0b, 0x0b],
  [0x0c, 0x0c],
  [0x0e, 0x1f],
  [0x7f, 0x7f],
  [0x80, 0xa2],
  [0xa4, 0xa4],
  [0xa6, 0xa9],
  [0xab, 0xaf],
  [0xb4, 0xb4],
  [0xb6, 0xb8],
  [0xbb, 0xbf],
  [0x0180, 0x024f],
  [0xfffd, 0xfffd],
  [0xdc80, 0xdcff],
];

function isBinaryArtifact(cp: number): boolean {
  return BINARY_ARTIFACT_RANGES.some(([lo, hi]) => cp >= lo && cp <= hi);
}

/** Cumulative artifact-count prefix: counts[i] = artifacts ending before index i. */
export function buildBinaryPrefix(text: string): number[] {
  const counts = new Array<number>(text.length + 1).fill(0);
  let count = 0;
  let filled = 0;
  for (const ch of text) {
    if (!isBinaryArtifact(ch.codePointAt(0) ?? 0)) continue;
    count++;
    const boundary = filled + ch.length;
    for (let i = filled + 1; i < boundary; i++) counts[i] = count - 1;
    counts[boundary] = count;
    filled = boundary;
  }
  for (let i = filled; i <= text.length; i++) {
    counts[i] = count;
  }
  return counts;
}

const BINARY_DENSITY_RADIUS = 64;
const BINARY_DENSITY_LIMIT = 4;

export function matchIsBinaryDensity(
  binaryPrefix: number[] | null,
  matchStart: number,
  matchEnd: number,
  textLength: number,
): boolean {
  if (binaryPrefix === null) return false;
  const high = Math.min(matchEnd + BINARY_DENSITY_RADIUS, binaryPrefix.length - 1);
  const low = Math.max(matchStart - BINARY_DENSITY_RADIUS, 0);
  return (binaryPrefix[high] ?? 0) - (binaryPrefix[low] ?? 0) >= BINARY_DENSITY_LIMIT;
}

const BINARY_CONTENT_RATIO_THRESHOLD = 0.2;

export function looksLikeBinaryContent(content: string): boolean {
  if (!content) return false;
  let nonTextCount = 0;
  let length = 0;
  for (const ch of content) {
    length++;
    const cp = ch.codePointAt(0) ?? 0;
    const isWhitespace = ch === '\t' || ch === '\r' || ch === '\n';
    if (!isWhitespace && (!isPrintableCodePoint(cp) || cp === 0xfffd)) nonTextCount++;
  }
  return nonTextCount / length >= BINARY_CONTENT_RATIO_THRESHOLD;
}
