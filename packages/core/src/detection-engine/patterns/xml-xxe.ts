/**
 * XML/XXE structural matchers ported from
 * guard_core/handlers/_suspatterns_xml_xxe.py (spec 4.0.2).
 */

import { compilePythonPattern, matchSpan } from '../regex-compat.js';
import type { CompiledPythonPattern, RegexMatchLike } from './types.js';

const XML_XXE_DOCTYPE = compilePythonPattern('<!DOCTYPE', true);
const XML_XXE_PUBLIC = compilePythonPattern('PUBLIC', true);
const XML_XXE_SCHEME = compilePythonPattern('https?://', true);
const XML_XXE_W3_ORG = compilePythonPattern('(?:www\\.)?w3\\.org/', true);
const XML_XXE_CLASS12_BOUNDARY = compilePythonPattern('[>\\[]');
const XML_XXE_CLASS3_BOUNDARY = compilePythonPattern('["\'>]');
const XML_SYSTEM_PREFIX = compilePythonPattern('<!(?:ENTITY|DOCTYPE)', true);
const XML_SYSTEM_KEYWORD = compilePythonPattern('SYSTEM', true);
const XML_ENTITY_PREFIX = compilePythonPattern('<!ENTITY', true);
const XML_GT = compilePythonPattern('>');

const XML_XXE_VALIDATED_SPAN_SOURCE = '[\\s\\S]*';
const XML_XXE_VALIDATED_SPAN = compilePythonPattern(XML_XXE_VALIDATED_SPAN_SOURCE);

function findAll(compiled: CompiledPythonPattern, text: string, end = text.length): RegExpExecArray[] {
  const matches: RegExpExecArray[] = [];
  const global = new RegExp(compiled.re.source, compiled.re.flags.replace('y', 'g'));
  const sliced = text.slice(0, end);
  let match: RegExpExecArray | null;
  while ((match = global.exec(sliced)) !== null) {
    matches.push(match);
    if (match[0].length === 0) global.lastIndex++;
  }
  return matches;
}

function firstAtOrAfter(sortedPositions: number[], floor: number): number | null {
  let lo = 0;
  let hi = sortedPositions.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if ((sortedPositions[mid] ?? 0) < floor) lo = mid + 1;
    else hi = mid;
  }
  return lo < sortedPositions.length ? (sortedPositions[lo] ?? null) : null;
}

function validatedMatch(text: string, start: number, end: number): RegexMatchLike {
  const match = matchSpan(XML_XXE_VALIDATED_SPAN, text, start, end);
  if (match === null) {
    throw new Error('xml validated span invariant violated');
  }
  return match;
}

export function _xml_system_finditer(text: string): RegexMatchLike[] {
  const ends = findAll(XML_GT, text).map((m) => m.index);
  const matches: RegexMatchLike[] = [];
  let lastEnd = 0;
  for (const prefix of findAll(XML_SYSTEM_PREFIX, text)) {
    const prefixStart = prefix.index;
    const prefixEnd = prefix.index + prefix[0].length;
    if (prefixStart < lastEnd) continue;
    const end = firstAtOrAfter(ends, prefixEnd);
    if (end === null) return matches;
    lastEnd = end + 1;
    const keyword = searchBetween(XML_SYSTEM_KEYWORD, text, prefixEnd + 1, end - 1);
    if (keyword !== null) {
      matches.push(validatedMatch(text, prefixStart, lastEnd));
    }
  }
  return matches;
}

function searchBetween(
  compiled: CompiledPythonPattern,
  text: string,
  start: number,
  end: number,
): RegExpExecArray | null {
  if (start >= end) return null;
  const global = new RegExp(compiled.re.source, compiled.re.flags.replace('y', 'g'));
  const sliced = text.slice(0, end);
  global.lastIndex = start;
  return global.exec(sliced);
}

export function _xml_internal_entity_finditer(text: string): RegexMatchLike[] {
  const boundaries = findAll(XML_XXE_CLASS12_BOUNDARY, text).map((m) => m.index);
  const entities = findAll(XML_ENTITY_PREFIX, text).map((m) => m.index);
  const matches: RegexMatchLike[] = [];
  let lastEnd = 0;
  for (const prefix of findAll(XML_XXE_DOCTYPE, text)) {
    const prefixStart = prefix.index;
    const prefixEnd = prefix.index + prefix[0].length;
    if (prefixStart < lastEnd) continue;
    const boundary = firstAtOrAfter(boundaries, prefixEnd);
    if (boundary === null) return matches;
    lastEnd = boundary + 1;
    if (text[boundary] !== '[') continue;
    const entity = firstAtOrAfter(entities, boundary + 1);
    if (entity === null) return matches;
    lastEnd = entity + '<!ENTITY'.length;
    matches.push(validatedMatch(text, prefixStart, lastEnd));
  }
  return matches;
}

function xmlXxeSchemeCompletionEnd(
  text: string,
  schemeStart: number,
  class12Boundaries: number[],
  class3Boundaries: number[],
): number | null {
  if (schemeStart === 0 || !'"\''.includes(text[schemeStart - 1] ?? '')) return null;
  const sticky = XML_XXE_SCHEME.re;
  sticky.lastIndex = schemeStart;
  const schemeMatch = sticky.exec(text);
  if (schemeMatch === null || schemeMatch.index !== schemeStart) return null;
  const schemeEnd = schemeMatch.index + schemeMatch[0].length;
  const w3 = XML_XXE_W3_ORG.re;
  w3.lastIndex = schemeEnd;
  if (w3.exec(text) !== null) return null;
  return xmlXxeQuotedUrlEnd(text, schemeEnd, class12Boundaries, class3Boundaries);
}

function xmlXxeQuotedUrlEnd(
  text: string,
  schemeEnd: number,
  class12Boundaries: number[],
  class3Boundaries: number[],
): number | null {
  const quote2 = firstAtOrAfter(class3Boundaries, schemeEnd);
  if (quote2 === null) return null;
  if (quote2 === schemeEnd || text[quote2] === '>') return null;
  const finalBoundary = firstAtOrAfter(class12Boundaries, quote2 + 1);
  if (finalBoundary === null) return null;
  return text[finalBoundary] === '>' ? finalBoundary : null;
}

function xmlXxeValidQuoteCompletions(
  text: string,
  class12Boundaries: number[],
  class3Boundaries: number[],
): { quotePositions: number[]; quoteToFinalGt: Map<number, number> } {
  const quotePositions: number[] = [];
  const quoteToFinalGt = new Map<number, number>();
  for (const schemeMatch of findAll(XML_XXE_SCHEME, text)) {
    const finalGt = xmlXxeSchemeCompletionEnd(text, schemeMatch.index, class12Boundaries, class3Boundaries);
    if (finalGt !== null) {
      const quotePos = schemeMatch.index - 1;
      quotePositions.push(quotePos);
      quoteToFinalGt.set(quotePos, finalGt);
    }
  }
  return { quotePositions, quoteToFinalGt };
}

function xmlXxePublicRunBounds(class12Boundaries: number[], publicPos: number, textLen: number): [number, number] {
  let runIdx = 0;
  while (runIdx < class12Boundaries.length && (class12Boundaries[runIdx] ?? 0) <= publicPos) runIdx++;
  const runStart = runIdx > 0 ? (class12Boundaries[runIdx - 1] ?? 0) + 1 : 0;
  const runEnd = runIdx < class12Boundaries.length ? (class12Boundaries[runIdx] as number) : textLen;
  return [runStart, runEnd];
}

interface XxeSpan {
  doctypeBefore: number;
  finalGt: number;
}

function xmlXxeCandidateSpan(
  doctypePositions: number[],
  quotePositions: number[],
  quoteToFinalGt: Map<number, number>,
  class12Boundaries: number[],
  publicPos: number,
  textLen: number,
): XxeSpan | null {
  const [runStart, runEnd] = xmlXxePublicRunBounds(class12Boundaries, publicPos, textLen);
  const doctypeBefore = firstAtOrAfter(doctypePositions, runStart);
  if (doctypeBefore === null || doctypeBefore >= publicPos - 9) return null;
  const quote1 = firstAtOrAfter(quotePositions, publicPos + 7);
  if (quote1 === null || quote1 >= runEnd) return null;
  const finalGt = quoteToFinalGt.get(quote1);
  if (finalGt === undefined) return null;
  return { doctypeBefore, finalGt };
}

export function _xml_xxe_public_external_dtd_finditer(text: string): RegexMatchLike[] {
  const doctypePositions = findAll(XML_XXE_DOCTYPE, text).map((m) => m.index);
  const publicPositions = findAll(XML_XXE_PUBLIC, text).map((m) => m.index);
  if (doctypePositions.length === 0 || publicPositions.length === 0) return [];
  const class12Boundaries = findAll(XML_XXE_CLASS12_BOUNDARY, text).map((m) => m.index);
  const class3Boundaries = findAll(XML_XXE_CLASS3_BOUNDARY, text).map((m) => m.index);
  const { quotePositions, quoteToFinalGt } = xmlXxeValidQuoteCompletions(text, class12Boundaries, class3Boundaries);
  if (quotePositions.length === 0) return [];

  const matches: RegexMatchLike[] = [];
  let lastEnd = 0;
  for (const publicPos of publicPositions) {
    if (publicPos < lastEnd) continue;
    const span = xmlXxeCandidateSpan(
      doctypePositions,
      quotePositions,
      quoteToFinalGt,
      class12Boundaries,
      publicPos,
      text.length,
    );
    if (span === null) continue;
    const match = validatedMatch(text, span.doctypeBefore, span.finalGt + 1);
    matches.push(match);
    lastEnd = match.index + match[0].length;
  }
  return matches;
}
