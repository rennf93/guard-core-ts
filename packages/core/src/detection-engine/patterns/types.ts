/** Shared matcher types for the detection pattern port. */

import type { CompiledPythonPattern } from '../regex-compat.js';

export type { CompiledPythonPattern };

/**
 * Stand-in for Python `re.Match`. `input` is the string the pattern ran on
 * (`match.string`), `index` is `match.start()`, and the full match is
 * `match[0]`.
 */
export type RegexMatchLike = RegExpExecArray;

export interface PatternThreat {
  type: string;
  pattern: string;
  match: string;
  position: number;
  category: string;
  weight: number;
}

export type CandidateValidator = (match: RegexMatchLike, context: string) => boolean;
export type WindowedFinder = (text: string) => Iterable<RegexMatchLike>;
export type ScanWindowMatcher = (content: string, compiled: CompiledPythonPattern) => RegexMatchLike[];

export interface PatternDefinition {
  readonly source: string;
  readonly contexts: ReadonlySet<string>;
  readonly category: string;
}
