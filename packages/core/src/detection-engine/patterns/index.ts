/**
 * Detection wiring: compiles the canonical pattern table and dispatches
 * each pattern to the same structural matcher, windowed finder, candidate
 * validator and scan-window bounds as the guard-core spec 4.0.2 reference
 * (guard_core/handlers/_suspatterns_regex.py).
 */

import { compilePythonPattern } from '../regex-compat.js';
import { bounded_finditer } from '../scan-window.js';
import type { CandidateValidator, CompiledPythonPattern, PatternThreat, RegexMatchLike, ScanWindowMatcher, WindowedFinder } from './types.js';
import { PATTERN_DEFINITIONS, DETECTION_PATTERN_WEIGHT_OVERRIDES, NOISE_PRONE_PATTERN_SOURCES } from './pattern-table.js';
import { matchIsBinaryDensity } from '../binary.js';
import {
  _CMD_INJECTION_DOLLAR_SUBSTITUTION_RE,
  _SQLI_LOAD_FILE_RE,
  _TEMPLATE_ASP_KEYWORD_RE,
  _TEMPLATE_CURLY_CALL_RE,
  _TEMPLATE_CURLY_KEYWORD_RE,
  _TEMPLATE_DOLLAR_BRACE_CALL_RE,
  _TEMPLATE_PERCENT_KEYWORD_RE,
  _brace_expansion_is_dangerous_command,
  _cmd_injection_dollar_scan_matches,
  _cmd_injection_shell_dash_c_finditer,
  _ldap_null_byte_attr_finditer,
  _load_file_scan_matches,
  _pickle_global_generic_finditer,
  _quote_splice_finditer,
  _template_asp_keyword_scan_matches,
  _template_curly_call_scan_matches,
  _template_curly_keyword_scan_matches,
  _template_dollar_brace_scan_matches,
  _template_hash_brace_scan_matches,
  _template_percent_keyword_scan_matches,
} from './matchers.js';
import {
  _FILE_UPLOAD_DANGEROUS_EXTENSION_RE,
  _FILE_UPLOAD_DECODED_TRUNCATION_RE,
  _FILE_UPLOAD_DOUBLE_EXTENSION_RE,
  _FILE_UPLOAD_TRUNCATION_RE,
  _file_upload_scan_matches,
} from './file-upload.js';
import {
  _BRACE_EXPANSION_COMMAND_RE,
  _GLUED_BACKTICK_CANDIDATE_RE,
  _GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE,
  _GLOB_WILDCARD_ATOM_RE,
  _GLOB_WILDCARD_PATH_RUN_RE,
  _QUOTE_SPLICE_CANDIDATE_RE,
} from './shell-sources.js';
import {
  _glued_backtick_pair_is_injection,
  _dollar_substitution_pair_is_injection,
  _glob_wildcard_token_is_dangerous_command,
  _quote_splice_token_is_dangerous_command,
} from './shell-validators.js';
import {
  _LEGACY_IPV4_HOST_RE,
  _legacy_ipv4_match_is_blocked,
  _ldap_paren_conjunction_is_injection,
  _ldap_wildcard_chain_is_injection,
} from './ldap-ipv4.js';
import {
  _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE,
  _DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE,
  _LDAP_NULL_BYTE_ATTR_RE,
  _LDAP_NULL_BYTE_DECODED_ATTR_RE,
  _LDAP_PAREN_BREAKOUT_RE,
  _LDAP_PAREN_CONJUNCTION_RE,
  _LDAP_WILDCARD_CHAIN_RE,
  _LDAP_WILDCARD_EQUALS_RE,
  _SENSITIVE_SOURCE_EXTENSION_PATH_RE,
  _SSTI_HASH_BRACE_SHAPE_RE,
  _XML_XXE_PUBLIC_EXTERNAL_DTD_RE,
  _source_extension_path_is_probe,
} from './sources.js';
import { _pickle_global_candidate_is_injection } from './pickle.js';
import { _xml_internal_entity_finditer, _xml_system_finditer, _xml_xxe_public_external_dtd_finditer } from './xml-xxe.js';
import type { TableEntry } from './pattern-table.js';

export interface CompiledTableEntry {
  readonly source: string;
  readonly re: CompiledPythonPattern;
  readonly contexts: ReadonlySet<string>;
  readonly category: string;
}

let compiledTable: readonly CompiledTableEntry[] | null = null;

function compileOnce(entry: TableEntry): CompiledTableEntry {
  // The deserialization sources embed `(?-i:...)` wrappers and must stay
  // case-sensitive; every other builtin compiles with the reference's
  // re.IGNORECASE builtin flag.
  const ignoreCase = !entry.source.includes('(?-i:');
  return {
    source: entry.source,
    re: compilePythonPattern(entry.source, ignoreCase),
    contexts: entry.contexts,
    category: entry.category,
  };
}

export function getCompiledPatterns(): readonly CompiledTableEntry[] {
  if (compiledTable === null) {
    compiledTable = PATTERN_DEFINITIONS.map(compileOnce);
  }
  return compiledTable;
}

export function resolvePatternWeight(patternSource: string, category: string): number {
  const override = DETECTION_PATTERN_WEIGHT_OVERRIDES[patternSource];
  if (override !== undefined) return override;
  return 1.0;
}

// ---------------------------------------------------------------------------
// Candidate rejection validators (reference order)
// ---------------------------------------------------------------------------

const CANDIDATE_REJECTION_VALIDATORS: ReadonlyArray<readonly [string, CandidateValidator]> = [
  [_LEGACY_IPV4_HOST_RE, (match) => _legacy_ipv4_match_is_blocked(match)],
  [_LDAP_WILDCARD_CHAIN_RE, (match) => _ldap_wildcard_chain_is_injection(match, _LDAP_WILDCARD_CHAIN_RE)],
  [_LDAP_WILDCARD_EQUALS_RE, (match) => _ldap_wildcard_chain_is_injection(match, _LDAP_WILDCARD_EQUALS_RE)],
  [_LDAP_PAREN_BREAKOUT_RE, (match) => _ldap_wildcard_chain_is_injection(match, _LDAP_PAREN_BREAKOUT_RE)],
  [_LDAP_PAREN_CONJUNCTION_RE, (match) => _ldap_paren_conjunction_is_injection(match, _LDAP_PAREN_CONJUNCTION_RE)],
  [_GLUED_BACKTICK_CANDIDATE_RE, (match, context) => _glued_backtick_pair_is_injection(match, context)],
  [_SENSITIVE_SOURCE_EXTENSION_PATH_RE, (_match, context) => _source_extension_path_is_probe(context)],
  [_GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE, (match, context) => _dollar_substitution_pair_is_injection(match, context)],
  [_BRACE_EXPANSION_COMMAND_RE, (match) => _brace_expansion_is_dangerous_command(match)],
  [_QUOTE_SPLICE_CANDIDATE_RE, (match) => _quote_splice_token_is_dangerous_command(match)],
  [_GLOB_WILDCARD_ATOM_RE, (match, context) => _glob_wildcard_token_is_dangerous_command(match, context)],
  [_DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE, (match, context) => _pickle_global_candidate_is_injection(match, context)],
];

const VALIDATOR_BY_SOURCE = new Map<string, CandidateValidator>(CANDIDATE_REJECTION_VALIDATORS);

export function validatorFor(source: string): CandidateValidator | undefined {
  return VALIDATOR_BY_SOURCE.get(source);
}

// ---------------------------------------------------------------------------
// Windowed finders
// ---------------------------------------------------------------------------

const WINDOWED_PATTERN_FINDERS: ReadonlyArray<readonly [string, WindowedFinder]> = [
  [_CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE, (text) => _cmd_injection_shell_dash_c_finditer(text)],
  [_LDAP_NULL_BYTE_ATTR_RE, (text) => _ldap_null_byte_attr_finditer(text, compilePythonPattern(_LDAP_NULL_BYTE_ATTR_RE, true))],
  [
    _LDAP_NULL_BYTE_DECODED_ATTR_RE,
    (text) => _ldap_null_byte_attr_finditer(text, compilePythonPattern(_LDAP_NULL_BYTE_DECODED_ATTR_RE, true)),
  ],
  [_QUOTE_SPLICE_CANDIDATE_RE, (text) => _quote_splice_finditer(text)],
  [_DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE, (text) => _pickle_global_generic_finditer(text)],
  [_XML_XXE_PUBLIC_EXTERNAL_DTD_RE, (text) => _xml_xxe_public_external_dtd_finditer(text)],
];

const WINDOWED_FINDER_BY_SOURCE = new Map<string, WindowedFinder>(WINDOWED_PATTERN_FINDERS);

export function windowedFinderFor(source: string): WindowedFinder | undefined {
  return WINDOWED_FINDER_BY_SOURCE.get(source);
}

// ---------------------------------------------------------------------------
// Dedicated scan-window matchers
// ---------------------------------------------------------------------------

const PATTERN_SCAN_WINDOW_MATCHERS: ReadonlyArray<readonly [string, ScanWindowMatcher]> = [
  [_SQLI_LOAD_FILE_RE, (content, compiled) => _load_file_scan_matches(content, compiled)],
  [_CMD_INJECTION_DOLLAR_SUBSTITUTION_RE, (content, compiled) => _cmd_injection_dollar_scan_matches(content, compiled)],
  [_FILE_UPLOAD_DANGEROUS_EXTENSION_RE, (content, compiled) => _file_upload_scan_matches(content, compiled)],
  [_FILE_UPLOAD_DOUBLE_EXTENSION_RE, (content, compiled) => _file_upload_scan_matches(content, compiled)],
  [_FILE_UPLOAD_TRUNCATION_RE, (content, compiled) => _file_upload_scan_matches(content, compiled)],
  [_FILE_UPLOAD_DECODED_TRUNCATION_RE, (content, compiled) => _file_upload_scan_matches(content, compiled)],
  [_TEMPLATE_CURLY_KEYWORD_RE, (content, compiled) => _template_curly_keyword_scan_matches(content, compiled)],
  [_TEMPLATE_DOLLAR_BRACE_CALL_RE, (content, compiled) => _template_dollar_brace_scan_matches(content, compiled)],
  [_TEMPLATE_CURLY_CALL_RE, (content, compiled) => _template_curly_call_scan_matches(content, compiled)],
  [_TEMPLATE_PERCENT_KEYWORD_RE, (content, compiled) => _template_percent_keyword_scan_matches(content, compiled)],
  [_TEMPLATE_ASP_KEYWORD_RE, (content, compiled) => _template_asp_keyword_scan_matches(content, compiled)],
  [_SSTI_HASH_BRACE_SHAPE_RE, (content, compiled) => _template_hash_brace_scan_matches(content, compiled)],
  [_GLOB_WILDCARD_ATOM_RE, globWildcardScanMatches],
];

const SCAN_MATCHER_BY_SOURCE = new Map<string, ScanWindowMatcher>(PATTERN_SCAN_WINDOW_MATCHERS);

export function scanMatcherFor(source: string): ScanWindowMatcher | undefined {
  return SCAN_MATCHER_BY_SOURCE.get(source);
}

function globWildcardScanMatches(content: string, compiled: CompiledPythonPattern): RegexMatchLike[] {
  const matches: RegexMatchLike[] = [];
  const global = new RegExp(_GLOB_WILDCARD_PATH_RUN_RE.source, _GLOB_WILDCARD_PATH_RUN_RE.flags);
  let run: RegExpExecArray | null;
  while ((run = global.exec(content)) !== null) {
    const runStart = run.index;
    const runEnd = runStart + run[0].length;
    if (!/[?*]/.test(run[0])) continue;
    // Python: compiled.match(content, run_start, run_end); the atom cannot
    // overshoot the run because the run bounds its own shape.
    const re = compiled.re;
    re.lastIndex = runStart;
    const match = re.exec(content);
    if (match !== null && match.index === runStart && match.index + match[0].length <= runEnd) {
      matches.push(match);
    }
  }
  return matches;
}

// ---------------------------------------------------------------------------
// Generic bounded scan windows (prefix + terminator pairs)
// ---------------------------------------------------------------------------

type ScanWindowBounds = ReadonlyArray<readonly [CompiledPythonPattern, CompiledPythonPattern]>;

function bounds(...pairs: Array<[string, string]>): ScanWindowBounds {
  return pairs.map(([prefix, terminator]) => [compilePythonPattern(prefix, true), compilePythonPattern(terminator, true)]);
}

const SCAN_WINDOW_BOUND_SOURCES: ReadonlyArray<readonly [string, ScanWindowBounds]> = [
  ['<script[^>]*>[^<]*<\\/script\\s*>', bounds(['<script', '<\\/script\\s*>'])],
  [
    '(?:<[A-Za-z/][^<>]*style\\s*=\\s{0,20}["\']?[^<>"\']*(?:expression|behavior|url)\\s*\\([^)]*\\))',
    bounds(['<[A-Za-z/][^<>]*style\\s*=', '\\)']),
  ],
  ['(?:<object[^>]*>[\\s\\S]*<\\/object\\s*>)', bounds(['<object', '<\\/object\\s*>'])],
  ['(?:<embed[^>]*>[\\s\\S]*<\\/embed\\s*>)', bounds(['<embed', '<\\/embed\\s*>'])],
  ['(?:<applet[^>]*>[\\s\\S]*<\\/applet\\s*>)', bounds(['<applet', '<\\/applet\\s*>'])],
  ['\\.\\.;[^/\\\\]*[/\\\\]', bounds(['\\.\\.;', '[/\\\\]'])],
  [
    '=(?:https?|ftp):\\/\\/[^\\s\'"<>]+\\/[^\\s\'"<>\\/]*\\.(?:phtml|php[3-5]?|phar|jsp|aspx?|pl|py|txt|inc)(?![a-zA-Z0-9])',
    bounds([
      '=(?:https?|ftp):\\/\\/',
      '\\.(?:phtml|php\\d*|phar|jsp|aspx?|pl|py|txt|inc)[a-zA-Z0-9]*',
    ]),
  ],
  ['<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>', bounds(['<!(?:ENTITY|DOCTYPE)', '>'])],
  ['(?:<!\\[CDATA\\[.*?\\]\\]>)', bounds(['<!\\[CDATA\\[', '\\]\\]>'])],
  ['<!DOCTYPE[^>\\[]*\\[[\\s\\S]*?<!ENTITY', bounds(['<!DOCTYPE', '<!ENTITY'])],
];

const BOUNDS_BY_SOURCE = new Map<string, ScanWindowBounds>(SCAN_WINDOW_BOUND_SOURCES);

export function scanWindowBoundsFor(source: string): ScanWindowBounds | undefined {
  return BOUNDS_BY_SOURCE.get(source);
}

export function iterScanWindowMatches(
  content: string,
  compiled: CompiledPythonPattern,
  boundsPairs: ScanWindowBounds,
): RegexMatchLike[] {
  if (compiled.source === '<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>') {
    return _xml_system_finditer(content);
  }
  if (compiled.source === '<!DOCTYPE[^>\\[]*\\[[\\s\\S]*?<!ENTITY') {
    return _xml_internal_entity_finditer(content);
  }
  const matches: RegexMatchLike[] = [];
  for (const [prefix, terminator] of boundsPairs) {
    matches.push(...bounded_finditer(content, compiled, prefix, terminator));
  }
  return matches;
}

// ---------------------------------------------------------------------------
// Threat building
// ---------------------------------------------------------------------------

export function buildRegexThreat(
  compiled: CompiledPythonPattern,
  match: RegexMatchLike,
  category: string,
  context: string,
  binaryPrefix: number[] | null = null,
): PatternThreat | null {
  const validator = validatorFor(compiled.source);
  if (validator !== undefined && !validator(match, context)) return null;
  if (NOISE_PRONE_PATTERN_SOURCES.has(compiled.source) && binaryPrefix !== null) {
    const matchEnd = match.index + match[0].length;
    if (matchIsBinaryDensity(binaryPrefix, match.index, matchEnd, match.input.length)) return null;
  }
  return {
    type: 'regex',
    pattern: compiled.source,
    match: match[0],
    position: match.index,
    category,
    weight: resolvePatternWeight(compiled.source, category),
  };
}

export function firstAcceptedRegexThreat(
  matches: Iterable<RegexMatchLike>,
  compiled: CompiledPythonPattern,
  category: string,
  context: string,
  binaryPrefix: number[] | null = null,
): PatternThreat | null {
  for (const match of matches) {
    const threat = buildRegexThreat(compiled, match, category, context, binaryPrefix);
    if (threat !== null) return threat;
  }
  return null;
}

export { bounded_finditer };
