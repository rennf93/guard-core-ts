/**
 * Shell-adjacent compiled helpers ported from
 * guard_core/handlers/_suspatterns_shell_sources.py (spec 4.0.2). Source
 * strings come from canonical-sources.generated.ts.
 */

import { compilePythonPattern } from '../regex-compat.js';
import {
  _GLUED_BACKTICK_CANDIDATE_RE,
  _GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE,
  _QUOTE_SPLICE_CANDIDATE_RE,
  _BACKTICK_WINDOW_DELIMITER_CHARS,
  _BARE_SHELL_PARAMETER_NAME_COMPILED,
} from './canonical-sources.generated.js';

export {
  _GLUED_BACKTICK_CANDIDATE_RE,
  _GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE,
  _QUOTE_SPLICE_CANDIDATE_RE,
  _BACKTICK_WINDOW_DELIMITER_CHARS,
  _BRACE_EXPANSION_ITEM_RE,
  _BRACE_EXPANSION_COMMAND_RE,
  _GLOB_WILDCARD_ATOM_RE,
  _PY_DANGEROUS_MODULE_RE,
  _PY_DANGEROUS_METHOD_RE,
  _PY_GETATTR_INDIRECTION_RE,
  _PY_VARS_INDIRECTION_RE,
} from './canonical-sources.generated.js';

export const _GLUED_BACKTICK_ASCII_WORD_RE = /[A-Za-z0-9_]/;

export const _STRONG_SQL_KEYWORD_GLUED_PREFIX_RE = compilePythonPattern(
  '\\b(?:SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|JOIN|VALUES|ORDER\\s+BY|GROUP\\s+BY)\\Z',
  true,
);
export const _STRONG_SQL_KEYWORD_GLUED_SUFFIX_RE = compilePythonPattern(
  '\\A(?:SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|JOIN|VALUES|ORDER\\s+BY|GROUP\\s+BY)\\b',
  true,
);

export const _BACKTICK_WINDOW_DELIMITER_RE = /[`'"\n\r]/;

export const _IMPLAUSIBLE_SQL_IDENTIFIER_CHARS_RE = /[\s/.;|&$()]/;
export const _IMPLAUSIBLE_DOLLAR_PAREN_TOKEN_CHARS_RE = /[/.;|&$()]/;
export const _BARE_SHELL_PARAMETER_NAME_RE = _BARE_SHELL_PARAMETER_NAME_COMPILED;

export const _SHELL_SPECIAL_PARAMETER_NAMES: ReadonlySet<string> = new Set(['ifs']);
export const _AMBIGUOUS_BACKTICK_INJECTION_CONTEXTS: ReadonlySet<string> = new Set(['query_param', 'url_path']);
export const _CTX_CMD_INJECTION_WITH_URL_PATH: ReadonlySet<string> = new Set([
  'query_param',
  'header',
  'url_path',
  'request_body',
  'unknown',
]);
export const _CTX_LOG4SHELL: ReadonlySet<string> = new Set([
  'query_param',
  'header',
  'request_body',
  'url_path',
  'unknown',
]);

export const _QUOTE_SPLICE_CANDIDATE_COMPILED_RE = compilePythonPattern(_QUOTE_SPLICE_CANDIDATE_RE, true);

export const _GLOB_WILDCARD_PATH_RUN_RE = /[\w./*?-]+/g;
export const _GLOB_WILDCARD_CHAR_RE = /[?*]/;

export const _SHELL_CHAIN_OPERATOR_RE = /;|\|\||\||&&/g;

export { _BARE_SHELL_PARAMETER_NAME_COMPILED };
