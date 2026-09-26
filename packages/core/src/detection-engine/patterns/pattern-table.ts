/**
/**
 * Canonical detection pattern table, generated from the guard-core spec
 * 4.0.2 reference (guard_core/handlers/_suspatterns_pattern_table.py).
 * The `source` strings are carried verbatim on threats and compared by the
 * conformance corpus; regenerate via the reference when the spec moves.
 */

import { _TOP_LEVEL_PATH_PREFIX_RE } from './canonical-sources.generated.js';

export interface TableEntry {
  readonly source: string;
  readonly contexts: ReadonlySet<string>;
  readonly category: string;
}

export const PATTERN_DEFINITIONS: readonly TableEntry[] = [
  { source: "<script[^>]*>[^<]*<\\/script\\s*>", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "xss" },
  { source: "javascript:\\s*[^\\s]+", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "xss" },
  { source: "j[\\t\\r\\n]*a[\\t\\r\\n]*v[\\t\\r\\n]*a[\\t\\r\\n]*s[\\t\\r\\n]*c[\\t\\r\\n]*r[\\t\\r\\n]*i[\\t\\r\\n]*p[\\t\\r\\n]*t[\\t\\r\\n]*:\\s*[^\\s]+", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "xss" },
  { source: "(?:<[A-Za-z/](?:[^<>]*[^<>\\s/])?(?<!=)(?<!=\\\")(?<!=')[\\s/]+(?:onwebkitplaybacktargetavailabilitychanged|oncontentvisibilityautostatechange|onwebkitpresentationmodechanged|onwebkitmouseforcewillbegin|onwebkitanimationiteration|onsecuritypolicyviolation|onwebkitmouseforcechanged|onvalidationstatuschange|onwebkitfullscreenchange|onwebkitwillrevealbottom|onwebkitanimationstart|onwebkitmouseforcedown|onbeforescriptexecute|onmozfullscreenchange|onwebkittransitionend|onafterscriptexecute|onanimationiteration|onlostpointercapture|onscrollsnapchanging|onunhandledrejection|onwebkitanimationend|onwebkitmouseforceup|ondeviceorientation|ongotpointercapture|onbeforedeactivate|onfullscreenchange|onpointerrawupdate|onreadystatechange|onrejectionhandled|onscrollsnapchange|ontransitioncancel|onanimationcancel|onbeforeeditfocus|oncontextrestored|ondatasetcomplete|onselectionchange|ontransitionstart|onanimationstart|onbeforeactivate|oncanplaythrough|ondatasetchanged|ondurationchange|onlanguagechange|onlayoutcomplete|onloadedmetadata|onpropertychange|oncontrolselect|ondataavailable|ongesturechange|onmediacomplete|onpointercancel|onpromptdismiss|ontransitionend|ontransitionrun|onwebkitneedkey|onanimationend|onbeforetoggle|onbeforeunload|onbeforeupdate|ondevicemotion|onfilterchange|ongesturestart|onmessageerror|onpointerenter|onpointerleave|onpromptaction|onsyncrestored|onvolumechange|onafterupdate|onbeforeinput|onbeforematch|onbeforepaste|onbeforeprint|oncontextlost|oncontextmenu|onerrorupdate|onlosecapture|onpointerdown|onpointermove|onpointerover|onresizestart|onrowinserted|onselectstart|ontouchcancel|ontrackchange|onafterprint|onbeforecopy|oncellchange|ondeactivate|ongestureend|onhashchange|onloadeddata|onmediaerror|onmouseenter|onmouseleave|onmousewheel|onpagereveal|onpointerout|onratechange|onslotchange|ontimeupdate|ontouchstart|onbeforecut|oncuechange|ondragenter|ondragleave|ondragstart|onloadstart|onmousedown|onmousemove|onmouseover|onmovestart|onoutofsync|onpointerup|onresizeend|onrowdelete|onrowsenter|onscrollend|ontimeerror|ontouchmove|onactivate|onauxclick|ondblclick|ondragdrop|ondragexit|ondragover|onfocusout|onformdata|onkeypress|onlocation|onmouseout|onpagehide|onpageshow|onpageswap|onpopstate|onprogress|ontouchend|oncanplay|oncommand|ondragend|onemptied|onfocusin|oninvalid|onkeydown|onmessage|onmouseup|onmoveend|onoffline|onplaying|onreverse|onrowexit|onseeking|onstalled|onstorage|onsuspend|onurlflip|onwaiting|onbounce|oncancel|onchange|onfinish|ononline|onrepeat|onresize|onresume|onscroll|onsearch|onseeked|onselect|onsubmit|ontoggle|onunload|onabort|onbegin|onclick|onclose|onended|onerror|onfocus|oninput|onkeyup|onpaste|onpause|onreset|onstart|onwheel|onblur|oncopy|ondrag|ondrop|onhelp|onload|onmove|onplay|onredo|onseek|onstop|onundo|oncut|onend)\\s*=\\s{0,20}(?:[\\\"'][^\\\"']*[\\\"']|[^\\s>]+))", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "xss" },
  { source: "(?:<[A-Za-z/](?:[^<>]*[^<>\\s])?\\s+(?:href|src|data|action)\\s*=[\\s\\\"\\']*(?:javascript|vbscript|data):)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "xss" },
  { source: "(?:<[A-Za-z/][^<>]*style\\s*=\\s{0,20}[\\\"']?[^<>\\\"']*(?:expression|behavior|url)\\s*\\([^)]*\\))", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "xss" },
  { source: "(?:<object[^>]*>[\\s\\S]*<\\/object\\s*>)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "xss" },
  { source: "(?:<embed[^>]*>[\\s\\S]*<\\/embed\\s*>)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "xss" },
  { source: "(?:<applet[^>]*>[\\s\\S]*<\\/applet\\s*>)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "xss" },
  { source: "(?i)\\bSELECT\\b(?:(?!\\bSELECT\\b)[\\w\\s,\\*().])*?\\bFROM\\b", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "sqli" },
  { source: "(?i)SELECT\\s+\\*", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "sqli" },
  { source: "(?i)\\bWHERE\\s+[\\w.\"]+\\s*(?:=|<|>|<=|>=|LIKE|IN)\\b", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "sqli" },
  { source: "(?i)\\b(?:OR|AND)\\s*(\\d+|'[^']*'|\\\"[^\\\"]*\\\"|[@:$][A-Za-z_]\\w*)\\s*=\\s*\\1\\b", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "sqli" },
  { source: "(?i)UNION\\s+(?:ALL\\s+)?SELECT", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "sqli" },
  { source: "(?i)('\\s*(?:OR|AND)[\\s(]*'?(?:[@:$][A-Za-z_]\\w*|[\\d\\w]+)\\s*(?:LIKE|[<>]=?|=)[\\s(]*'?(?:[@:$][A-Za-z_]\\w*|[\\d\\w]+))", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "sqli" },
  { source: "(?i)(UNION\\s+(?:ALL\\s+)?SELECT\\s+NULL(?:[,\\s]*NULL)*[,\\s]*|\\(\\s*SELECT\\s+(?:@@|VERSION))", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "sqli" },
  { source: "(?i)(?:INTO\\s+(?:OUTFILE|DUMPFILE)\\s+'[^']+')", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "sqli" },
  { source: "(?i)(?:LOAD_FILE\\s*\\([^)]+\\))", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "sqli" },
  { source: "(?i)(?:BENCHMARK\\s*\\(\\s*\\d+\\s*,)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "sqli" },
  { source: "(?i)(?:SLEEP\\s*\\(\\s*\\d+\\s*\\))", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "sqli" },
  { source: "(?i)(?:\\/\\*![0-9]*\\s*(?:OR|AND|UNION|SELECT|INSERT|DELETE|DROP|CONCAT|CHAR|UPDATE)\\b)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "sqli" },
  { source: "\\w/\\*(?!!)[^*]*\\*/\\w", contexts: new Set(["query_param", "request_body", "unknown"]), category: "sqli" },
  { source: "(?i)(?:OR|AND)\\s+(?:'[\\w\\d]*'='[\\w\\d]*'?|[@:$][A-Za-z_]\\w*\\s*=\\s*[@:$][A-Za-z_]\\w*)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "sqli" },
  { source: "(?i);\\s*(?:DROP|TRUNCATE|ALTER|CREATE)\\s+(?:TABLE|DATABASE|SCHEMA)\\b", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "sqli" },
  { source: "(?i);\\s*(?:INSERT\\s+INTO|UPDATE\\s+\\w+\\s+SET|DELETE\\s+FROM|SELECT\\b[^;]*?\\bFROM\\b|REPLACE\\s+INTO)\\b", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "sqli" },
  { source: "(?i)\\bEXEC(?:UTE)?\\s+(?:xp_\\w+|sp_\\w+)", contexts: new Set(["query_param", "request_body", "unknown"]), category: "sqli" },
  { source: "(?i)(?:\\A|[;'\\\"])\\s*EXEC(?:UTE)?\\s+(?:xp_\\w+|sp_\\w+)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "sqli" },
  { source: "(?i)\\bORDER\\s+BY\\s+\\d+\\s*(?:--|#|;|\\)|,|/\\*|\\Z)|(?<=[=?&])ORDER\\s+BY\\s+\\d+\\s*\\n", contexts: new Set(["query_param", "request_body", "unknown"]), category: "sqli" },
  { source: "(?i)(?:['\\\")\\d]|/\\*)\\s{0,3}\\bORDER\\s+BY\\s+\\d+|\\bORDER\\s+BY\\s+\\d+\\s*(?:--|#|/\\*)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "sqli" },
  { source: "'\\s*(?:[\\);]+\\s*)?--|'[\\);]*#(?:\\n|\\Z)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "sqli" },
  { source: "(?i)\\bWAITFOR\\s+(?:DELAY|TIME)\\s+'\\d{1,2}:\\d{1,2}:\\d{1,2}(?:\\.\\d+)?'", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "sqli" },
  { source: "(?:\\.\\.\\/|\\.\\.\\\\)(?:\\.\\.\\/|\\.\\.\\\\)+", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "dir_traversal" },
  { source: "\\A(?:(?!\\n).)*etc/(?:passwd|shadow|group|hosts|motd|issue|mysql/my\\.cnf|ssh/ssh_config)(?:[&#;,\\\"'<>]|\\s*\\Z)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "dir_traversal" },
  { source: "\\A(?=(?:(?!\\n).)*\\b(?:scan(?:ner|ning|ned|s)?|attack(?:er|ers|ed|s)?|attempt(?:ed|s)?|exploit(?:ation|ed|s|ing|kit)?|prob(?:e|ed|es|ing)|malicious|intrusion(?:s)?|botnet(?:s)?|honeypot(?:s)?|brute[- ]force|credential[- ]stuffing|threat feed|vulnerabilit(?:y|ies)|hostile|recon(?:naissance)?|spoofed referer|bad actor(?:s)?|WAF|IDS|SOC|pentest(?:ing)?|blocked|flagged|triggered|denied|enumerat(?:e|ed|ing)|suspicious)\\b)\\A(?:(?!\\n).)*[/\\\\](?:etc/(?:passwd|shadow|group|hosts|motd|issue|mysql/my\\.cnf|ssh/ssh_config))(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?\\b", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "dir_traversal" },
  { source: "\\A(?:(?!\\n).)*(?:boot\\.ini|win\\.ini|system\\.ini|config\\.sys)(?:[&#;,\\\"'<>]|\\s*\\Z)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "dir_traversal" },
  { source: "\\A(?:(?!\\n).)*proc/self/environ(?:[&#;,\\\"'<>]|\\s*\\Z)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "dir_traversal" },
  { source: "\\A(?:(?!\\n).)*var/log/[^\\s/]+(?:[&#;,\\\"'<>]|\\s*\\Z)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "dir_traversal" },
  { source: "\\.\\.;[^/\\\\]*[/\\\\]", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "dir_traversal" },
  { source: ";\\s*(?:ls|cat|rm|chmod|chown|wget|curl|nc|netcat|ping|telnet)\\s+-[a-zA-Z]+\\s+", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "cmd_injection" },
  { source: "\\|\\s*(?:wget|curl|fetch|lwp-download|lynx|links|GET)\\s+", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "cmd_injection" },
  { source: "(?:[;&|]\\s*(?:\\$\\([^)]+\\)|\\$\\{[^}]+\\}))", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "cmd_injection" },
  { source: "\\A\\s*(?:[;&|]\\s*)*`\\s*(?:[A-Za-z0-9_./~]|\\$[({])(?:[^`\\\\\\n]|\\\\.)*(?:\\n\\s*)?`(?:\\s*[;&|]\\s*`\\s*(?:[A-Za-z0-9_./~]|\\$[({])(?:[^`\\\\\\n]|\\\\.)*(?:\\n\\s*)?`)*\\s*(?:[;&|]\\s*)*\\Z", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "cmd_injection" },
  { source: "(?<!`)`(?:[A-Za-z0-9_./~]|\\$[({])(?:[^`\\\\\\n]|\\\\.)*`", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "cmd_injection" },
  { source: "\\$\\((?:[^()\\\\\\n]|\\\\.)*\\)|\\$\\{(?:[^{}\\\\\\n]|\\\\.)*\\}", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "cmd_injection" },
  { source: "(?i)\\$\\{(?:jndi:(?:ldap|rmi|dns)://|\\$?\\{?(?:lower|upper):j\\}ndi|::-j\\}ndi)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "cmd_injection" },
  { source: "(?:\\A|[;|&])\\s*/?(?:[\\w.-]+/)*(?:env\\s+/?(?:[\\w.-]+/)*)?(?:bash|sh|ksh|csh|tsch|zsh|ash)\\s+-[a-zA-Z]+(?:\\s+(?:'[^']*'|\\\"[^\\\"]*\\\"|[^\\s;|&]+))?(?=\\s*(?:[;|&]|\\Z))", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "cmd_injection" },
  { source: "(?:\\A|[;|&])\\s*[^=\\s;|&]+=[^\\s;|&]+\\s+(?:/?(?:[\\w.-]+/)*env\\s+)?/?(?:[\\w.-]+/)*(?:bash|sh|ksh|csh|tsch|zsh|ash)\\s+-[a-zA-Z]+", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "cmd_injection" },
  { source: "\\n[^\\S\\r\\n]*(?:[^=\\s;|&]+=[^\\s;|&]+\\s+)*(?:/?(?:[\\w.-]+/)*env\\s+)?/?(?:[\\w.-]+/)*(?:bash|sh|ksh|csh|tsch|zsh|ash)\\s+-c\\b", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "cmd_injection" },
  { source: "\\b(?:eval|system|exec|shell_exec|passthru|popen|proc_open|create_function)\\s*\\(", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "cmd_injection" },
  { source: "(?:require\\(\\s*[\\\"']child_process[\\\"']\\s*\\)|child_process)\\s*\\.\\s*(?:execSync|spawnSync|spawn|fork)\\s*\\(", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "cmd_injection" },
  { source: "\\bassert\\s*\\(\\s*\\$", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "cmd_injection" },
  { source: "\\bos\\.exec(?:l|le|lp|lpe|v|ve|vp|vpe)\\s*\\(", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "cmd_injection" },
  { source: "\\b(?:new\\s+)?Function\\s*\\(\\s*[\\\"']", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "cmd_injection" },
  { source: "\\[\\s*[\\\"']eval[\\\"']\\s*\\]\\s*\\(\\s*[\\\"']", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "cmd_injection" },
  { source: "(?:\\.\\s*constructor|\\[\\s*[\\\"']constructor[\\\"']\\s*\\])\\s*(?:\\.\\s*constructor|\\[\\s*[\\\"']constructor[\\\"']\\s*\\])\\s*\\(\\s*[\\\"']", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "cmd_injection" },
  { source: "\\b(?:setTimeout|setInterval)\\s*\\(\\s*[\\\"']", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "cmd_injection" },
  { source: "[;|&]\\s*(?:ls|cat|rm|id|whoami|uname|wget|curl|nc|netcat|socat|bash|sh|python|perl)\\b", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "cmd_injection" },
  { source: "(?i)\\b(?:nc|netcat|ncat)\\s+-[a-z]*e\\b|/dev/tcp/\\d", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "cmd_injection" },
  { source: "(?:\\A|[;&|]\\s*|\\$\\()\\{[^{}\\s,:'\\\"][^{},:'\\\"]*(?:,(?:[^{}\\s,:'\\\"][^{},:'\\\"]*)?)+\\}", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "cmd_injection" },
  { source: "\\w+(?:['\\\"]+\\w+){1,10}", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "cmd_injection" },
  { source: "[A-Za-z0-9_./*?-]*[?*][A-Za-z0-9_./*?-]*", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "cmd_injection" },
  { source: "(?:php|data|zip|rar|file|glob|expect|input|phpinfo|zlib|phar|ssh2|rar|ogg|expect)://[^\\s]+", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "file_inclusion" },
  { source: "(?:(?<!:)\\/\\/[0-9a-zA-Z](?:[-\\w]*[0-9a-zA-Z])?(?:\\.[0-9a-zA-Z](?:[-\\w]*[0-9a-zA-Z])?)+(:[0-9]+)?(?:\\/?)(?:[a-zA-Z0-9\\-\\.\\?,'/\\\\\\+&amp;%\\$#_]*)?)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "file_inclusion" },
  { source: "=(?:https?|ftp):\\/\\/[^\\s'\\\"<>]+\\/[^\\s'\\\"<>\\/]*\\.(?:phtml|php[3-5]?|phar|jsp|aspx?|pl|py|txt|inc)(?![a-zA-Z0-9])", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "file_inclusion" },
  { source: "[\\\"'](?:template|include|tpl|module|layout)[\\\"']\\s*:\\s*[\\\"'](?:https?|ftp)://[^\\s'\\\"<>]+/[^\\s'\\\"<>/]*\\.(?:phtml|php[3-5]?|phar|jsp|aspx?|cgi|pl|py|sh|txt|inc)(?![a-zA-Z0-9])[\\\"']", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "file_inclusion" },
  { source: "\\([\\s]*[|&][\\s]*\\([^)(]+=[*]", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "ldap" },
  { source: "\\*\\s*\\)+\\s*(?:[|&!]\\s*)?\\(+\\s*(?:[&|!]|(?::)?(?:[a-zA-Z][\\w.-]*|\\d+(?:\\.\\d+)*)(?:;[\\w.-]+)*(?::[\\w.-]+)*\\s*:?=)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "ldap" },
  { source: "\\)\\s*\\(\\s*(?:[&|!]|(?::)?(?:[a-zA-Z][\\w.-]*|\\d+(?:\\.\\d+)*)(?:;[\\w.-]+)*(?::[\\w.-]+)*\\s*:?[=~<>])", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "ldap" },
  { source: "\\(\\s*[&|]\\s*", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "ldap" },
  { source: "\\*\\)[|&]?\\(+\\s*(?::)?(?:[a-zA-Z][\\w.-]*|\\d+(?:\\.\\d+)*)(?:;[\\w.-]+)*(?::[\\w.-]+)*\\s*:?=", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "ldap" },
  { source: "[a-zA-Z][\\w-]*\\s*=[\\d\\w\\s]*\\*\\)+(?:%00|\\\\u0000|\\\\x00|\\\\0|\\x00)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "ldap" },
  { source: "\\*\\)\\)+(?:%00|\\\\u0000|\\\\x00|\\\\0|\\x00)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "ldap" },
  { source: "[a-zA-Z][\\w-]*\\s*=[\\d\\w\\s]*\\*\\)+\\x00", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "ldap" },
  { source: "\\*\\)\\)+\\x00", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "ldap" },
  { source: "<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "xml" },
  { source: "<!DOCTYPE[^>\\[]+PUBLIC[^>\\[]+[\\\"']https?://(?!(?:www\\.)?w3\\.org/)[^\\\"'>]+[\\\"'][^>\\[]*>", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "xml" },
  { source: "(?:<!\\[CDATA\\[.*?\\]\\]>)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "xml" },
  { source: "<!DOCTYPE[^>\\[]*\\[[\\s\\S]*?<!ENTITY", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "xml" },
  { source: "(?:^|\\s|/)(?:(?<=://)[^\\s/@]*@)?(?:localhost\\.?|127\\.0\\.0\\.1|0\\.0\\.0\\.0|\\[::(?:\\d*)\\]|\\[::ffff:127\\.0\\.0\\.1\\]|169\\.254(?:\\.\\d{1,3}){2}|192\\.168(?:\\.\\d{1,3}){2}|10(?:\\.\\d{1,3}){3}|172\\.(?:1[6-9]|2[0-9]|3[01])(?:\\.\\d{1,3}){2}|metadata\\.google\\.internal|metadata\\.goog|100\\.100\\.100\\.200)(?::\\d+)?(?:\\s|$|/)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "ssrf" },
  { source: "://(?:[^/@\\s]*@)?((?:0[xX][0-9a-fA-F]+|0[0-7]+|[1-9]\\d*|0)(?:\\.(?:0[xX][0-9a-fA-F]+|0[0-7]+|[1-9]\\d*|0)){0,3})(?=[:/\\s]|$)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "ssrf" },
  { source: "(?:file|dict|gopher|jar|tftp)://[^\\s]+", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "ssrf" },
  { source: "://[^/\\s@]*@[^/\\s@]*@", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "ssrf" },
  { source: "://(?:metadata|instance-data)(?::\\d+)?(?:/|\\s|$)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "ssrf" },
  { source: "\\{\\s*\\$(?:where|gt|lt|ne|eq|regex|in|nin|all|size|exists|type|mod|options):", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "nosql" },
  { source: "(?:\\{\\s*\\$[a-zA-Z]+\\s*:\\s*(?:\\{|\\[))", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "nosql" },
  { source: "\"\\$(?:where|regex|expr|jsonSchema|function|accumulator|type|exists|size)\"\\s*:", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "nosql" },
  { source: "\"\\$(?:gt|gte|lt|lte|ne|eq|in|nin|all|mod)\"\\s*:\\s*(?:\"\"|null|\\{|\\[)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "nosql" },
  { source: "\"[^\"]+\"\\s*:\\s*\\{\\s*\"\\$(?:ne|eq)\"\\s*:\\s*(?:true|false)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "nosql" },
  { source: "\\[\\$(?:where|gt|gte|lt|lte|ne|eq|regex|in|nin|nor|and|or|not|all|size|exists|type|mod|options|expr|function|elemMatch)\\]", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "nosql" },
  { source: "(?:\\A|[;,:\\n])\\s*filename\\s*=\\s*[\\\"'][^\\\"']*\\.(?:php\\d*|phtml|shtml|asax|ascx|ashx|asmx|aspx|bash|jspx|phar|phps|asa|asp|bat|cer|cfc|cfm|cgi|cmd|com|exe|hta|jsp|msi|pht|vbe|vbs|war|wsf|js|pl|py|rb|sh|ws)[\\\"']", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "file_upload" },
  { source: "(?:\\A|[;,:\\n])\\s*filename\\s*=\\s*[\\\"'][^\\\"']*\\.(?:php\\d*|phtml|shtml|asax|ascx|ashx|asmx|aspx|bash|jspx|phar|phps|asa|asp|bat|cer|cfc|cfm|cgi|cmd|exe|hta|jsp|msi|pht|vbe|vbs|war|wsf|js|pl|py|rb|sh|ws)(?![A-Za-z0-9])(?:[^ \\\"'][^\\\"']*)?\\.(?:docx|jpeg|pptx|tiff|webm|webp|xlsx|avi|bmp|doc|gif|ico|jpg|mkv|mov|mp3|mp4|odt|pdf|png|ppt|svg|tif|wav|xls)[\\\"']", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "file_upload" },
  { source: "(?:\\A|[;,:\\n])\\s*filename\\s*=\\s*[\\\"'][^\\\"']*\\.(?:php\\d*|phtml|shtml|asax|ascx|ashx|asmx|aspx|bash|jspx|phar|phps|asa|asp|bat|cer|cfc|cfm|cgi|cmd|exe|hta|jsp|msi|pht|vbe|vbs|war|wsf|js|pl|py|rb|sh|ws)(?![A-Za-z0-9])(?:(?:%00|\\\\u0000|\\\\x00|\\\\0|\\x00|;)[^\\\"']*|\\.)[\\\"']", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "file_upload" },
  { source: "(?:\\A|[;,:\\n])\\s*filename\\s*=\\s*[\\\"'][^\\\"']*\\.(?:php\\d*|phtml|shtml|asax|ascx|ashx|asmx|aspx|bash|jspx|phar|phps|asa|asp|bat|cer|cfc|cfm|cgi|cmd|exe|hta|jsp|msi|pht|vbe|vbs|war|wsf|js|pl|py|rb|sh|ws)(?![A-Za-z0-9])(?:(?:\\x00|;)[^\\\"']*|\\.)[\\\"']", contexts: new Set(["header", "query_param", "request_body", "unknown"]), category: "file_upload" },
  { source: "(?:%2e%2e|%252e%252e|%uff0e%uff0e|%c0%ae%c0%ae|%e0%40%ae|%c0%ae%e0%80%ae|%25c0%25ae)/", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "path_traversal" },
  { source: "\\{\\{\\s*[^\\}]+(?:system|exec|popen|eval|require|include)\\s*\\}\\}", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "template" },
  { source: "\\{\\%\\s*[^\\%]+(?:system|exec|popen|eval|require|include)\\s*\\%\\}", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "template" },
  { source: "(?i)<%[=#]?[^%]*(?:system|exec|eval|`|Runtime|IO\\.|File\\.|Dir\\.|\\d+\\s*[-+*/]\\s*\\d+)[^%]*%>", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "template" },
  { source: "\\$\\{[^}]*(?:@[\\w.]+@|\\b\\w+\\s*\\(|\\d+\\s*[*/%+\\-]\\s*\\d+)[^}]*\\}", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "template" },
  { source: "\\{\\{(?![^\\}]*\\d{4}-\\d{1,2}-\\d{1,2}(?!\\d))(?=[^\\}]*(?:@[\\w.]+@|\\b\\w+\\(\\s*\\)|['\\\"]?\\d+['\\\"]?\\s*[*/%+\\-]\\s*['\\\"]?\\d+['\\\"]?))[^\\}]*\\}\\}", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "template" },
  { source: "#\\{(?![^\\}]*\\d{4}-\\d{1,2}-\\d{1,2}(?!\\d))(?=[^\\}]*(?:@[\\w.]+@|\\b\\w+\\s*\\(|['\\\"]?\\d+['\\\"]?\\s*[*/%+\\-]\\s*['\\\"]?\\d+['\\\"]?))[^\\}]*\\}", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "template" },
  { source: "[\\r\\n][^\\S\\r\\n]*(?:HTTP\\/[0-9.]+|Location:|Set-Cookie:)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "http_split" },
  { source: "\\A[/\\\\]?(?:(?!\\.env(?:\\.\\w+)?(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*\\.env(?:\\.\\w+)?(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "sensitive_file" },
  { source: "\\A(?=(?:(?!\\n).)*\\b(?:scan(?:ner|ning|ned|s)?|attack(?:er|ers|ed|s)?|attempt(?:ed|s)?|exploit(?:ation|ed|s|ing|kit)?|prob(?:e|ed|es|ing)|malicious|intrusion(?:s)?|botnet(?:s)?|honeypot(?:s)?|brute[- ]force|credential[- ]stuffing|threat feed|vulnerabilit(?:y|ies)|hostile|recon(?:naissance)?|spoofed referer|bad actor(?:s)?|WAF|IDS|SOC|pentest(?:ing)?|blocked|flagged|triggered|denied|enumerat(?:e|ed|ing)|suspicious)\\b)\\A(?:(?!\\n).)*[/\\\\](?:\\.env(?:\\.\\w+)?)(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?\\b", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "sensitive_file" },
  { source: "\\A[/\\\\]?(?:(?!(?:(?!config)[\\w-])*config[\\w-]*\\.(?:env|yml|yaml|json|toml|ini|xml|conf)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:(?!config)[\\w-])*config[\\w-]*\\.(?:env|yml|yaml|json|toml|ini|xml|conf)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "sensitive_file" },
  { source: "\\A[/\\\\]?(?:(?![\\w.\\-~%]*\\.map(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*[\\w.\\-~%]*\\.map(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "sensitive_file" },
  { source: "\\A[/\\\\]?(?:[\\w.\\-~%]+[/\\\\])*[\\w.\\-~%]*\\.(?:ts|tsx|jsx|py|rb|java|go|rs|php|pl|sh|sql)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "sensitive_file" },
  { source: "\\A[/\\\\]?(?:(?!\\.(?:git|svn|hg|bzr)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*\\.(?:git|svn|hg|bzr)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "sensitive_file" },
  { source: "\\A(?=(?:(?!\\n).)*\\b(?:scan(?:ner|ning|ned|s)?|attack(?:er|ers|ed|s)?|attempt(?:ed|s)?|exploit(?:ation|ed|s|ing|kit)?|prob(?:e|ed|es|ing)|malicious|intrusion(?:s)?|botnet(?:s)?|honeypot(?:s)?|brute[- ]force|credential[- ]stuffing|threat feed|vulnerabilit(?:y|ies)|hostile|recon(?:naissance)?|spoofed referer|bad actor(?:s)?|WAF|IDS|SOC|pentest(?:ing)?|blocked|flagged|triggered|denied|enumerat(?:e|ed|ing)|suspicious)\\b)\\A(?:(?!\\n).)*[/\\\\](?:\\.(?:git|svn|hg|bzr))(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?\\b", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "sensitive_file" },
  { source: "\\A[/\\\\]?(?:[\\w.\\-~%]+[/\\\\])*[\\w.\\-~%]*\\.\\w+~(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "sensitive_file" },
  { source: "\\A[/\\\\]?(?:(?!(?:wp-(?:admin|login|content|includes|config)|administrator|xmlrpc)\\.?(?:php)?(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:wp-(?:admin|login|content|includes|config)|administrator|xmlrpc)\\.?(?:php)?(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "cms_probing" },
  { source: "\\A(?=(?:(?!\\n).)*\\b(?:scan(?:ner|ning|ned|s)?|attack(?:er|ers|ed|s)?|attempt(?:ed|s)?|exploit(?:ation|ed|s|ing|kit)?|prob(?:e|ed|es|ing)|malicious|intrusion(?:s)?|botnet(?:s)?|honeypot(?:s)?|brute[- ]force|credential[- ]stuffing|threat feed|vulnerabilit(?:y|ies)|hostile|recon(?:naissance)?|spoofed referer|bad actor(?:s)?|WAF|IDS|SOC|pentest(?:ing)?|blocked|flagged|triggered|denied|enumerat(?:e|ed|ing)|suspicious)\\b)\\A(?:(?!\\n).)*[/\\\\](?:(?:wp-(?:admin|login|content|includes|config)|administrator|xmlrpc)\\.?(?:php)?)(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?\\b", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "cms_probing" },
  { source: "\\A[/\\\\]?(?:(?!(?:phpinfo|info|test|php_info)\\.php(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:phpinfo|info|test|php_info)\\.php(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "cms_probing" },
  { source: "\\A(?=(?:(?!\\n).)*\\b(?:scan(?:ner|ning|ned|s)?|attack(?:er|ers|ed|s)?|attempt(?:ed|s)?|exploit(?:ation|ed|s|ing|kit)?|prob(?:e|ed|es|ing)|malicious|intrusion(?:s)?|botnet(?:s)?|honeypot(?:s)?|brute[- ]force|credential[- ]stuffing|threat feed|vulnerabilit(?:y|ies)|hostile|recon(?:naissance)?|spoofed referer|bad actor(?:s)?|WAF|IDS|SOC|pentest(?:ing)?|blocked|flagged|triggered|denied|enumerat(?:e|ed|ing)|suspicious)\\b)\\A(?:(?!\\n).)*[/\\\\](?:(?:phpinfo|info|test|php_info)\\.php)(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?\\b", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "cms_probing" },
  { source: "\\A[/\\\\]?(?:(?![\\w.\\-~%]*\\.(?:bak|backup|old|orig|save|swp|swo|tmp|temp)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*[\\w.\\-~%]*\\.(?:bak|backup|old|orig|save|swp|swo|tmp|temp)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "cms_probing" },
  { source: "\\A[/\\\\]?(?:(?!(?:\\.htaccess|\\.htpasswd|\\.DS_Store|Thumbs\\.db|\\.npmrc|\\.dockerenv|web\\.config)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:\\.htaccess|\\.htpasswd|\\.DS_Store|Thumbs\\.db|\\.npmrc|\\.dockerenv|web\\.config)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "cms_probing" },
  { source: "\\A(?=(?:(?!\\n).)*\\b(?:scan(?:ner|ning|ned|s)?|attack(?:er|ers|ed|s)?|attempt(?:ed|s)?|exploit(?:ation|ed|s|ing|kit)?|prob(?:e|ed|es|ing)|malicious|intrusion(?:s)?|botnet(?:s)?|honeypot(?:s)?|brute[- ]force|credential[- ]stuffing|threat feed|vulnerabilit(?:y|ies)|hostile|recon(?:naissance)?|spoofed referer|bad actor(?:s)?|WAF|IDS|SOC|pentest(?:ing)?|blocked|flagged|triggered|denied|enumerat(?:e|ed|ing)|suspicious)\\b)\\A(?:(?!\\n).)*[/\\\\](?:(?:\\.htaccess|\\.htpasswd|\\.DS_Store|Thumbs\\.db|\\.npmrc|\\.dockerenv|web\\.config))(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?\\b", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "cms_probing" },
  { source: "\\A[/\\\\]?(?:[\\w.\\-~%]+[/\\\\])*[\\w.\\-~%]*\\.(?:asp|aspx|jsp|jsa|jhtml|shtml|cfm|cgi|do|action|lua|inc|woa|nsf|esp)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "recon" },
  { source: "\\A[/\\\\](?:(?!(?:management|config_dump|credentials|system[/\\\\]version|version[/\\\\]system)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:management|config_dump|credentials|system[/\\\\]version|version[/\\\\]system)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "recon" },
  { source: "\\A[/\\\\](?:system|version)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "recon" },
  { source: "\\A[/\\\\]?(?:(?!(?:actuator|server-status|telescope)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:actuator|server-status|telescope)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "recon" },
  { source: "(?:CSCOE|dana-(?:na|cached)|sslvpn|RDWeb|/owa/|/ecp/|global-protect|ssl-vpn/|svpn/|sonicui|/remote/login|myvpn|vpntunnel|versa/login)", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "recon" },
  { source: "\\A[/\\\\]?(?:(?!(?:geoserver|confluence|nifi|ScadaBR|pandora_console|centreon|kylin|decisioncenter|evox|MagicInfo|metasys|officescan|helpdesk|ignite)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:geoserver|confluence|nifi|ScadaBR|pandora_console|centreon|kylin|decisioncenter|evox|MagicInfo|metasys|officescan|helpdesk|ignite)(?:[.\\-][\\w.\\-~%]*)?(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "recon" },
  { source: "\\A[/\\\\]?(?:(?!cgi-(?:bin|mod)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*cgi-(?:bin|mod)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "recon" },
  { source: "\\A[/\\\\]?(?:(?!(?:HNAP1|IPCamDesc\\.xml|SDK/webLanguage)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:HNAP1|IPCamDesc\\.xml|SDK/webLanguage)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "recon" },
  { source: "\\A[/\\\\]?(?:(?!(?:language|languages)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:language|languages)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "recon" },
  { source: "\\A[/\\\\]?(?:(?!(?:readme\\.txt|README\\.md|CHANGELOG|pom\\.xml|build\\.gradle|appsettings\\.json|crossdomain\\.xml)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:readme\\.txt|README\\.md|CHANGELOG|pom\\.xml|build\\.gradle|appsettings\\.json|crossdomain\\.xml)(?:\\.[\\w.\\-~%]*)?(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "recon" },
  { source: "\\A[/\\\\]?(?:(?!(?:sap|ise|nidp|cslu|rustfs|developmentserver|fog/management|lms/db|json/login_session|sms_mp|plugin/webs_model|wsman|am_bin)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:sap|ise|nidp|cslu|rustfs|developmentserver|fog/management|lms/db|json/login_session|sms_mp|plugin/webs_model|wsman|am_bin)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "recon" },
  { source: "(?:nmaplowercheck|nice\\s+ports|Trinity\\.txt)", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "recon" },
  { source: "\\A[/\\\\]?(?:(?!\\.(?:openclaw|clawdbot)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*\\.(?:openclaw|clawdbot)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "recon" },
  { source: "\\A[/\\\\]?(?:default|inicio|indice|localstart)(?:\\.[\\w.\\-~%]*)?(?:[/\\\\])?(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "recon" },
  { source: "\\A[/\\\\]?(?:(?!inicio\\.html?(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*inicio\\.html?(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "recon" },
  { source: "\\A[/\\\\]?(?:(?!(?:\\.streamlit|\\.gpt-pilot|\\.aider|\\.cursor|\\.windsurf|\\.copilot|\\.devcontainer)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:\\.streamlit|\\.gpt-pilot|\\.aider|\\.cursor|\\.windsurf|\\.copilot|\\.devcontainer)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "recon" },
  { source: "\\A[/\\\\]?(?:(?!(?:docker-compose|Dockerfile|Makefile|Vagrantfile|Jenkinsfile|Procfile)(?:\\.ya?ml)?(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:docker-compose|Dockerfile|Makefile|Vagrantfile|Jenkinsfile|Procfile)(?:\\.ya?ml)?(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "recon" },
  { source: "\\A[/\\\\]?(?:(?![\\w.\\-~%]*(?:secrets?|credentials?)\\.(?:py|json|yml|yaml|toml|txt|env|xml|conf|cfg)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*[\\w.\\-~%]*(?:secrets?|credentials?)\\.(?:py|json|yml|yaml|toml|txt|env|xml|conf|cfg)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "recon" },
  { source: "\\A[/\\\\]?(?:(?!autodiscover(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*autodiscover(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "recon" },
  { source: "\\A[/\\\\]?(?:(?!dns-query(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*dns-query(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "recon" },
  { source: "\\A[/\\\\]?(?:(?!\\.git/(?:refs|index|HEAD|objects|logs)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*\\.git/(?:refs|index|HEAD|objects|logs)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", contexts: new Set(["query_param", "request_body", "unknown", "url_path"]), category: "recon" },
  { source: "(?:__proto__|constructor)\\s*(?:\\[\\s*[\\\"']prototype[\\\"']\\s*\\]|\\.\\s*prototype)|[\\\"']__proto__[\\\"']\\s*:", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "proto_pollution" },
  { source: "__proto__\\s*(?:\\[|\\.)|\\[\\s*[\\\"']?__proto__[\\\"']?\\s*\\]|constructor\\s*\\[\\s*[\\\"']?prototype[\\\"']?\\s*\\]|\\[\\s*[\\\"']?constructor[\\\"']?\\s*\\]\\s*\\[\\s*[\\\"']?prototype[\\\"']?\\s*\\]", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "proto_pollution" },
  { source: "Object\\.prototype\\.[A-Za-z_$][\\w$]*\\s*=(?!=)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "proto_pollution" },
  { source: "\\b(?:Object|Reflect)\\.setPrototypeOf\\s*\\(", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "proto_pollution" },
  { source: "System\\.Diagnostics\\.Process\\.Start\\s*\\(|System\\.Reflection\\.|Assembly\\.Load\\s*\\(", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "code_injection" },
  { source: "(?-i:\\bgetattr\\(\\s*(?:__import__\\(\\s*['\\\"](?:os|subprocess|builtins|importlib)['\\\"]\\s*\\)|\\b(?:os|subprocess|builtins|importlib)\\b)\\s*,\\s*['\\\"](?:system|popen|exec|eval|call|run|Popen|check_output|check_call)['\\\"]\\s*\\)\\s*\\()", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "code_injection" },
  { source: "(?-i:\\bvars\\(\\s*(?:__import__\\(\\s*['\\\"](?:os|subprocess|builtins|importlib)['\\\"]\\s*\\)|\\b(?:os|subprocess|builtins|importlib)\\b)\\s*\\)\\s*\\[\\s*['\\\"](?:system|popen|exec|eval|call|run|Popen|check_output|check_call)['\\\"]\\s*\\]\\s*\\()", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "code_injection" },
  { source: "(?<![A-Za-z0-9+/])(?-i:rO0AB)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "deserialization" },
  { source: "(?<![A-Za-z0-9+/])(?-i:AAEAAAD)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "deserialization" },
  { source: "(?<![A-Za-z0-9+/])(?-i:gA[SW]V)", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "deserialization" },
  { source: "(?<![A-Za-z0-9+/])(?-i:BAh[Jv7bV])", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "deserialization" },
  { source: "cos\\n", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "deserialization" },
  { source: "c__builtin__", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "deserialization" },
  { source: "csubprocess", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "deserialization" },
  { source: "cposix", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "deserialization" },
  { source: "(c[A-Za-z_][A-Za-z0-9_]{0,100}(?:\\.[A-Za-z_][A-Za-z0-9_]{0,100}){0,20}\\n[A-Za-z_][A-Za-z0-9_]{0,100}\\n)[^ \\t]{0,100}?[Rb]", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "deserialization" },
  { source: "O:\\d+:\"", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "deserialization" },
  { source: "C:\\d+:\"", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "deserialization" },
  { source: "E:\\d+:\"", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "deserialization" },
  { source: "<ObjectDataProvider\\b", contexts: new Set(["header", "query_param", "request_body", "unknown", "url_path"]), category: "deserialization" },
];

/**
 * Whole-value recon rows whose leading path separator is optional: outside a
 * URL path they match bare words such as "default" or "README.md", not only
 * probe paths. Mirrors RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES in
 * guard_core/handlers/_suspatterns_pattern_table.py (upstream #115/#116):
 * the recon sources that start with the optional-separator anchor \A[/\\]?;
 * required-separator (\A[/\\]) rows and non-anchored rows are excluded.
 */
export const RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES: ReadonlySet<string> = new Set(
  PATTERN_DEFINITIONS
    .filter((entry) => entry.category === 'recon' && entry.source.startsWith(_TOP_LEVEL_PATH_PREFIX_RE))
    .map((entry) => entry.source),
);

/**
 * Recon rows additionally scanned against the signal-preserving raw view.
 * The processed views fold LDAP hex escapes ("\de" -> "Þ") before the
 * pattern tables run, so separator-prefixed probes such as "\default" or
 * "\default.asp" never reach a recon row there. The raw view keeps them
 * intact; the leading-separator gate still decides which matches are probes,
 * so bare words stay innocent exactly as on the processed views. Mirrors
 * DETECTION_RECON_RAW_VIEW_PATTERN_SOURCES in
 * guard_core/handlers/_suspatterns_pattern_table.py (upstream commit
 * 81cf07f1): every recon-category row, derived programmatically.
 */
export const DETECTION_RECON_RAW_VIEW_PATTERN_SOURCES: ReadonlySet<string> = new Set(
  PATTERN_DEFINITIONS
    .filter((entry) => entry.category === 'recon')
    .map((entry) => entry.source),
);

/** Patterns whose matches are suppressed inside binary-dense regions. */
export const NOISE_PRONE_PATTERN_SOURCES: ReadonlySet<string> = new Set([
  "#\\{(?![^\\}]*\\d{4}-\\d{1,2}-\\d{1,2}(?!\\d))(?=[^\\}]*(?:@[\\w.]+@|\\b\\w+\\s*\\(|['\\\"]?\\d+['\\\"]?\\s*[*/%+\\-]\\s*['\\\"]?\\d+['\\\"]?))[^\\}]*\\}",
  "(?:[;&|]\\s*(?:\\$\\([^)]+\\)|\\$\\{[^}]+\\}))",
  "(?<!`)`(?:[A-Za-z0-9_./~]|\\$[({])(?:[^`\\\\\\n]|\\\\.)*`",
  "[;|&]\\s*(?:ls|cat|rm|id|whoami|uname|wget|curl|nc|netcat|socat|bash|sh|python|perl)\\b",
  "[A-Za-z0-9_./*?-]*[?*][A-Za-z0-9_./*?-]*",
  "\\$\\((?:[^()\\\\\\n]|\\\\.)*\\)|\\$\\{(?:[^{}\\\\\\n]|\\\\.)*\\}",
  "\\$\\{[^}]*(?:@[\\w.]+@|\\b\\w+\\s*\\(|\\d+\\s*[*/%+\\-]\\s*\\d+)[^}]*\\}",
  "\\(\\s*[&|]\\s*",
  "\\w+(?:['\\\"]+\\w+){1,10}",
  // SQLi comment terminators span arbitrary whitespace between the quote and
  // the -- / # terminator, so they routinely fire inside text-decoded binary
  // bodies (e.g. "'\n--" byte runs in compressed payloads). Parity with
  // upstream commit f5d53ca5.
  "'\\s*(?:[\\);]+\\s*)?--|'[\\);]*#(?:\\n|\\Z)",
]);

/** Patterns that only run on the raw signal-preserving view. */
export const DETECTION_RAW_VIEW_PATTERN_SOURCES: ReadonlySet<string> = new Set([
  "#\\{(?![^\\}]*\\d{4}-\\d{1,2}-\\d{1,2}(?!\\d))(?=[^\\}]*(?:@[\\w.]+@|\\b\\w+\\s*\\(|['\\\"]?\\d+['\\\"]?\\s*[*/%+\\-]\\s*['\\\"]?\\d+['\\\"]?))[^\\}]*\\}",
  "'\\s*(?:[\\);]+\\s*)?--|'[\\);]*#(?:\\n|\\Z)",
  "(?:%2e%2e|%252e%252e|%uff0e%uff0e|%c0%ae%c0%ae|%e0%40%ae|%c0%ae%e0%80%ae|%25c0%25ae)/",
  "(?:\\A|[;,:\\n])\\s*filename\\s*=\\s*[\\\"'][^\\\"']*\\.(?:php\\d*|phtml|shtml|asax|ascx|ashx|asmx|aspx|bash|jspx|phar|phps|asa|asp|bat|cer|cfc|cfm|cgi|cmd|exe|hta|jsp|msi|pht|vbe|vbs|war|wsf|js|pl|py|rb|sh|ws)(?![A-Za-z0-9])(?:(?:%00|\\\\u0000|\\\\x00|\\\\0|\\x00|;)[^\\\"']*|\\.)[\\\"']",
  "(?:\\A|[;,:\\n])\\s*filename\\s*=\\s*[\\\"'][^\\\"']*\\.(?:php\\d*|phtml|shtml|asax|ascx|ashx|asmx|aspx|bash|jspx|phar|phps|asa|asp|bat|cer|cfc|cfm|cgi|cmd|exe|hta|jsp|msi|pht|vbe|vbs|war|wsf|js|pl|py|rb|sh|ws)(?![A-Za-z0-9])(?:[^ \\\"'][^\\\"']*)?\\.(?:docx|jpeg|pptx|tiff|webm|webp|xlsx|avi|bmp|doc|gif|ico|jpg|mkv|mov|mp3|mp4|odt|pdf|png|ppt|svg|tif|wav|xls)[\\\"']",
  "(?<![A-Za-z0-9+/])(?-i:AAEAAAD)",
  "(?<![A-Za-z0-9+/])(?-i:BAh[Jv7bV])",
  "(?<![A-Za-z0-9+/])(?-i:gA[SW]V)",
  "(?<![A-Za-z0-9+/])(?-i:rO0AB)",
  "(?i)\\bORDER\\s+BY\\s+\\d+\\s*(?:--|#|;|\\)|,|/\\*|\\Z)|(?<=[=?&])ORDER\\s+BY\\s+\\d+\\s*\\n",
  "(c[A-Za-z_][A-Za-z0-9_]{0,100}(?:\\.[A-Za-z_][A-Za-z0-9_]{0,100}){0,20}\\n[A-Za-z_][A-Za-z0-9_]{0,100}\\n)[^ \\t]{0,100}?[Rb]",
  "[\\r\\n][^\\S\\r\\n]*(?:HTTP\\/[0-9.]+|Location:|Set-Cookie:)",
  "[a-zA-Z][\\w-]*\\s*=[\\d\\w\\s]*\\*\\)+(?:%00|\\\\u0000|\\\\x00|\\\\0|\\x00)",
  "\\*\\)\\)+(?:%00|\\\\u0000|\\\\x00|\\\\0|\\x00)",
  "cos\\n",
  "j[\\t\\r\\n]*a[\\t\\r\\n]*v[\\t\\r\\n]*a[\\t\\r\\n]*s[\\t\\r\\n]*c[\\t\\r\\n]*r[\\t\\r\\n]*i[\\t\\r\\n]*p[\\t\\r\\n]*t[\\t\\r\\n]*:\\s*[^\\s]+",
]);

/** Patterns that only run on the URL-decoded view. */
export const DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES: ReadonlySet<string> = new Set([
  "(?:\\A|[;,:\\n])\\s*filename\\s*=\\s*[\\\"'][^\\\"']*\\.(?:php\\d*|phtml|shtml|asax|ascx|ashx|asmx|aspx|bash|jspx|phar|phps|asa|asp|bat|cer|cfc|cfm|cgi|cmd|exe|hta|jsp|msi|pht|vbe|vbs|war|wsf|js|pl|py|rb|sh|ws)(?![A-Za-z0-9])(?:(?:\\x00|;)[^\\\"']*|\\.)[\\\"']",
  "(?i)(?:['\\\")\\d]|/\\*)\\s{0,3}\\bORDER\\s+BY\\s+\\d+|\\bORDER\\s+BY\\s+\\d+\\s*(?:--|#|/\\*)",
  "[a-zA-Z][\\w-]*\\s*=[\\d\\w\\s]*\\*\\)+\\x00",
  "\\*\\)\\)+\\x00",
  "\\A(?:(?!\\n).)*(?:boot\\.ini|win\\.ini|system\\.ini|config\\.sys)(?:[&#;,\\\"'<>]|\\s*\\Z)",
  "\\A(?:(?!\\n).)*etc/(?:passwd|shadow|group|hosts|motd|issue|mysql/my\\.cnf|ssh/ssh_config)(?:[&#;,\\\"'<>]|\\s*\\Z)",
  "\\A(?:(?!\\n).)*proc/self/environ(?:[&#;,\\\"'<>]|\\s*\\Z)",
  "\\A(?:(?!\\n).)*var/log/[^\\s/]+(?:[&#;,\\\"'<>]|\\s*\\Z)",
  "\\n[^\\S\\r\\n]*(?:[^=\\s;|&]+=[^\\s;|&]+\\s+)*(?:/?(?:[\\w.-]+/)*env\\s+)?/?(?:[\\w.-]+/)*(?:bash|sh|ksh|csh|tsch|zsh|ash)\\s+-c\\b",
]);

/** Per-pattern weight overrides; every other category weighs 1.0. */
export const DETECTION_PATTERN_WEIGHT_OVERRIDES: Readonly<Record<string, number>> = {
  "(?i)\\bSELECT\\b(?:(?!\\bSELECT\\b)[\\w\\s,\\*().])*?\\bFROM\\b": 0.5,
  "(?i)SELECT\\s+\\*": 0.5,
  "(?i)\\bWHERE\\s+[\\w.\"]+\\s*(?:=|<|>|<=|>=|LIKE|IN)\\b": 0.5,
};

/** Validators wired to candidate-rejection in the reference order. */
export const VALIDATOR_PATTERN_SOURCES: readonly string[] = [
  "://(?:[^/@\\s]*@)?((?:0[xX][0-9a-fA-F]+|0[0-7]+|[1-9]\\d*|0)(?:\\.(?:0[xX][0-9a-fA-F]+|0[0-7]+|[1-9]\\d*|0)){0,3})(?=[:/\\s]|$)",
  "\\*\\)[|&]?\\(+\\s*(?::)?(?:[a-zA-Z][\\w.-]*|\\d+(?:\\.\\d+)*)(?:;[\\w.-]+)*(?::[\\w.-]+)*\\s*:?=",
  "\\*\\s*\\)+\\s*(?:[|&!]\\s*)?\\(+\\s*(?:[&|!]|(?::)?(?:[a-zA-Z][\\w.-]*|\\d+(?:\\.\\d+)*)(?:;[\\w.-]+)*(?::[\\w.-]+)*\\s*:?=)",
  "\\)\\s*\\(\\s*(?:[&|!]|(?::)?(?:[a-zA-Z][\\w.-]*|\\d+(?:\\.\\d+)*)(?:;[\\w.-]+)*(?::[\\w.-]+)*\\s*:?[=~<>])",
  "\\(\\s*[&|]\\s*",
  "(?<!`)`(?:[A-Za-z0-9_./~]|\\$[({])(?:[^`\\\\\\n]|\\\\.)*`",
  "\\A[/\\\\]?(?:[\\w.\\-~%]+[/\\\\])*[\\w.\\-~%]*\\.(?:ts|tsx|jsx|py|rb|java|go|rs|php|pl|sh|sql)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z",
  "\\$\\((?:[^()\\\\\\n]|\\\\.)*\\)|\\$\\{(?:[^{}\\\\\\n]|\\\\.)*\\}",
  "(?:\\A|[;&|]\\s*|\\$\\()\\{[^{}\\s,:'\\\"][^{},:'\\\"]*(?:,(?:[^{}\\s,:'\\\"][^{},:'\\\"]*)?)+\\}",
  "\\w+(?:['\\\"]+\\w+){1,10}",
  "[A-Za-z0-9_./*?-]*[?*][A-Za-z0-9_./*?-]*",
  "(c[A-Za-z_][A-Za-z0-9_]{0,100}(?:\\.[A-Za-z_][A-Za-z0-9_]{0,100}){0,20}\\n[A-Za-z_][A-Za-z0-9_]{0,100}\\n)[^ \\t]{0,100}?[Rb]",
];

/** Patterns served by structural windowed finders. */
export const WINDOWED_FINDER_PATTERN_SOURCES: readonly string[] = [
  "(c[A-Za-z_][A-Za-z0-9_]{0,100}(?:\\.[A-Za-z_][A-Za-z0-9_]{0,100}){0,20}\\n[A-Za-z_][A-Za-z0-9_]{0,100}\\n)[^ \\t]{0,100}?[Rb]",
  "<!DOCTYPE[^>\\[]+PUBLIC[^>\\[]+[\\\"']https?://(?!(?:www\\.)?w3\\.org/)[^\\\"'>]+[\\\"'][^>\\[]*>",
  "[a-zA-Z][\\w-]*\\s*=[\\d\\w\\s]*\\*\\)+(?:%00|\\\\u0000|\\\\x00|\\\\0|\\x00)",
  "[a-zA-Z][\\w-]*\\s*=[\\d\\w\\s]*\\*\\)+\\x00",
  "\\n[^\\S\\r\\n]*(?:[^=\\s;|&]+=[^\\s;|&]+\\s+)*(?:/?(?:[\\w.-]+/)*env\\s+)?/?(?:[\\w.-]+/)*(?:bash|sh|ksh|csh|tsch|zsh|ash)\\s+-c\\b",
  "\\w+(?:['\\\"]+\\w+){1,10}",
];

/** Patterns served by dedicated scan-window matchers. */
export const SCAN_MATCHER_PATTERN_SOURCES: readonly string[] = [
  "#\\{(?![^\\}]*\\d{4}-\\d{1,2}-\\d{1,2}(?!\\d))(?=[^\\}]*(?:@[\\w.]+@|\\b\\w+\\s*\\(|['\\\"]?\\d+['\\\"]?\\s*[*/%+\\-]\\s*['\\\"]?\\d+['\\\"]?))[^\\}]*\\}",
  "(?:[;&|]\\s*(?:\\$\\([^)]+\\)|\\$\\{[^}]+\\}))",
  "(?:\\A|[;,:\\n])\\s*filename\\s*=\\s*[\\\"'][^\\\"']*\\.(?:php\\d*|phtml|shtml|asax|ascx|ashx|asmx|aspx|bash|jspx|phar|phps|asa|asp|bat|cer|cfc|cfm|cgi|cmd|com|exe|hta|jsp|msi|pht|vbe|vbs|war|wsf|js|pl|py|rb|sh|ws)[\\\"']",
  "(?:\\A|[;,:\\n])\\s*filename\\s*=\\s*[\\\"'][^\\\"']*\\.(?:php\\d*|phtml|shtml|asax|ascx|ashx|asmx|aspx|bash|jspx|phar|phps|asa|asp|bat|cer|cfc|cfm|cgi|cmd|exe|hta|jsp|msi|pht|vbe|vbs|war|wsf|js|pl|py|rb|sh|ws)(?![A-Za-z0-9])(?:(?:%00|\\\\u0000|\\\\x00|\\\\0|\\x00|;)[^\\\"']*|\\.)[\\\"']",
  "(?:\\A|[;,:\\n])\\s*filename\\s*=\\s*[\\\"'][^\\\"']*\\.(?:php\\d*|phtml|shtml|asax|ascx|ashx|asmx|aspx|bash|jspx|phar|phps|asa|asp|bat|cer|cfc|cfm|cgi|cmd|exe|hta|jsp|msi|pht|vbe|vbs|war|wsf|js|pl|py|rb|sh|ws)(?![A-Za-z0-9])(?:(?:\\x00|;)[^\\\"']*|\\.)[\\\"']",
  "(?:\\A|[;,:\\n])\\s*filename\\s*=\\s*[\\\"'][^\\\"']*\\.(?:php\\d*|phtml|shtml|asax|ascx|ashx|asmx|aspx|bash|jspx|phar|phps|asa|asp|bat|cer|cfc|cfm|cgi|cmd|exe|hta|jsp|msi|pht|vbe|vbs|war|wsf|js|pl|py|rb|sh|ws)(?![A-Za-z0-9])(?:[^ \\\"'][^\\\"']*)?\\.(?:docx|jpeg|pptx|tiff|webm|webp|xlsx|avi|bmp|doc|gif|ico|jpg|mkv|mov|mp3|mp4|odt|pdf|png|ppt|svg|tif|wav|xls)[\\\"']",
  "(?i)(?:LOAD_FILE\\s*\\([^)]+\\))",
  "(?i)<%[=#]?[^%]*(?:system|exec|eval|`|Runtime|IO\\.|File\\.|Dir\\.|\\d+\\s*[-+*/]\\s*\\d+)[^%]*%>",
  "[A-Za-z0-9_./*?-]*[?*][A-Za-z0-9_./*?-]*",
  "\\$\\{[^}]*(?:@[\\w.]+@|\\b\\w+\\s*\\(|\\d+\\s*[*/%+\\-]\\s*\\d+)[^}]*\\}",
  "\\{\\%\\s*[^\\%]+(?:system|exec|popen|eval|require|include)\\s*\\%\\}",
  "\\{\\{(?![^\\}]*\\d{4}-\\d{1,2}-\\d{1,2}(?!\\d))(?=[^\\}]*(?:@[\\w.]+@|\\b\\w+\\(\\s*\\)|['\\\"]?\\d+['\\\"]?\\s*[*/%+\\-]\\s*['\\\"]?\\d+['\\\"]?))[^\\}]*\\}\\}",
  "\\{\\{\\s*[^\\}]+(?:system|exec|popen|eval|require|include)\\s*\\}\\}",
];

/** Patterns served by generic bounded scan windows (prefix+terminator pairs). */
export const SCAN_WINDOW_BOUND_PATTERN_SOURCES: readonly string[] = [
  "(?:<!\\[CDATA\\[.*?\\]\\]>)",
  "(?:<[A-Za-z/][^<>]*style\\s*=\\s{0,20}[\\\"']?[^<>\\\"']*(?:expression|behavior|url)\\s*\\([^)]*\\))",
  "(?:<applet[^>]*>[\\s\\S]*<\\/applet\\s*>)",
  "(?:<embed[^>]*>[\\s\\S]*<\\/embed\\s*>)",
  "(?:<object[^>]*>[\\s\\S]*<\\/object\\s*>)",
  "<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>",
  "<!DOCTYPE[^>\\[]*\\[[\\s\\S]*?<!ENTITY",
  "<script[^>]*>[^<]*<\\/script\\s*>",
  "=(?:https?|ftp):\\/\\/[^\\s'\\\"<>]+\\/[^\\s'\\\"<>\\/]*\\.(?:phtml|php[3-5]?|phar|jsp|aspx?|pl|py|txt|inc)(?![a-zA-Z0-9])",
  "\\.\\.;[^/\\\\]*[/\\\\]",
];
