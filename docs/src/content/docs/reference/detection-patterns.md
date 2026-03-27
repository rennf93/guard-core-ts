---
title: "Detection Patterns"
description: "All 75 attack patterns grouped by category with context sets explained"
---

The detection engine ships with 75 built-in regex patterns across 15 attack categories. Each pattern is associated with a set of contexts that determine when it is checked.

## Contexts

Each request component is assigned a context:

| Context | Source |
|---------|--------|
| `url_path` | The URL path portion of the request |
| `query_param` | Query string parameters |
| `header` | Request headers |
| `request_body` | Request body content |
| `unknown` | Fallback context (always checked) |

Patterns are only tested against content from matching contexts. This reduces false positives -- for example, SQL injection patterns are not checked against URL paths, and reconnaissance patterns are not checked against request bodies.

## XSS (8 patterns)

**Contexts**: `query_param`, `header`, `request_body`, `unknown`

| Pattern | Detects |
|---------|---------|
| `<script[^>]*>[^<]*</script\s*>` | Script tags with content |
| `javascript:\s*[^\s]+` | JavaScript protocol URIs |
| `on(error\|load\|click\|mouseover\|submit\|...)=...` | Event handler attributes |
| `<[^>]+\s+(href\|src\|data\|action)\s*=...javascript:...` | JS in attribute URIs |
| `<[^>]+style\s*=...(expression\|behavior\|url)\s*\(` | CSS expressions |
| `<object[^>]*>...</object\s*>` | Object embeds |
| `<embed[^>]*>...</embed\s*>` | Embed tags |
| `<applet[^>]*>...</applet\s*>` | Applet tags |

## SQL Injection (9 patterns)

**Contexts**: `query_param`, `request_body`, `unknown`

| Pattern | Detects |
|---------|---------|
| `SELECT\s+[\w\s,*]+\s+FROM\s+[\w\s._]+` | SELECT...FROM statements |
| `UNION\s+(ALL\s+)?SELECT` | UNION SELECT injection |
| `'\s*(OR\|AND)\s*...=...` | Boolean-based injection |
| `UNION\s+(ALL\s+)?SELECT\s+(NULL,?)+` | NULL-based UNION probing |
| `INTO\s+(OUTFILE\|DUMPFILE)\s+'...'` | File write injection |
| `LOAD_FILE\s*\(` | File read injection |
| `BENCHMARK\s*\(\s*\d+` | Time-based blind injection |
| `SLEEP\s*\(\s*\d+\s*\)` | Time-based blind injection |
| `/\*![0-9]*\s*(OR\|AND\|UNION\|...)` | MySQL comment-based injection |

## Directory Traversal (5 patterns)

**Contexts**: `url_path`, `query_param`, `request_body`, `unknown`

| Pattern | Detects |
|---------|---------|
| `(\.\.\/\|\.\.\\)(\.\.\/\|\.\.\\)+` | Multiple `../` sequences |
| `/etc/(passwd\|shadow\|group\|hosts\|...)$` | Linux system files |
| `(boot\.ini\|win\.ini\|system\.ini\|config\.sys)` | Windows system files |
| `/proc/self/environ$` | Process environment |
| `/var/log/[^/]+$` | Log file access |

## Command Injection (5 patterns)

**Contexts**: `query_param`, `request_body`, `unknown`

| Pattern | Detects |
|---------|---------|
| `;\s*(ls\|cat\|rm\|chmod\|wget\|curl\|nc\|...)\s+-[a-zA-Z]+` | Chained commands with flags |
| `\|\s*(wget\|curl\|fetch\|lwp-download\|...)` | Piped downloads |
| `[;&\|` `` ` `` `]\s*(\$\(...\)\|\$\{...\})` | Command substitution |
| `(bash\|sh\|ksh\|csh\|...)\s+-[a-zA-Z]+` | Shell invocation |
| `(eval\|system\|exec\|shell_exec\|...)\s*\(` | Function-based execution |

## File Inclusion (2 patterns)

**Contexts**: `url_path`, `query_param`, `request_body`, `unknown`

| Pattern | Detects |
|---------|---------|
| `(php\|data\|zip\|rar\|file\|glob\|...)://` | PHP/protocol wrappers |
| `//[host](:[port])?([path])` | Remote file inclusion |

## LDAP Injection (3 patterns)

**Contexts**: `query_param`, `request_body`, `unknown`

| Pattern | Detects |
|---------|---------|
| `\(\s*[\|&]\s*\(\s*[^)]+=[*]` | LDAP filter injection |
| `\*(...=...\|=...)` | Wildcard injection |
| `\(\s*[&\|]\s*\)` | Empty filter injection |

## XML/XXE (3 patterns)

**Contexts**: `header`, `request_body`, `unknown`

| Pattern | Detects |
|---------|---------|
| `<!(ENTITY\|DOCTYPE)...SYSTEM...>` | External entity declaration |
| `<!\[CDATA\[...\]\]>` | CDATA sections |
| `<\?xml...\?>` | XML processing instructions |

## SSRF (2 patterns)

**Contexts**: `query_param`, `request_body`, `unknown`

| Pattern | Detects |
|---------|---------|
| `(localhost\|127.0.0.1\|0.0.0.0\|[::]\|169.254\|192.168\|10.\|172.16-31)` | Internal IP access |
| `(file\|dict\|gopher\|jar\|tftp)://` | Internal protocol access |

## NoSQL Injection (2 patterns)

**Contexts**: `query_param`, `request_body`, `unknown`

| Pattern | Detects |
|---------|---------|
| `\{\s*\$(where\|gt\|lt\|ne\|eq\|regex\|in\|...):` | MongoDB operator injection |
| `\{\s*\$[a-zA-Z]+\s*:\s*(\{\|\[)` | Nested operator injection |

## File Upload (1 pattern)

**Contexts**: `header`, `request_body`, `unknown`

| Pattern | Detects |
|---------|---------|
| `filename=...\.( php\|exe\|jsp\|asp\|sh\|bash\|...)` | Dangerous file extensions |

## Encoded Path Traversal (1 pattern)

**Contexts**: `url_path`, `query_param`, `request_body`, `unknown`

| Pattern | Detects |
|---------|---------|
| `(%2e%2e\|%252e%252e\|%uff0e%uff0e\|...)/` | Double-encoded and unicode `../` |

## Template Injection (2 patterns)

**Contexts**: `query_param`, `request_body`, `unknown`

| Pattern | Detects |
|---------|---------|
| `\{\{\s*...(system\|exec\|popen\|eval\|...)\s*\}\}` | Mustache/Jinja template injection |
| `\{%\s*...(system\|exec\|popen\|eval\|...)\s*%\}` | Jinja block injection |

## HTTP Splitting (1 pattern)

**Contexts**: `header`, `query_param`, `request_body`, `unknown`

| Pattern | Detects |
|---------|---------|
| `[\r\n]\s*(HTTP/\|Location:\|Set-Cookie:)` | Response splitting via CRLF |

## Sensitive Files (5 patterns)

**Contexts**: `url_path`, `request_body`, `unknown`

| Pattern | Detects |
|---------|---------|
| `.env(.*)` | Environment files |
| `config.(env\|yml\|yaml\|json\|toml\|ini\|xml\|conf)` | Configuration files |
| `*.map` | Source maps |
| `*.(ts\|tsx\|jsx\|py\|rb\|java\|go\|rs\|php\|...)` | Source code files |
| `.git\|.svn\|.hg\|.bzr` | Version control directories |

## CMS Probing (4 patterns)

**Contexts**: `url_path`, `request_body`, `unknown`

| Pattern | Detects |
|---------|---------|
| `wp-(admin\|login\|content\|includes\|config)\|administrator\|xmlrpc` | WordPress/CMS admin paths |
| `(phpinfo\|info\|test\|php_info).php` | PHP info pages |
| `*.(bak\|backup\|old\|orig\|save\|swp\|tmp\|temp)` | Backup files |
| `.htaccess\|.htpasswd\|.DS_Store\|.npmrc\|.dockerenv\|web.config` | Server config files |

## Reconnaissance (22 patterns)

**Contexts**: `url_path`, `unknown`

Detects probing for common web application paths, admin panels, API endpoints, VPN portals, monitoring tools, development files, and scanning tool signatures (nmap, etc.).

## Custom Patterns

Add custom patterns at runtime:

```typescript
await susPatternsHandler.addPattern('my-custom-pattern-regex');
```

Custom patterns are checked against all contexts (`query_param`, `header`, `url_path`, `request_body`, `unknown`) and persisted to Redis for cross-process sharing.
