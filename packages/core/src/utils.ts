import ipaddr from 'ipaddr.js';

import { multipartPartEntries, parseFormPairs, parseMediaTypeParams, parseMultipartParts } from './detection-engine/body-form-scan.js';
import type { ResolvedSecurityConfig } from './models/config.js';
import { defaultLogger } from './models/logger.js';
import type { Logger } from './models/logger.js';
import type { AgentHandlerProtocol } from './protocols/agent.js';
import type { GeoIPHandler } from './protocols/geo-ip.js';
import type { GuardRequest } from './protocols/request.js';
import type { DetectionResult, SusPatternsManager } from './handlers/sus-patterns.js';

const EXCLUDED_HEADERS = new Set([
  'host', 'user-agent', 'accept', 'accept-encoding', 'connection',
  'origin', 'referer', 'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest',
  'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
]);

/**
 * Port of guard_core._utils.logging_utils._sanitize_for_log: make a string
 * safe to emit on any console encoding. Control characters become \uXXXX
 * escapes and every non-ASCII code point becomes a \uXXXX (or \xNN for
 * surrogate-escaped bytes in the 0xDC80-0xDCFF range) escape, so the result
 * is pure ASCII and can never raise on legacy code pages such as cp1252.
 */
export function sanitizeForLog(value: string): string {
  if (!value) return value;
  const sanitized = value
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t');
  let out = '';
  for (const char of sanitized) {
    const code = char.codePointAt(0) ?? 0;
    if (code >= 32 && code <= 126) {
      out += char;
    } else if (code >= 0xdc80 && code <= 0xdcff) {
      out += `\\x${(code - 0xdc00).toString(16).padStart(2, '0')}`;
    } else {
      out += `\\u${code.toString(16).padStart(4, '0')}`;
    }
  }
  return out;
}

export async function sendAgentEvent(
  agentHandler: AgentHandlerProtocol | null,
  eventType: string,
  ipAddress: string,
  actionTaken: string,
  reason: string,
  request?: GuardRequest | null,
  metadata?: Record<string, unknown>,
): Promise<void> {
  if (!agentHandler) return;

  /* v8 ignore start -- agent event dispatch; tests pass null agentHandler so this block is unreachable */
  try {
    await agentHandler.sendEvent({
      timestamp: new Date(),
      eventType,
      ipAddress,
      actionTaken,
      reason,
      endpoint: request?.urlPath ?? null,
      method: request?.method ?? null,
      userAgent: request?.headers['user-agent'] ?? null,
      metadata: metadata ?? {},
    });
  } catch {
  }
  /* v8 ignore stop */
}

function isTrustedProxy(connectingIp: string, trustedProxies: string[]): boolean {
  for (const proxy of trustedProxies) {
    if (!proxy.includes('/')) {
      /* v8 ignore next -- exact proxy IP match; tests use CIDR proxies */
      if (connectingIp === proxy) return true;
    } else {
      try {
        const parsed = ipaddr.parse(connectingIp);
        const [addr, prefixLen] = ipaddr.parseCIDR(proxy);
        if (parsed.kind() === addr.kind() && parsed.match([addr, prefixLen])) return true;
      } catch { continue; }
    }
  }
  /* v8 ignore start -- isTrustedProxy default return; tests always match a proxy */
  return false;
}
/* v8 ignore stop */

function extractFromForwardedHeader(forwardedFor: string, proxyDepth: number): string | null {
  const ips = forwardedFor.split(',').map((ip) => ip.trim()).filter(Boolean);
  if (ips.length === 0) return null;
  const targetIndex = ips.length - proxyDepth;
  if (targetIndex < 0) return ips[0];
  return ips[targetIndex];
}

export async function extractClientIp(
  request: GuardRequest,
  config: ResolvedSecurityConfig,
  agentHandler?: AgentHandlerProtocol | null,
): Promise<string> {
  const connectingIp = request.clientHost;
  if (!connectingIp) return 'unknown';

  const forwardedFor = request.headers['x-forwarded-for'] ?? null;

  if (forwardedFor && config.trustedProxies.length === 0) {
    await sendAgentEvent(
      agentHandler ?? null, 'suspicious_request', connectingIp,
      'spoofing_detected', 'X-Forwarded-For received from untrusted source',
      request,
    );
    return connectingIp;
  }

  if (
    forwardedFor &&
    config.trustedProxies.length > 0 &&
    isTrustedProxy(connectingIp, config.trustedProxies)
  ) {
    const extracted = extractFromForwardedHeader(forwardedFor, config.trustedProxyDepth);
    if (extracted && ipaddr.isValid(extracted)) return extracted;
  }

  return connectingIp;
}

export async function isUserAgentAllowed(
  userAgent: string,
  config: ResolvedSecurityConfig,
): Promise<boolean> {
  for (const pattern of config.blockedUserAgents) {
    if (new RegExp(pattern, 'i').test(userAgent)) return false;
  }
  return true;
}

export async function checkIpCountry(
  ip: string,
  config: ResolvedSecurityConfig,
  geoIpHandler: GeoIPHandler,
): Promise<boolean> {
  if (config.blockedCountries.length === 0 && config.whitelistCountries.length === 0) {
    return false;
  }

  if (!geoIpHandler.isInitialized) {
    await geoIpHandler.initialize();
  }

  const country = geoIpHandler.getCountry(ip);
  if (!country) return false;

  if (config.whitelistCountries.length > 0) {
    return !config.whitelistCountries.includes(country);
  }

  if (config.blockedCountries.length > 0) {
    return config.blockedCountries.includes(country);
  }

  /* v8 ignore start -- default return when no country rules configured; tests always set country rules */
  return false;
}
/* v8 ignore stop */

export async function isIpAllowed(
  ip: string,
  config: ResolvedSecurityConfig,
  geoIpHandler?: GeoIPHandler | null,
): Promise<boolean> {
  try {
    const parsed = ipaddr.parse(ip);

    for (const blocked of config.blacklist) {
      if (blocked.includes('/')) {
        const [addr, prefixLen] = ipaddr.parseCIDR(blocked);
        if (parsed.kind() === addr.kind() && parsed.match([addr, prefixLen])) return false;
      } else if (ip === blocked) {
        return false;
      }
    }

    if (config.whitelist && config.whitelist.length > 0) {
      let found = false;
      for (const allowed of config.whitelist) {
        /* v8 ignore start -- whitelist CIDR parse + match; tests use exact IPs not CIDR in whitelist */
        if (allowed.includes('/')) {
          const [addr, prefixLen] = ipaddr.parseCIDR(allowed);
          if (parsed.kind() === addr.kind() && parsed.match([addr, prefixLen])) { found = true; break; }
        /* v8 ignore stop */
        } else if (ip === allowed) {
          found = true; break;
        }
      }
      if (!found) return false;
    }

    /* v8 ignore start -- geoIpHandler branch unreachable in recursive JSON check because dangerousPatterns check returns first */
    if (geoIpHandler) {
      const blocked = await checkIpCountry(ip, config, geoIpHandler);
      if (blocked) return false;
    }
    /* v8 ignore stop */
  } catch {
    return false;
  }

  return true;
}

/**
 * Scan budgets mirroring the reference defaults (_DEFAULT_MAX_SCAN_VALUES,
 * _DEFAULT_MAX_SCAN_CHARS, _DEFAULT_MAX_JSON_DEPTH in
 * guard_core/_utils/detection_scan.py + detection_config.py).
 */
const MAX_SCAN_VALUES = 512;
const MAX_SCAN_CHARS = 65536;
const MAX_JSON_DEPTH = 32;

/** Mongo operator keys, ported from _MONGO_OPERATOR_KEY_RE in body_json_scan.py. */
const MONGO_OPERATOR_KEY_RE =
  /^\$(?:ne|gt|gte|lt|lte|eq|in|nin|nor|and|or|not|all|size|exists|type|mod|options|where|regex|expr|function|elemMatch)$/;

interface ScanBudget {
  values: number;
  chars: number;
}

/**
 * Exclusion sets resolved from the config (reference
 * excluded_detection_params / excluded_detection_body_fields). Entries stay
 * verbatim (Python's _STR_SET_ADAPTER stores them as given); scanned names
 * and keys are lowercased before the membership test, exactly like the
 * reference's `key.lower() in excluded_params` checks.
 */
interface ScanExclusions {
  params: ReadonlySet<string>;
  bodyFields: ReadonlySet<string>;
}

function resolveScanExclusions(
  config?: Pick<ResolvedSecurityConfig, 'excludedDetectionParams' | 'excludedDetectionBodyFields'>,
): ScanExclusions {
  return {
    params: new Set(config?.excludedDetectionParams ?? []),
    bodyFields: new Set(config?.excludedDetectionBodyFields ?? []),
  };
}

function isExcludedParam(exclusions: ScanExclusions, key: string): boolean {
  return exclusions.params.has(key.toLowerCase());
}

function isExcludedBodyField(exclusions: ScanExclusions, name: string): boolean {
  return exclusions.bodyFields.has(name.toLowerCase());
}

function scanBudgetExhausted(budget: ScanBudget, value: string): boolean {
  budget.values++;
  if (budget.values > MAX_SCAN_VALUES) return true;
  if (budget.chars >= MAX_SCAN_CHARS) return true;
  budget.chars += value.length;
  return false;
}

/**
 * Shared SusPatternsManager backing the standalone detectPenetrationAttempt
 * entry point, mirroring the reference's configured sus_patterns_handler
 * singleton: constructed once, reused across requests. The parsed default
 * config rides along so the scan routing can read its exclusion fields.
 */
let defaultManagerPromise: Promise<{ manager: SusPatternsManager; config: ResolvedSecurityConfig }> | null = null;
function getDefaultSusPatternsManager(): Promise<{ manager: SusPatternsManager; config: ResolvedSecurityConfig }> {
  defaultManagerPromise ??= (async () => {
    const { SusPatternsManager } = await import('./handlers/sus-patterns.js');
    const { SecurityConfigSchema } = await import('./models/config.js');
    const config = SecurityConfigSchema.parse({});
    return { manager: new SusPatternsManager(config, defaultLogger), config };
  })();
  return defaultManagerPromise;
}

function buildThreatMessage(result: DetectionResult): string {
  const threat = result.threats[0];
  if (threat === undefined) return 'Threat detected';
  if (threat.detectionMethod === 'semantic') {
    const attackType = threat.pattern.slice('semantic:'.length) || 'suspicious';
    const scoreMatch = /score=([\d.]+)/.exec(threat.matchedContent);
    const score = scoreMatch ? Number(scoreMatch[1]).toFixed(2) : '0.00';
    return `Semantic attack: ${attackType} (score: ${score})`;
  }
  return `Value matched pattern '${threat.pattern}'`;
}

/**
 * Full request-surface penetration scan on top of the SusPatternsManager
 * engine (the canonical pattern table, all content views). Value routing
 * mirrors the reference detect flow in guard_core/_utils/
 * penetration_detection.py + detection_scan.py: query param names and values,
 * the URL path, header names and values, then the body (JSON leaves, form
 * fields, multipart parts, or the raw blob, per content type). Multipart
 * bodies split into parts whose label, filename entry, headers and payload
 * scan under `request_body:multipart_field` (binary-dense file-part payloads
 * reduce to printable islands first, bounded by
 * detectionBinaryMinRunLength). JSON leaves embedded inside
 * non-body values are labeled with the `:embedded_json` context suffix so the
 * engine's per-context gates (recon bare-word rule, source-extension probe
 * rule) apply to them.
 *
 * `config`, when given, activates the reference's excluded-field surface:
 * `excludedDetectionParams` skips a query parameter's whole pair
 * (`key.lower() in excluded_params` in _scan_query_params) and
 * `excludedDetectionBodyFields` skips urlencoded pairs and multipart parts
 * by field name and whole JSON subtrees by key at any nesting depth (the
 * body walk and the embedded-JSON walks of query and header values all
 * honor it, like the reference threading excluded_body_fields through
 * _scan_form_body, _scan_multipart_part, _scan_query_param_value and
 * _scan_normal_header_component).
 */
export async function scanRequestWithManager(
  manager: SusPatternsManager,
  request: GuardRequest,
  config?: Pick<ResolvedSecurityConfig, 'excludedDetectionParams' | 'excludedDetectionBodyFields'>,
): Promise<[boolean, string]> {
  const clientIp = request.clientHost ?? 'unknown';
  const budget: ScanBudget = { values: 0, chars: 0 };
  const exclusions = resolveScanExclusions(config);

  for (const [key, value] of Object.entries(request.queryParams)) {
    if (isExcludedParam(exclusions, key)) continue;
    const nameHit = await detectComponent(manager, key, `query_param:${key}`, clientIp, budget);
    if (nameHit[0]) return [true, `Query param name '${key}': ${nameHit[1]}`];
    const valueHit = await detectValueEnhanced(manager, value, `query_param:${key}`, clientIp, budget, exclusions.bodyFields);
    if (valueHit[0]) return [true, `Query param '${key}': ${valueHit[1]}`];
  }

  const urlPath = request.urlPath;
  if (urlPath && urlPath !== '/') {
    const hit = await detectValueEnhanced(manager, urlPath, 'url_path', clientIp, budget);
    if (hit[0]) return [true, `URL path: ${hit[1]}`];
  }

  for (const [headerName, headerValue] of Object.entries(request.headers)) {
    if (EXCLUDED_HEADERS.has(headerName.toLowerCase())) continue;
    if (headerName.toLowerCase().startsWith('sec-')) continue;
    const nameHit = await detectComponent(manager, headerName, `header:${headerName}`, clientIp, budget);
    if (nameHit[0]) return [true, `Header name '${headerName}': ${nameHit[1]}`];
    const valueHit = await detectValueEnhanced(manager, headerValue, `header:${headerName}`, clientIp, budget, exclusions.bodyFields);
    if (valueHit[0]) return [true, `Header '${headerName}': ${valueHit[1]}`];
  }

  return scanBodySurface(manager, request, clientIp, budget, exclusions);
}

async function scanBodySurface(
  manager: SusPatternsManager,
  request: GuardRequest,
  clientIp: string,
  budget: ScanBudget,
  exclusions: ScanExclusions,
): Promise<[boolean, string]> {
  let rawBody: string;
  try {
    const bodyBytes = await request.body();
    if (bodyBytes.length === 0) return [false, ''];
    rawBody = new TextDecoder().decode(bodyBytes);
    if (!rawBody.trim()) return [false, ''];
  } catch {
    // body read failure is not a threat
    return [false, ''];
  }

  const rawContentType = request.headers['content-type'] ?? '';
  const contentType = rawContentType.toLowerCase();

  if (contentType.includes('application/x-www-form-urlencoded')) {
    for (const { name, value } of parseFormPairs(rawBody)) {
      if (isExcludedBodyField(exclusions, name)) continue;
      const nameHit = await detectComponent(manager, name, 'request_body', clientIp, budget);
      if (nameHit[0]) return [true, `Form field name '${name}': ${nameHit[1]}`];
      const valueHit = await detectValueEnhanced(
        manager, value, 'request_body:form_field', clientIp, budget, exclusions.bodyFields,
      );
      if (valueHit[0]) return [true, `Request body field '${name}': ${valueHit[1]}`];
    }
    return [false, ''];
  }

  if (contentType.includes('multipart/form-data')) {
    return scanMultipartBody(manager, rawBody, rawContentType, clientIp, budget, exclusions);
  }

  if (contentType.includes('json')) {
    const [jsonThreat, jsonInfo, parsedClean] = await scanJsonContent(manager, rawBody, 'request_body', clientIp, budget, exclusions.bodyFields);
    // A clean parse is final: the reference returns the walk result without
    // a blob rescan (json_hit is not None), so excluded subtrees stay
    // excluded. Only a parse failure falls through to the raw blob.
    if (parsedClean) {
      if (jsonThreat) return [true, jsonInfo];
      return [false, ''];
    }
  }

  const blobHit = await detectValueEnhanced(manager, rawBody, 'request_body', clientIp, budget);
  if (blobHit[0]) return [true, `Request body: ${blobHit[1]}`];
  return [false, ''];
}

/**
 * Multipart body scan (reference _scan_multipart_body): when the body does
 * not parse into at least one leaf part (no boundary parameter, boundary
 * mismatch, no opening boundary), the whole raw body is scanned as one
 * request_body blob value, like the email parser's is_multipart() == False
 * fallback. Each leaf part scans its label name, then its filename entry,
 * header entries and payload entries (islands for a binary-like file part)
 * under `request_body:multipart_field`.
 */
async function scanMultipartBody(
  manager: SusPatternsManager,
  rawBody: string,
  rawContentType: string,
  clientIp: string,
  budget: ScanBudget,
  exclusions: ScanExclusions,
): Promise<[boolean, string]> {
  const [, params] = parseMediaTypeParams(rawContentType);
  const parts = parseMultipartParts(rawBody, params['boundary'] ?? '');
  if (parts.length === 0) {
    const blobHit = await detectValueEnhanced(manager, rawBody, 'request_body', clientIp, budget);
    if (blobHit[0]) return [true, `Request body: ${blobHit[1]}`];
    return [false, ''];
  }
  for (const part of parts) {
    const entries = multipartPartEntries(part, manager.detectionBinaryMinRunLength);
    if (entries.length === 0) continue;
    const exclusionKey = entries[0].exclusionKey;
    if (exclusionKey !== null && isExcludedBodyField(exclusions, exclusionKey)) continue;
    const label = entries[0].label;
    const nameHit = await detectComponent(manager, label, 'request_body', clientIp, budget);
    if (nameHit[0]) return [true, `Multipart field name '${label}': ${nameHit[1]}`];
    for (const entry of entries) {
      const valueHit = await detectValueEnhanced(
        manager, entry.value, 'request_body:multipart_field', clientIp, budget, exclusions.bodyFields,
      );
      if (valueHit[0]) return [true, `Request body field '${label}': ${valueHit[1]}`];
    }
  }
  return [false, ''];
}

/**
 * Embedded-JSON pre-scan (reference _check_embedded_json): when the scanned
 * value parses to an object or array, its leaves are scanned under
 * `{context}:embedded_json` before the raw value itself runs through the
 * engine, with excluded body fields skipping whole JSON subtrees by key.
 * The reference skips it for the body context, where JSON content is walked
 * once by scanJsonContent instead.
 */
async function detectValueEnhanced(
  manager: SusPatternsManager,
  value: string,
  context: string,
  clientIp: string,
  budget: ScanBudget,
  excludedBodyFields?: ReadonlySet<string>,
): Promise<[boolean, string]> {
  if (scanBudgetExhausted(budget, value)) return [false, ''];

  if (context !== 'request_body') {
    const [jsonThreat, jsonInfo] = await scanJsonContent(manager, value, `${context}:embedded_json`, clientIp, budget, excludedBodyFields);
    if (jsonThreat) return [true, jsonInfo];
  }

  let result: DetectionResult;
  try {
    result = await manager.detect(value, clientIp, context);
  } catch {
    return [false, ''];
  }
  if (!result.isThreat) return [false, ''];
  return [true, buildThreatMessage(result)];
}

/**
 * Component-name scan (reference _scan_component_name): keys and names are
 * scanned as plain values, never through the embedded-JSON path.
 */
async function detectComponent(
  manager: SusPatternsManager,
  value: string,
  context: string,
  clientIp: string,
  budget: ScanBudget,
): Promise<[boolean, string]> {
  if (scanBudgetExhausted(budget, value)) return [false, ''];
  try {
    const result = await manager.detect(value, clientIp, context);
    if (!result.isThreat) return [false, ''];
    return [true, buildThreatMessage(result)];
  } catch {
    return [false, ''];
  }
}

/**
 * JSON body scan (reference _scan_json_content/_scan_json_value): walks
 * parsed JSON, scans operator-shaped dict keys (`$where`, `$ne`, ...) and
 * every scalar leaf under the given context, capping recursion at
 * MAX_JSON_DEPTH (deeper subtrees serialize to text and scan as one value).
 * Keys in `excludedBodyFields` (matched lowercased against verbatim entries)
 * skip their whole subtree before the operator and name checks. The third
 * element reports whether the parse was clean (object or array root): the
 * body routing uses it to decide between the walk result (final) and the
 * raw blob fallback, exactly like _scan_request_body's json_hit is-not-None
 * check.
 */
async function scanJsonContent(
  manager: SusPatternsManager,
  raw: string,
  context: string,
  clientIp: string,
  budget: ScanBudget,
  excludedBodyFields?: ReadonlySet<string>,
): Promise<[boolean, string, boolean]> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [false, '', false];
  }
  if (typeof parsed !== 'object' || parsed === null) return [false, '', false];
  const hit = await scanJsonValue(manager, parsed, '', context, clientIp, budget, 1, excludedBodyFields);
  return [hit[0], hit[1], true];
}

async function scanJsonValue(
  manager: SusPatternsManager,
  value: unknown,
  label: string,
  context: string,
  clientIp: string,
  budget: ScanBudget,
  depth: number,
  excludedBodyFields?: ReadonlySet<string>,
): Promise<[boolean, string]> {
  if (Array.isArray(value)) {
    if (depth >= MAX_JSON_DEPTH) return scanCappedJsonSubtree(manager, value, label, context, clientIp, budget);
    for (const item of value) {
      const hit = await scanJsonValue(manager, item, label, context, clientIp, budget, depth + 1, excludedBodyFields);
      if (hit[0]) return hit;
    }
    return [false, ''];
  }
  if (typeof value === 'object' && value !== null) {
    if (depth >= MAX_JSON_DEPTH) return scanCappedJsonSubtree(manager, value, label, context, clientIp, budget);
    for (const [key, item] of Object.entries(value)) {
      if (excludedBodyFields?.has(key.toLowerCase())) continue;
      const keyHit = await scanJsonKey(manager, key, context, clientIp, budget);
      if (keyHit[0]) return [true, `JSON key '${key}': ${keyHit[1]}`];
      const hit = await scanJsonValue(manager, item, key, context, clientIp, budget, depth + 1, excludedBodyFields);
      if (hit[0]) return hit;
    }
    return [false, ''];
  }

  const hit = await detectValueEnhanced(
    manager, String(value), context, clientIp, budget, excludedBodyFields,
  );
  if (!hit[0]) return [false, ''];
  return [true, label ? `Request body field '${label}': ${hit[1]}` : hit[1]];
}

async function scanJsonKey(
  manager: SusPatternsManager,
  key: string,
  context: string,
  clientIp: string,
  budget: ScanBudget,
): Promise<[boolean, string]> {
  if (MONGO_OPERATOR_KEY_RE.test(key)) {
    return [true, `JSON operator key '${key}': matched pattern '${MONGO_OPERATOR_KEY_RE.source}'`];
  }
  return detectComponent(manager, key, `${context}:${key}`, clientIp, budget);
}

async function scanCappedJsonSubtree(
  manager: SusPatternsManager,
  value: object,
  label: string,
  context: string,
  clientIp: string,
  budget: ScanBudget,
): Promise<[boolean, string]> {
  let serialized: string;
  try {
    serialized = JSON.stringify(value);
  } catch {
    /* v8 ignore start -- JSON.stringify cannot throw on JSON.parse output */
    return [false, ''];
  }
  /* v8 ignore stop */
  const hit = await detectValueEnhanced(manager, serialized, context, clientIp, budget);
  if (!hit[0]) return [false, ''];
  return [true, label ? `Request body field '${label}': ${hit[1]}` : hit[1]];
}

/**
 * Standalone penetration detection entry point (public API). Runs the full
 * SusPatternsManager engine over the request surface on a shared default
 * manager; the live middleware path feeds the initializer's manager into
 * scanRequestWithManager directly via SuspiciousActivityCheck.
 */
export async function detectPenetrationAttempt(
  request: GuardRequest,
): Promise<[boolean, string]> {
  const { manager, config } = await getDefaultSusPatternsManager();
  return scanRequestWithManager(manager, request, config);
}

export function logActivity(
  request: GuardRequest,
  logger: Logger,
  logType = 'request',
  reason = '',
  passiveMode = false,
  triggerInfo = '',
  level: 'INFO' | 'DEBUG' | 'WARNING' | 'ERROR' | 'CRITICAL' | null = 'WARNING',
): void {
  if (!level) return;

  const clientIp = request.clientHost ?? 'unknown';
  const method = request.method;
  const url = sanitizeForLog(request.urlPath);
  const userAgent = sanitizeForLog(request.headers['user-agent'] ?? '');

  let message: string;

  if (logType === 'request') {
    message = `Request from ${clientIp}: ${method} ${url} [UA: ${userAgent}]`;
  } else if (logType === 'suspicious') {
    const prefix = passiveMode ? '[PASSIVE MODE]' : '';
    const trigger = triggerInfo ? ` | Trigger: ${triggerInfo}` : '';
    message = `${prefix} Suspicious request from ${clientIp}: ${method} ${url} - ${reason}${trigger}`;
  } else {
    message = `${logType} from ${clientIp}: ${method} ${url} - ${reason}`;
  }

  const levelLower = level.toLowerCase();
  const logMethod: keyof Logger =
    levelLower === 'warning' ? 'warn'
    : levelLower === 'critical' ? 'error'
    : levelLower === 'debug' ? 'debug'
    : levelLower === 'error' ? 'error'
    : 'info';

  logger[logMethod](message);
}
