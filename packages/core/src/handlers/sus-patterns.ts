import type { ResolvedSecurityConfig } from '../models/config.js';
import type { Logger } from '../models/logger.js';
import { ContentPreprocessor } from '../detection-engine/preprocessor.js';
import { PatternCompiler } from '../detection-engine/compiler.js';
import { PerformanceMonitor } from '../detection-engine/monitor.js';
import { SemanticAnalyzer } from '../detection-engine/semantic.js';
import type { AgentHandlerProtocol } from '../protocols/agent.js';
import type { RedisManager } from './redis.js';

const CTX_XSS: ReadonlySet<string> = new Set(['query_param', 'header', 'request_body', 'unknown']);
const CTX_SQLI: ReadonlySet<string> = new Set(['query_param', 'request_body', 'unknown']);
const CTX_DIR_TRAVERSAL: ReadonlySet<string> = new Set(['url_path', 'query_param', 'request_body', 'unknown']);
const CTX_CMD_INJECTION: ReadonlySet<string> = new Set(['query_param', 'request_body', 'unknown']);
const CTX_FILE_INCLUSION: ReadonlySet<string> = new Set(['url_path', 'query_param', 'request_body', 'unknown']);
const CTX_LDAP: ReadonlySet<string> = new Set(['query_param', 'request_body', 'unknown']);
const CTX_XML: ReadonlySet<string> = new Set(['header', 'request_body', 'unknown']);
const CTX_SSRF: ReadonlySet<string> = new Set(['query_param', 'request_body', 'unknown']);
const CTX_NOSQL: ReadonlySet<string> = new Set(['query_param', 'request_body', 'unknown']);
const CTX_FILE_UPLOAD: ReadonlySet<string> = new Set(['header', 'request_body', 'unknown']);
const CTX_PATH_TRAVERSAL: ReadonlySet<string> = new Set(['url_path', 'query_param', 'request_body', 'unknown']);
const CTX_TEMPLATE: ReadonlySet<string> = new Set(['query_param', 'request_body', 'unknown']);
const CTX_HTTP_SPLIT: ReadonlySet<string> = new Set(['header', 'query_param', 'request_body', 'unknown']);
const CTX_SENSITIVE_FILE: ReadonlySet<string> = new Set(['url_path', 'request_body', 'unknown']);
const CTX_CMS_PROBING: ReadonlySet<string> = new Set(['url_path', 'request_body', 'unknown']);
const CTX_RECON: ReadonlySet<string> = new Set(['url_path', 'unknown']);
const CTX_ALL: ReadonlySet<string> = new Set(['query_param', 'header', 'url_path', 'request_body', 'unknown']);

const KNOWN_CONTEXTS = new Set(['query_param', 'header', 'url_path', 'request_body', 'unknown']);

const PATTERN_DEFINITIONS: Array<[string, ReadonlySet<string>]> = [
  [String.raw`<script[^>]*>[^<]*<\/script\s*>`, CTX_XSS],
  [String.raw`javascript:\s*[^\s]+`, CTX_XSS],
  [String.raw`(?:on(?:error|load|click|mouseover|submit|mouse|unload|change|focus|blur|drag))=(?:["'][^"']*["']|[^\s>]+)`, CTX_XSS],
  [String.raw`(?:<[^>]+\s+(?:href|src|data|action)\s*=[\s"']*(?:javascript|vbscript|data):)`, CTX_XSS],
  [String.raw`(?:<[^>]+style\s*=[\s"']*[^>"']*(?:expression|behavior|url)\s*\([^)]*\))`, CTX_XSS],
  [String.raw`(?:<object[^>]*>[\s\S]*<\/object\s*>)`, CTX_XSS],
  [String.raw`(?:<embed[^>]*>[\s\S]*<\/embed\s*>)`, CTX_XSS],
  [String.raw`(?:<applet[^>]*>[\s\S]*<\/applet\s*>)`, CTX_XSS],
  [String.raw`SELECT\s+[\w\s,*]+\s+FROM\s+[\w\s._]+`, CTX_SQLI],
  [String.raw`UNION\s+(?:ALL\s+)?SELECT`, CTX_SQLI],
  [String.raw`('\s*(?:OR|AND)\s*[(\s]*'?[\d\w]+\s*(?:=|LIKE|<|>|<=|>=)\s*[(\s]*'?[\d\w]+)`, CTX_SQLI],
  [String.raw`(UNION\s+(?:ALL\s+)?SELECT\s+(?:NULL[,\s]*)+|\(\s*SELECT\s+(?:@@|VERSION))`, CTX_SQLI],
  [String.raw`(?:INTO\s+(?:OUTFILE|DUMPFILE)\s+'[^']+')`, CTX_SQLI],
  [String.raw`(?:LOAD_FILE\s*\([^)]+\))`, CTX_SQLI],
  [String.raw`(?:BENCHMARK\s*\(\s*\d+\s*,)`, CTX_SQLI],
  [String.raw`(?:SLEEP\s*\(\s*\d+\s*\))`, CTX_SQLI],
  [String.raw`(?:\/\*![0-9]*\s*(?:OR|AND|UNION|SELECT|INSERT|DELETE|DROP|CONCAT|CHAR|UPDATE)\b)`, CTX_SQLI],
  [String.raw`(?:\.\.\/|\.\.\\)(?:\.\.\/|\.\.\\)+`, CTX_DIR_TRAVERSAL],
  [String.raw`(?:/etc/(?:passwd|shadow|group|hosts|motd|issue|mysql/my.cnf|ssh/ssh_config)$)`, CTX_DIR_TRAVERSAL],
  [String.raw`(?:boot\.ini|win\.ini|system\.ini|config\.sys)\s*$`, CTX_DIR_TRAVERSAL],
  [String.raw`(?:\/proc\/self\/environ$)`, CTX_DIR_TRAVERSAL],
  [String.raw`(?:\/var\/log\/[^/]+$)`, CTX_DIR_TRAVERSAL],
  [String.raw`;\s*(?:ls|cat|rm|chmod|chown|wget|curl|nc|netcat|ping|telnet)\s+-[a-zA-Z]+\s+`, CTX_CMD_INJECTION],
  [String.raw`\|\s*(?:wget|curl|fetch|lwp-download|lynx|links|GET)\s+`, CTX_CMD_INJECTION],
  [String.raw`(?:[;&|` + '`' + String.raw`]\s*(?:\$\([^)]+\)|\$\{[^}]+\}))`, CTX_CMD_INJECTION],
  [String.raw`(?:^|;)\s*(?:bash|sh|ksh|csh|tsch|zsh|ash)\s+-[a-zA-Z]+`, CTX_CMD_INJECTION],
  [String.raw`\b(?:eval|system|exec|shell_exec|passthru|popen|proc_open)\s*\(`, CTX_CMD_INJECTION],
  [String.raw`(?:php|data|zip|rar|file|glob|expect|input|phpinfo|zlib|phar|ssh2|rar|ogg|expect)://[^\s]+`, CTX_FILE_INCLUSION],
  [String.raw`(?:\/\/[0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*(:[0-9]+)?(?:\/?)?(?:[a-zA-Z0-9\-.,?'/\\+&amp;%$#_]*)?)`, CTX_FILE_INCLUSION],
  [String.raw`\(\s*[|&]\s*\(\s*[^)]+=[*]`, CTX_LDAP],
  [String.raw`(?:\*(?:[\s\d\w]+\s*=|=\s*[\d\w\s]+))`, CTX_LDAP],
  [String.raw`(?:\(\s*[&|]\s*)`, CTX_LDAP],
  [String.raw`<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>`, CTX_XML],
  [String.raw`(?:<!\[CDATA\[.*?\]\]>)`, CTX_XML],
  [String.raw`(?:<\?xml.*?\?>)`, CTX_XML],
  [String.raw`(?:^|\s|/)(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::(?:\d*)\]|(?:169\.254|192\.168|10\.|172\.(?:1[6-9]|2[0-9]|3[01]))\.\d+)(?:\s|$|/)`, CTX_SSRF],
  [String.raw`(?:file|dict|gopher|jar|tftp)://[^\s]+`, CTX_SSRF],
  [String.raw`\{\s*\$(?:where|gt|lt|ne|eq|regex|in|nin|all|size|exists|type|mod|options):`, CTX_NOSQL],
  [String.raw`(?:\{\s*\$[a-zA-Z]+\s*:\s*(?:\{|\[))`, CTX_NOSQL],
  [String.raw`filename=["'].*?\.(?:php\d*|phar|phtml|exe|jsp|asp|aspx|sh|bash|rb|py|pl|cgi|com|bat|cmd|vbs|vbe|js|ws|wsf|msi|hta)["']`, CTX_FILE_UPLOAD],
  [String.raw`(?:%2e%2e|%252e%252e|%uff0e%uff0e|%c0%ae%c0%ae|%e0%40%ae|%c0%ae%e0%80%ae|%25c0%25ae)/`, CTX_PATH_TRAVERSAL],
  [String.raw`\{\{\s*[^}]+(?:system|exec|popen|eval|require|include)\s*\}\}`, CTX_TEMPLATE],
  [String.raw`\{%\s*[^%]+(?:system|exec|popen|eval|require|include)\s*%\}`, CTX_TEMPLATE],
  [String.raw`[\r\n]\s*(?:HTTP\/[0-9.]+|Location:|Set-Cookie:)`, CTX_HTTP_SPLIT],
  [String.raw`(?:^|/)\.env(?:\.\w+)?(?:\?|$|/)`, CTX_SENSITIVE_FILE],
  [String.raw`(?:^|/)[\w-]*config[\w-]*\.(?:env|yml|yaml|json|toml|ini|xml|conf)(?:\?|$)`, CTX_SENSITIVE_FILE],
  [String.raw`(?:^|/)[\w./-]*\.map(?:\?|$)`, CTX_SENSITIVE_FILE],
  [String.raw`(?:^|/)[\w./-]*\.(?:ts|tsx|jsx|py|rb|java|go|rs|php|pl|sh|sql)(?:\?|$)`, CTX_SENSITIVE_FILE],
  [String.raw`(?:^|/)\.(?:git|svn|hg|bzr)(?:/|$)`, CTX_SENSITIVE_FILE],
  [String.raw`(?:^|/)(?:wp-(?:admin|login|content|includes|config)|administrator|xmlrpc)\.?(?:php)?(?:/|$|\?)`, CTX_CMS_PROBING],
  [String.raw`(?:^|/)(?:phpinfo|info|test|php_info)\.php(?:\?|$)`, CTX_CMS_PROBING],
  [String.raw`(?:^|/)[\w./-]*\.(?:bak|backup|old|orig|save|swp|swo|tmp|temp)(?:\?|$)`, CTX_CMS_PROBING],
  [String.raw`(?:^|/)(?:\.htaccess|\.htpasswd|\.DS_Store|Thumbs\.db|\.npmrc|\.dockerenv|web\.config)(?:\?|$)`, CTX_CMS_PROBING],
  [String.raw`(?:^|/)[\w./-]*\.(?:asp|aspx|jsp|jsa|jhtml|shtml|cfm|cgi|do|action|lua|inc|woa|nsf|esp|html?|js|css|properties|png|gif|jpg|jpeg|svg|webp|bmp|pl)(?:\?|$)`, CTX_RECON],
  [String.raw`^/(?:api|rest|v\d+|management|system|version|status|config|config_dump|credentials)(?:/|$|\?)`, CTX_RECON],
  [String.raw`^/admin(?:istrator)?(?:[./?\-]|$)`, CTX_RECON],
  [String.raw`^/(?:login|logon|signin)(?:[./?\-]|$|/)`, CTX_RECON],
  [String.raw`(?:^|/)account/login(?:\?|$|/)`, CTX_RECON],
  [String.raw`(?:^|/)(?:actuator|server-status|telescope)(?:/|$|\?)`, CTX_RECON],
  [String.raw`(?:CSCOE|dana-(?:na|cached)|sslvpn|RDWeb|/owa/|/ecp/|global-protect|ssl-vpn/|svpn/|sonicui|/remote/login|myvpn|vpntunnel|versa/login)`, CTX_RECON],
  [String.raw`(?:^|/)(?:geoserver|confluence|nifi|ScadaBR|pandora_console|centreon|kylin|decisioncenter|evox|MagicInfo|metasys|officescan|helpdesk|ignite)(?:/|$|\?|\.|\-)`, CTX_RECON],
  [String.raw`(?:^|/)cgi-(?:bin|mod)/`, CTX_RECON],
  [String.raw`(?:^|/)(?:HNAP1|IPCamDesc\.xml|SDK/webLanguage)(?:\?|$|/)`, CTX_RECON],
  [String.raw`^/(?:scripts|language|languages|images|css|img)/`, CTX_RECON],
  [String.raw`(?:^|/)(?:robots\.txt|sitemap\.xml|security\.txt|readme\.txt|README\.md|CHANGELOG|pom\.xml|build\.gradle|appsettings\.json|crossdomain\.xml)(?:\?|$|\.)`, CTX_RECON],
  [String.raw`(?:^|/)(?:sap|ise|nidp|cslu|rustfs|developmentserver|fog/management|lms/db|json/login_session|sms_mp|plugin/webs_model|wsman|am_bin)(?:/|$|\?)`, CTX_RECON],
  [String.raw`(?:nmaplowercheck|nice\s+ports|Trinity\.txt)`, CTX_RECON],
  [String.raw`(?:^|/)\.(?:openclaw|clawdbot)(?:/|$)`, CTX_RECON],
  [String.raw`^/(?:default|inicio|indice|localstart)(?:\.|/|$|\?)`, CTX_RECON],
  [String.raw`(?:^|/)(?:\.streamlit|\.gpt-pilot|\.aider|\.cursor|\.windsurf|\.copilot|\.devcontainer)(?:/|$)`, CTX_RECON],
  [String.raw`(?:^|/)(?:docker-compose|Dockerfile|Makefile|Vagrantfile|Jenkinsfile|Procfile)(?:\.ya?ml)?(?:\?|$)`, CTX_RECON],
  [String.raw`(?:^|/)[\w./-]*(?:secrets?|credentials?)\.(?:py|json|yml|yaml|toml|txt|env|xml|conf|cfg)(?:\?|$)`, CTX_RECON],
  [String.raw`(?:^|/)autodiscover/`, CTX_RECON],
  [String.raw`^/dns-query(?:\?|$)`, CTX_RECON],
  [String.raw`(?:^|/)\.git/(?:refs|index|HEAD|objects|logs)(?:/|$)`, CTX_RECON],
];

export interface DetectionResult {
  isThreat: boolean;
  threatScore: number;
  threats: Array<{
    pattern: string;
    context: string;
    matchedContent: string;
    detectionMethod: string;
  }>;
  executionTime: number;
  timeouts: string[];
  correlationId: string | null;
  originalLength: number;
  processedLength: number;
}

export class SusPatternsManager {
  private compiler: PatternCompiler;
  private preprocessor: ContentPreprocessor;
  private semantic: SemanticAnalyzer;
  private monitor: PerformanceMonitor;
  private customPatterns = new Set<string>();
  private compiledCustomContexts = new Map<string, ReadonlySet<string>>();
  private redisHandler: RedisManager | null = null;
  private agentHandler: AgentHandlerProtocol | null = null;
  private semanticThreshold: number;

  constructor(
    config: ResolvedSecurityConfig,
    private readonly logger: Logger,
  ) {
    this.compiler = new PatternCompiler(config.detectionCompilerTimeout * 1000, config.detectionMaxTrackedPatterns);
    this.preprocessor = new ContentPreprocessor(config.detectionMaxContentLength, config.detectionPreserveAttackPatterns);
    this.semantic = new SemanticAnalyzer();
    this.monitor = new PerformanceMonitor(
      config.detectionAnomalyThreshold,
      config.detectionSlowPatternThreshold,
      config.detectionMonitorHistorySize,
      config.detectionMaxTrackedPatterns,
    );
    this.semanticThreshold = config.detectionSemanticThreshold;
  }

  async initializeRedis(redisHandler: RedisManager): Promise<void> {
    this.redisHandler = redisHandler;
    const cached = await redisHandler.getKey('patterns', 'custom');
    if (typeof cached === 'string' && cached.length > 0) {
      for (const p of cached.split(',')) {
        if (p.trim()) {
          this.customPatterns.add(p.trim());
          this.compiledCustomContexts.set(p.trim(), CTX_ALL);
        }
      }
    }
  }

  async initializeAgent(agentHandler: AgentHandlerProtocol): Promise<void> {
    this.agentHandler = agentHandler;
  }

  private normalizeContext(context: string): string {
    const parts = context.split(':');
    const normalized = parts[0].toLowerCase();
    return KNOWN_CONTEXTS.has(normalized) ? normalized : 'unknown';
  }

  async detect(
    content: string,
    ipAddress: string,
    context = 'unknown',
    correlationId: string | null = null,
  ): Promise<DetectionResult> {
    const startTime = performance.now();
    const originalLength = content.length;

    const processed = await this.preprocessor.preprocess(content);
    const normalizedCtx = this.normalizeContext(context);

    const threats: DetectionResult['threats'] = [];
    const timeouts: string[] = [];

    for (const [pattern, contexts] of PATTERN_DEFINITIONS) {
      if (!contexts.has(normalizedCtx)) continue;

      const patternStart = performance.now();
      try {
        const match = await this.compiler.safeMatch(pattern, processed);
        const elapsed = (performance.now() - patternStart) / 1000;

        await this.monitor.recordMetric(pattern, elapsed, processed.length, match !== null, false, this.agentHandler, correlationId);

        if (match) {
          threats.push({
            pattern,
            context: normalizedCtx,
            matchedContent: String(match[0] ?? '').slice(0, 200),
            detectionMethod: 'regex',
          });
        }
      /* v8 ignore start -- custom pattern context check; requires pattern compiler to throw during safeMatch */
      } catch {
        timeouts.push(pattern);
        const elapsed = (performance.now() - patternStart) / 1000;
        await this.monitor.recordMetric(pattern, elapsed, processed.length, false, true, this.agentHandler, correlationId);
      }
      /* v8 ignore stop */
    }

    for (const customPattern of this.customPatterns) {
      const ctxSet = this.compiledCustomContexts.get(customPattern) ?? CTX_ALL;
      if (!ctxSet.has(normalizedCtx)) continue;

      try {
        const match = await this.compiler.safeMatch(customPattern, processed);
        if (match) {
          threats.push({
            pattern: customPattern,
            context: normalizedCtx,
            matchedContent: String(match[0] ?? '').slice(0, 200),
            detectionMethod: 'regex_custom',
          });
        }
      /* v8 ignore start -- custom pattern timeout catch; requires safeMatch to throw */
      } catch {
        timeouts.push(customPattern);
      }
      /* v8 ignore stop */
    }

    const analysis = this.semantic.analyze(processed);
    const semanticScore = this.semantic.getThreatScore(analysis);

    if (semanticScore >= this.semanticThreshold) {
      const topAttack = Object.entries(analysis.attackProbabilities)
        .sort(([, a], [, b]) => b - a)[0];
      if (topAttack) {
        threats.push({
          pattern: `semantic:${topAttack[0]}`,
          context: normalizedCtx,
          matchedContent: `score=${semanticScore.toFixed(3)}`,
          detectionMethod: 'semantic',
        });
      }
    }

    const regexScore = threats.some((t) => t.detectionMethod.startsWith('regex')) ? 1.0 : 0.0;
    const threatScore = Math.max(regexScore, semanticScore);

    const executionTime = (performance.now() - startTime) / 1000;

    return {
      isThreat: threats.length > 0,
      threatScore,
      threats,
      executionTime,
      timeouts,
      correlationId,
      originalLength,
      processedLength: processed.length,
    };
  }

  async detectPatternMatch(
    content: string,
    ipAddress: string,
    context = 'unknown',
    correlationId: string | null = null,
  ): Promise<[boolean, string | null]> {
    const result = await this.detect(content, ipAddress, context, correlationId);
    if (result.isThreat && result.threats.length > 0) {
      return [true, result.threats[0].pattern];
    }
    return [false, null];
  }

  async addPattern(pattern: string, custom = true): Promise<void> {
    this.customPatterns.add(pattern);
    this.compiledCustomContexts.set(pattern, CTX_ALL);

    if (custom && this.redisHandler) {
      await this.redisHandler.setKey('patterns', 'custom', [...this.customPatterns].join(','));
    }
  }

  async removePattern(pattern: string): Promise<void> {
    this.customPatterns.delete(pattern);
    this.compiledCustomContexts.delete(pattern);

    if (this.redisHandler) {
      await this.redisHandler.setKey('patterns', 'custom', [...this.customPatterns].join(','));
    }

    await this.compiler.clearCache();
    await this.monitor.removePatternStats(pattern);
  }

  getDefaultPatterns(): string[] {
    return PATTERN_DEFINITIONS.map(([p]) => p);
  }

  getCustomPatterns(): string[] {
    return [...this.customPatterns];
  }

  getAllPatterns(): string[] {
    return [...this.getDefaultPatterns(), ...this.getCustomPatterns()];
  }

  async getPerformanceStats(): Promise<Record<string, unknown> | null> {
    return {
      summary: this.monitor.getSummaryStats(),
      slowPatterns: this.monitor.getSlowPatterns(),
      problematicPatterns: this.monitor.getProblematicPatterns(),
    };
  }

  getComponentStatus(): Record<string, boolean> {
    return {
      compiler: true,
      preprocessor: true,
      semanticAnalyzer: true,
      performanceMonitor: true,
    };
  }

  async configureSemanticThreshold(threshold: number): Promise<void> {
    this.semanticThreshold = Math.max(0, Math.min(1, threshold));
  }

  async reset(): Promise<void> {
    this.customPatterns.clear();
    this.compiledCustomContexts.clear();
    this.agentHandler = null;
    await this.compiler.clearCache();
    await this.monitor.clearStats();
  }
}
