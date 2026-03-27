import * as ipaddr from 'ipaddr.js';
import { z } from 'zod';

import type { GeoIPHandler } from '../protocols/geo-ip.js';
import type { GuardRequest } from '../protocols/request.js';
import type { GuardResponse } from '../protocols/response.js';
import type { Logger } from './logger.js';

function isValidIpOrCidr(value: string): boolean {
  if (value.includes('/')) {
    try {
      ipaddr.parseCIDR(value);
      return true;
    } catch {
      return false;
    }
  }
  return ipaddr.isValid(value);
}

const VALID_CLOUD_PROVIDERS = ['AWS', 'GCP', 'Azure'] as const;

const IpOrCidrSchema = z.string().refine(isValidIpOrCidr, 'Invalid IP or CIDR');

const LogLevel = z.enum(['INFO', 'DEBUG', 'WARNING', 'ERROR', 'CRITICAL']);

export const SecurityConfigSchema = z.object({
  trustedProxies: z.array(IpOrCidrSchema).default([]),
  trustedProxyDepth: z.number().int().min(1).default(1),
  trustXForwardedProto: z.boolean().default(false),

  passiveMode: z.boolean().default(false),

  geoIpHandler: z.custom<GeoIPHandler>().optional(),
  geoResolver: z.custom<(ip: string) => string | null>().optional(),

  enableRedis: z.boolean().default(true),
  redisUrl: z.string().default('redis://localhost:6379'),
  redisPrefix: z.string().default('guard_core:'),

  whitelist: z.array(IpOrCidrSchema).nullable().default(null),
  blacklist: z.array(IpOrCidrSchema).default([]),

  whitelistCountries: z.array(z.string().length(2)).default([]),
  blockedCountries: z.array(z.string().length(2)).default([]),

  blockedUserAgents: z.array(z.string()).default([]),

  autoBanThreshold: z.number().int().positive().default(10),
  autoBanDuration: z.number().int().positive().default(3600),

  logger: z.custom<Logger>().optional(),
  customLogFile: z.string().nullable().default(null),
  logSuspiciousLevel: LogLevel.nullable().default('WARNING'),
  logRequestLevel: LogLevel.nullable().default(null),
  logFormat: z.enum(['text', 'json']).default('text'),

  customErrorResponses: z.record(z.coerce.number(), z.string()).default({}),

  rateLimit: z.number().int().positive().default(10),
  rateLimitWindow: z.number().int().positive().default(60),

  enforceHttps: z.boolean().default(false),

  securityHeaders: z.object({
    enabled: z.boolean().default(true),
    hsts: z.object({
      maxAge: z.number().default(31536000),
      includeSubdomains: z.boolean().default(true),
      preload: z.boolean().default(false),
    }).optional(),
    csp: z.record(z.string(), z.array(z.string())).nullable().default(null),
    frameOptions: z.enum(['DENY', 'SAMEORIGIN']).default('SAMEORIGIN'),
    contentTypeOptions: z.string().default('nosniff'),
    xssProtection: z.string().default('1; mode=block'),
    referrerPolicy: z.string().default('strict-origin-when-cross-origin'),
    permissionsPolicy: z.string().default('geolocation=(), microphone=(), camera=()'),
    custom: z.record(z.string(), z.string()).nullable().default(null),
  }).nullable().default({
    enabled: true,
    hsts: { maxAge: 31536000, includeSubdomains: true, preload: false },
    frameOptions: 'SAMEORIGIN',
    contentTypeOptions: 'nosniff',
    xssProtection: '1; mode=block',
    referrerPolicy: 'strict-origin-when-cross-origin',
    permissionsPolicy: 'geolocation=(), microphone=(), camera=()',
    csp: null,
    custom: null,
  }),

  customRequestCheck: z.custom<(req: GuardRequest) => Promise<GuardResponse | null>>().optional(),
  customResponseModifier: z.custom<(res: GuardResponse) => Promise<GuardResponse>>().optional(),

  enableCors: z.boolean().default(false),
  corsAllowOrigins: z.array(z.string()).default(['*']),
  corsAllowMethods: z.array(z.string()).default(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']),
  corsAllowHeaders: z.array(z.string()).default(['*']),
  corsAllowCredentials: z.boolean().default(false),
  corsExposeHeaders: z.array(z.string()).default([]),
  corsMaxAge: z.number().int().positive().default(600),

  blockCloudProviders: z
    .array(z.enum(VALID_CLOUD_PROVIDERS))
    .transform((arr) => new Set(arr))
    .default([]),
  cloudIpRefreshInterval: z.number().int().min(60).max(86400).default(3600),

  excludePaths: z.array(z.string()).default([]),

  enableIpBanning: z.boolean().default(true),
  enableRateLimiting: z.boolean().default(true),
  enablePenetrationDetection: z.boolean().default(true),

  emergencyMode: z.boolean().default(false),
  emergencyWhitelist: z.array(z.string()).default([]),

  endpointRateLimits: z.record(z.string(), z.tuple([z.number(), z.number()])).default({}),

  detectionCompilerTimeout: z.number().min(0.1).max(10).default(2.0),
  detectionMaxContentLength: z.number().int().min(1000).max(100000).default(10000),
  detectionPreserveAttackPatterns: z.boolean().default(true),
  detectionSemanticThreshold: z.number().min(0).max(1).default(0.7),
  detectionAnomalyThreshold: z.number().min(1).max(10).default(3.0),
  detectionSlowPatternThreshold: z.number().min(0.01).max(1).default(0.1),
  detectionMonitorHistorySize: z.number().int().min(100).max(10000).default(1000),
  detectionMaxTrackedPatterns: z.number().int().min(100).max(5000).default(1000),

  enableAgent: z.boolean().default(false),
  agentApiKey: z.string().nullable().default(null),
  agentEndpoint: z.string().url().default('https://api.fastapi-guard.com'),
  agentProjectId: z.string().nullable().default(null),
  agentBufferSize: z.number().int().positive().default(100),
  agentFlushInterval: z.number().int().positive().default(30),
  agentEnableEvents: z.boolean().default(true),
  agentEnableMetrics: z.boolean().default(true),
  agentTimeout: z.number().int().positive().default(30),
  agentRetryAttempts: z.number().int().nonnegative().default(3),

  enableDynamicRules: z.boolean().default(false),
  dynamicRuleInterval: z.number().int().positive().default(300),

}).superRefine((data, ctx) => {
  if (data.enableAgent && !data.agentApiKey) {
    ctx.addIssue({
      code: 'custom',
      message: 'agentApiKey is required when enableAgent is true',
      path: ['agentApiKey'],
    });
  }
  if (data.enableDynamicRules && !data.enableAgent) {
    ctx.addIssue({
      code: 'custom',
      message: 'enableAgent must be true when enableDynamicRules is true',
      path: ['enableDynamicRules'],
    });
  }
  if (
    (data.blockedCountries.length > 0 || data.whitelistCountries.length > 0) &&
    !data.geoIpHandler &&
    !data.geoResolver
  ) {
    ctx.addIssue({
      code: 'custom',
      message: 'geoIpHandler or geoResolver is required when using country filtering',
      path: ['geoIpHandler'],
    });
  }
});

export type SecurityConfig = z.input<typeof SecurityConfigSchema>;
export type ResolvedSecurityConfig = z.output<typeof SecurityConfigSchema>;
