import type { Context, MiddlewareHandler } from 'hono';
import type {
  SecurityConfig,
  GuardRequest,
  GuardResponse,
  Logger,
  AgentHandlerProtocol,
  GeoIPHandler,
  SecurityMiddlewareComponents,
  RouteConfig,
} from '@guardcore/core';
import { SecurityConfigSchema, defaultLogger, initializeSecurityMiddleware } from '@guardcore/core';
import { HonoGuardRequest, HonoResponseFactory } from './adapters.js';

export interface GuardMiddlewareOptions {
  config: SecurityConfig;
  agentHandler?: AgentHandlerProtocol;
  geoIpHandler?: GeoIPHandler;
  guardDecorator?: unknown;
}

export function createGuardMiddleware(options: GuardMiddlewareOptions): MiddlewareHandler {
  const resolved = SecurityConfigSchema.parse(options.config);
  const logger: Logger = resolved.logger ?? defaultLogger;
  const responseFactory = new HonoResponseFactory();

  let initialized = false;
  let components: SecurityMiddlewareComponents;

  return async (c: Context, next) => {
    if (!initialized) {
      components = await initializeSecurityMiddleware(
        resolved, logger, responseFactory,
        options.agentHandler, options.geoIpHandler, options.guardDecorator,
      );
      initialized = true;
      logger.info('Guard security middleware initialized');
    }

    const startTime = performance.now();
    const connectingIp = (c.env as Record<string, unknown> | undefined)?.['remoteAddr'] as string | undefined ?? null;
    const guardReq = new HonoGuardRequest(c.req, connectingIp);

    const passthrough = await components.bypassHandler.handlePassthrough(
      guardReq, async () => createPassthroughResponse(),
    );
    if (passthrough) return sendHonoResponse(c, passthrough);

    const routeConfig = components.routeResolver.getRouteConfig(guardReq);

    const bypass = await components.bypassHandler.handleSecurityBypass(
      guardReq, async () => createPassthroughResponse(), routeConfig,
    );
    if (bypass) return sendHonoResponse(c, bypass);

    const blockResponse = await components.pipeline.execute(guardReq);
    if (blockResponse) return sendHonoResponse(c, blockResponse);

    if (routeConfig && routeConfig.behaviorRules.length > 0) {
      const clientIp = guardReq.clientHost ?? 'unknown';
      await components.behavioralProcessor.processUsageRules(guardReq, clientIp, routeConfig);
    }

    await next();

    const responseTime = (performance.now() - startTime) / 1000;
    const capturedResponse: GuardResponse = {
      statusCode: c.res.status,
      headers: Object.fromEntries(c.res.headers.entries()),
      setHeader(name: string, value: string) { c.res.headers.set(name, value); },
      body: null,
      bodyText: null,
    };

    await components.errorResponseFactory.processResponse(
      guardReq, capturedResponse, responseTime, routeConfig ?? null,
      routeConfig ? async (req: GuardRequest, res: GuardResponse, clientIp: string, rc: RouteConfig) => {
        await components.behavioralProcessor.processReturnRules(req, res, clientIp, rc);
      } : undefined,
    );
  };
}

function sendHonoResponse(c: Context, response: GuardResponse): Response {
  for (const [name, value] of Object.entries(response.headers)) {
    c.header(name, value);
  }

  if (response.headers['location']) {
    return c.redirect(response.headers['location'], response.statusCode as 301 | 302);
  }

  return c.json(
    { detail: response.bodyText },
    response.statusCode as Parameters<typeof c.json>[1],
  );
}

function createPassthroughResponse(): GuardResponse {
  return { statusCode: 200, headers: {}, setHeader() {}, body: null, bodyText: null };
}
