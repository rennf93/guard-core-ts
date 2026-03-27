import type { Request, Response, NextFunction } from 'express';
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
import { ExpressGuardRequest, ExpressResponseFactory, sendGuardResponse } from './adapters.js';

export interface SecurityMiddlewareOptions {
  config: SecurityConfig;
  agentHandler?: AgentHandlerProtocol;
  geoIpHandler?: GeoIPHandler;
  guardDecorator?: unknown;
}

export function createSecurityMiddleware(options: SecurityMiddlewareOptions) {
  const resolved = SecurityConfigSchema.parse(options.config);
  const logger: Logger = resolved.logger ?? defaultLogger;
  const responseFactory = new ExpressResponseFactory();

  let initialized = false;
  let components: SecurityMiddlewareComponents;

  async function initialize(): Promise<void> {
    if (initialized) return;
    components = await initializeSecurityMiddleware(
      resolved, logger, responseFactory,
      options.agentHandler, options.geoIpHandler, options.guardDecorator,
    );
    initialized = true;
    logger.info('Guard security middleware initialized');
  }

  return async function guardMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
    await initialize();

    const startTime = performance.now();
    const guardReq = new ExpressGuardRequest(req);

    const passthrough = await components.bypassHandler.handlePassthrough(
      guardReq,
      async () => createPassthroughResponse(),
    );
    if (passthrough) {
      sendGuardResponse(res, passthrough);
      return;
    }

    const routeConfig = components.routeResolver.getRouteConfig(guardReq);

    const bypass = await components.bypassHandler.handleSecurityBypass(
      guardReq,
      async () => createPassthroughResponse(),
      routeConfig,
    );
    if (bypass) {
      sendGuardResponse(res, bypass);
      return;
    }

    const blockResponse = await components.pipeline.execute(guardReq);
    if (blockResponse) {
      sendGuardResponse(res, blockResponse);
      return;
    }

    if (routeConfig && routeConfig.behaviorRules.length > 0) {
      const clientIp = guardReq.clientHost ?? 'unknown';
      await components.behavioralProcessor.processUsageRules(guardReq, clientIp, routeConfig);
    }

    const originalEnd = res.end;
    const chunks: Buffer[] = [];

    res.end = function (chunk: unknown, ...args: unknown[]): Response {
      if (chunk) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));

      const responseTime = (performance.now() - startTime) / 1000;
      const body = Buffer.concat(chunks);
      const capturedResponse: GuardResponse = {
        statusCode: res.statusCode,
        headers: Object.fromEntries(
          Object.entries(res.getHeaders()).map(([k, v]) => [k, String(v)]),
        ),
        setHeader(name: string, value: string) { res.setHeader(name, value); },
        body: new Uint8Array(body),
        bodyText: body.toString('utf-8'),
      };

      components.errorResponseFactory.processResponse(
        guardReq, capturedResponse, responseTime, routeConfig ?? null,
        routeConfig ? async (request: GuardRequest, response: GuardResponse, clientIp: string, rc: RouteConfig) => {
          await components.behavioralProcessor.processReturnRules(request, response, clientIp, rc);
        } : undefined,
      ).catch(() => {});

      return originalEnd.apply(res, [chunk, ...args] as Parameters<typeof originalEnd>);
    };

    next();
  };
}

function createPassthroughResponse(): GuardResponse {
  return {
    statusCode: 200,
    headers: {},
    setHeader() {},
    body: null,
    bodyText: null,
  };
}
