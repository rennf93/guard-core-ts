import type { FastifyInstance, FastifyReply } from 'fastify';
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
import { FastifyGuardRequest, FastifyResponseFactory } from './adapters.js';

export interface GuardPluginOptions {
  config: SecurityConfig;
  agentHandler?: AgentHandlerProtocol;
  geoIpHandler?: GeoIPHandler;
  guardDecorator?: unknown;
}

export async function guardPlugin(fastify: FastifyInstance, options: GuardPluginOptions): Promise<void> {
  const resolved = SecurityConfigSchema.parse(options.config);
  const logger: Logger = resolved.logger ?? defaultLogger;
  const responseFactory = new FastifyResponseFactory();

  const components: SecurityMiddlewareComponents = await initializeSecurityMiddleware(
    resolved, logger, responseFactory,
    options.agentHandler, options.geoIpHandler, options.guardDecorator,
  );

  logger.info('Guard security plugin initialized');

  fastify.addHook('onRequest', async (request, reply) => {
    const guardReq = new FastifyGuardRequest(request);

    const passthrough = await components.bypassHandler.handlePassthrough(
      guardReq, async () => createPassthroughResponse(),
    );
    if (passthrough) {
      sendFastifyResponse(reply, passthrough);
      return;
    }

    const routeConfig = components.routeResolver.getRouteConfig(guardReq);

    const bypass = await components.bypassHandler.handleSecurityBypass(
      guardReq, async () => createPassthroughResponse(), routeConfig,
    );
    if (bypass) {
      sendFastifyResponse(reply, bypass);
      return;
    }

    const blockResponse = await components.pipeline.execute(guardReq);
    if (blockResponse) {
      sendFastifyResponse(reply, blockResponse);
      return;
    }

    if (routeConfig && routeConfig.behaviorRules.length > 0) {
      const clientIp = guardReq.clientHost ?? 'unknown';
      await components.behavioralProcessor.processUsageRules(guardReq, clientIp, routeConfig);
    }

    (request as unknown as Record<string, unknown>)['_guardRequest'] = guardReq;
    (request as unknown as Record<string, unknown>)['_guardRouteConfig'] = routeConfig;
    (request as unknown as Record<string, unknown>)['_guardStartTime'] = performance.now();
  });

  fastify.addHook('onSend', async (request, reply, payload) => {
    const guardReq = (request as unknown as Record<string, unknown>)['_guardRequest'] as FastifyGuardRequest | undefined;
    const routeConfig = (request as unknown as Record<string, unknown>)['_guardRouteConfig'] as RouteConfig | null | undefined;
    const startTime = (request as unknown as Record<string, unknown>)['_guardStartTime'] as number | undefined;

    if (!guardReq || startTime === undefined) return payload;

    const responseTime = (performance.now() - startTime) / 1000;
    const bodyText = typeof payload === 'string' ? payload : null;
    const capturedResponse: GuardResponse = {
      statusCode: reply.statusCode,
      headers: Object.fromEntries(
        Object.entries(reply.getHeaders()).map(([k, v]) => [k, String(v)]),
      ),
      setHeader(name: string, value: string) { reply.header(name, value); },
      body: bodyText ? new TextEncoder().encode(bodyText) : null,
      bodyText,
    };

    await components.errorResponseFactory.processResponse(
      guardReq, capturedResponse, responseTime, routeConfig ?? null,
      routeConfig ? async (req: GuardRequest, res: GuardResponse, clientIp: string, rc: RouteConfig) => {
        await components.behavioralProcessor.processReturnRules(req, res, clientIp, rc);
      } : undefined,
    );

    return payload;
  });
}

function sendFastifyResponse(reply: FastifyReply, response: GuardResponse): void {
  for (const [name, value] of Object.entries(response.headers)) {
    reply.header(name, value);
  }

  if (response.headers['location']) {
    reply.redirect(response.statusCode, response.headers['location']);
    return;
  }

  reply.status(response.statusCode).send(response.bodyText ?? '');
}

function createPassthroughResponse(): GuardResponse {
  return { statusCode: 200, headers: {}, setHeader() {}, body: null, bodyText: null };
}
