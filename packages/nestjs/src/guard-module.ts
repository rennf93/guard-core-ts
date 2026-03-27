import { DynamicModule, Module, Inject, Injectable, NestMiddleware, MiddlewareConsumer } from '@nestjs/common';
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
import { NestGuardRequest, NestResponseFactory } from './adapters.js';

export const GUARD_MIDDLEWARE_TOKEN = Symbol('GUARD_MIDDLEWARE_COMPONENTS');

export interface GuardModuleOptions {
  config: SecurityConfig;
  agentHandler?: AgentHandlerProtocol;
  geoIpHandler?: GeoIPHandler;
  guardDecorator?: unknown;
}

@Injectable()
export class SecurityMiddlewareNest implements NestMiddleware {
  constructor(
    @Inject(GUARD_MIDDLEWARE_TOKEN) private readonly components: SecurityMiddlewareComponents,
  ) {}

  async use(req: Request, res: Response, next: NextFunction): Promise<void> {
    const startTime = performance.now();
    const guardReq = new NestGuardRequest(req);

    const passthrough = await this.components.bypassHandler.handlePassthrough(
      guardReq, async () => createPassthroughResponse(),
    );
    if (passthrough) {
      sendNestResponse(res, passthrough);
      return;
    }

    const routeConfig = this.components.routeResolver.getRouteConfig(guardReq);

    const bypass = await this.components.bypassHandler.handleSecurityBypass(
      guardReq, async () => createPassthroughResponse(), routeConfig,
    );
    if (bypass) {
      sendNestResponse(res, bypass);
      return;
    }

    const blockResponse = await this.components.pipeline.execute(guardReq);
    if (blockResponse) {
      sendNestResponse(res, blockResponse);
      return;
    }

    if (routeConfig && routeConfig.behaviorRules.length > 0) {
      const clientIp = guardReq.clientHost ?? 'unknown';
      await this.components.behavioralProcessor.processUsageRules(guardReq, clientIp, routeConfig);
    }

    (req as unknown as Record<string, unknown>)['_guardRequest'] = guardReq;
    (req as unknown as Record<string, unknown>)['_guardRouteConfig'] = routeConfig;
    (req as unknown as Record<string, unknown>)['_guardStartTime'] = startTime;

    next();
  }
}

@Module({})
export class GuardModule {
  static forRoot(options: GuardModuleOptions): DynamicModule {
    return {
      module: GuardModule,
      providers: [
        {
          provide: GUARD_MIDDLEWARE_TOKEN,
          useFactory: async () => {
            const resolved = SecurityConfigSchema.parse(options.config);
            const logger: Logger = resolved.logger ?? defaultLogger;
            const responseFactory = new NestResponseFactory();
            const components = await initializeSecurityMiddleware(
              resolved, logger, responseFactory,
              options.agentHandler, options.geoIpHandler, options.guardDecorator,
            );
            logger.info('Guard security module initialized');
            return components;
          },
        },
        SecurityMiddlewareNest,
      ],
      exports: [SecurityMiddlewareNest, GUARD_MIDDLEWARE_TOKEN],
      global: true,
    };
  }

  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(SecurityMiddlewareNest).forRoutes('*');
  }
}

function sendNestResponse(res: Response, response: GuardResponse): void {
  for (const [name, value] of Object.entries(response.headers)) {
    res.setHeader(name, value);
  }
  if (response.headers['location']) {
    res.redirect(response.statusCode, response.headers['location']);
    return;
  }
  res.status(response.statusCode).json({ detail: response.bodyText });
}

function createPassthroughResponse(): GuardResponse {
  return { statusCode: 200, headers: {}, setHeader() {}, body: null, bodyText: null };
}
