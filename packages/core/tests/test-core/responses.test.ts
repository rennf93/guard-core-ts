import { describe, it, expect, vi } from 'vitest';
import { ErrorResponseFactory } from '../../src/core/responses/factory.js';
import { MetricsCollector } from '../../src/core/events/metrics.js';
import { SecurityHeadersManager } from '../../src/handlers/security-headers.js';
import { RouteConfig } from '../../src/models/route-config.js';
import { createTestConfig, createMockRequest, createMockResponse, createMockResponseFactory } from '../helpers.js';
import { defaultLogger } from '../../src/models/logger.js';

function createFactory(configOverrides: Record<string, unknown> = {}) {
  const config = createTestConfig(configOverrides);
  const metricsCollector = new MetricsCollector(null, config, defaultLogger);
  const responseFactory = createMockResponseFactory();
  const headersManager = new SecurityHeadersManager(defaultLogger);

  return new ErrorResponseFactory(
    config, defaultLogger, metricsCollector,
    responseFactory, headersManager,
  );
}

describe('ErrorResponseFactory', () => {
  it('creates error response with default message', async () => {
    const factory = createFactory();
    const response = await factory.createErrorResponse(403, 'Forbidden');
    expect(response.statusCode).toBe(403);
    expect(response.bodyText).toContain('Forbidden');
  });

  it('uses custom error response when configured', async () => {
    const factory = createFactory({ customErrorResponses: { 403: 'Access denied by policy' } });
    const response = await factory.createErrorResponse(403, 'Forbidden');
    expect(response.bodyText).toContain('Access denied by policy');
  });

  it('applies security headers to error response', async () => {
    const factory = createFactory();
    const response = await factory.createErrorResponse(403, 'Forbidden');
    expect(response.headers['X-Content-Type-Options']).toBe('nosniff');
  });

  it('creates HTTPS redirect', async () => {
    const factory = createFactory();
    const request = createMockRequest({ urlScheme: 'http' });
    const response = await factory.createHttpsRedirect(request);
    expect(response.statusCode).toBe(301);
    expect(response.headers['location']).toContain('https://');
  });

  it('applies custom response modifier', async () => {
    const modifier = vi.fn().mockImplementation(async (res) => {
      res.setHeader('x-modified', 'true');
      return res;
    });
    const factory = createFactory({ customResponseModifier: modifier });
    const response = await factory.createErrorResponse(403, 'Forbidden');
    expect(modifier).toHaveBeenCalled();
  });

  it('applies CORS headers when origin present', async () => {
    const factory = createFactory({ enableCors: true, corsAllowOrigins: ['https://example.com'] });
    const request = createMockRequest({ headers: { origin: 'https://example.com', 'user-agent': 'Test' } });
    const response = await factory.createErrorResponse(200, 'ok');
    await factory.processResponse(request, response, 0.1, null);
  });

  it('processResponse collects metrics', async () => {
    const factory = createFactory();
    const request = createMockRequest();
    const response = await factory.createErrorResponse(200, 'ok');
    const result = await factory.processResponse(request, response, 0.1, null);
    expect(result).toBeDefined();
  });

  it('applies security headers when headersConfig enabled', async () => {
    const config = createTestConfig();
    const metrics = new MetricsCollector(null, config, defaultLogger);
    const headers = new SecurityHeadersManager(defaultLogger);
    const factory = new ErrorResponseFactory(config, defaultLogger, metrics, createMockResponseFactory(), headers);

    const response = await factory.createErrorResponse(403, 'Forbidden');
    expect(response.headers['X-Content-Type-Options']).toBe('nosniff');
  });

  it('applies CORS headers to error response when origin present', async () => {
    const config = createTestConfig({ enableCors: true, corsAllowOrigins: ['*'] });
    const metrics = new MetricsCollector(null, config, defaultLogger);
    const headers = new SecurityHeadersManager(defaultLogger);
    headers.configure({ corsOrigins: ['*'] });
    const factory = new ErrorResponseFactory(config, defaultLogger, metrics, createMockResponseFactory(), headers);

    const req = createMockRequest({ headers: { origin: 'https://test.com', 'user-agent': 'T' } });
    const resp = await factory.createErrorResponse(200, 'ok');
    const result = await factory.processResponse(req, resp, 0.1, null);
    expect(result).toBeDefined();
  });

  it('processResponse with behavioral rules callback', async () => {
    const config = createTestConfig();
    const metrics = new MetricsCollector(null, config, defaultLogger);
    const headers = new SecurityHeadersManager(defaultLogger);
    const factory = new ErrorResponseFactory(config, defaultLogger, metrics, createMockResponseFactory(), headers);

    const rc = new RouteConfig();
    rc.behaviorRules = [{ ruleType: 'usage' as const, threshold: 5, window: 3600, pattern: null, action: 'log' as const, customAction: null }];
    const callback = vi.fn();
    const req = createMockRequest();
    const resp = createMockResponse(200, 'ok');

    await factory.processResponse(req, resp, 0.1, rc, callback);
    expect(callback).toHaveBeenCalled();
  });

  it('applies custom response modifier', async () => {
    const modifier = vi.fn().mockImplementation(async (r: unknown) => r);
    const config = createTestConfig({ customResponseModifier: modifier });
    const metrics = new MetricsCollector(null, config, defaultLogger);
    const headers = new SecurityHeadersManager(defaultLogger);
    const factory = new ErrorResponseFactory(config, defaultLogger, metrics, createMockResponseFactory(), headers);

    await factory.createErrorResponse(403, 'test');
    expect(modifier).toHaveBeenCalled();
  });

  it('applies CORS when origin header present in processResponse', async () => {
    const config = createTestConfig({ enableCors: true, corsAllowOrigins: ['*'] });
    const metrics = new MetricsCollector(null, config, defaultLogger);
    const headers = new SecurityHeadersManager(defaultLogger);
    headers.configure({ corsOrigins: ['*'] });
    const guardFactory = {
      createResponse: (c: string, s: number) => createMockResponse(s, c),
      createRedirectResponse: (u: string, s: number) => createMockResponse(s),
    };
    const factory = new ErrorResponseFactory(config, defaultLogger, metrics, guardFactory, headers);
    const req = createMockRequest({ headers: { origin: 'https://app.com', 'user-agent': 'T' } });
    const resp = createMockResponse(200, 'ok');
    await factory.processResponse(req, resp, 0.1, null);
  });
});
