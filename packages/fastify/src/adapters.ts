import type { IncomingHttpHeaders } from 'http';
import type { FastifyRequest } from 'fastify';
import type { GuardRequest, GuardRequestState, GuardResponse, GuardResponseFactory } from '@guardcore/core';

function normalizeHeaders(headers: IncomingHttpHeaders): Record<string, string> {
  const normalized: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    normalized[name] = Array.isArray(value) ? value.join(', ') : String(value);
  }
  return normalized;
}

function normalizeQueryParams(query: Record<string, unknown> | undefined): Record<string, string> {
  const normalized: Record<string, string> = {};
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value === undefined || value === null) continue;
    if (typeof value === 'string') {
      normalized[key] = value;
    } else if (Array.isArray(value)) {
      normalized[key] = value.map((v) => String(v)).join(', ');
    } else if (typeof value === 'object') {
      normalized[key] = JSON.stringify(value);
    } else {
      normalized[key] = String(value);
    }
  }
  return normalized;
}

export class FastifyGuardRequest implements GuardRequest {
  private _state: GuardRequestState = {};
  private readonly _headers: Readonly<Record<string, string>>;
  private readonly _queryParams: Readonly<Record<string, string>>;

  constructor(private readonly req: FastifyRequest) {
    this._headers = normalizeHeaders(req.headers);
    this._queryParams = normalizeQueryParams(req.query as Record<string, unknown> | undefined);
  }

  get urlPath(): string { return this.req.url.split('?')[0]; }
  get urlScheme(): string { return this.req.protocol; }
  get urlFull(): string { return `${this.req.protocol}://${this.req.hostname}${this.req.url}`; }
  urlReplaceScheme(scheme: string): string { return this.urlFull.replace(/^https?/, scheme); }
  get method(): string { return this.req.method; }
  /* Spec 1.1: clientHost is the connecting peer IP. request.ip applies the
     framework's trustProxy forwarding, which would double-apply proxy logic the
     engine handles itself (trusted proxies, X-Forwarded-For depth). */
  get clientHost(): string | null {
    const rawSocket = this.req.raw?.socket;
    if (rawSocket?.remoteAddress) return rawSocket.remoteAddress;
    if (this.req.socket?.remoteAddress) return this.req.socket.remoteAddress;
    return this.req.ip ?? null;
  }
  get headers(): Readonly<Record<string, string>> { return this._headers; }
  get queryParams(): Readonly<Record<string, string>> { return this._queryParams; }
  async body(): Promise<Uint8Array> {
    const raw = this.req.body;
    if (raw instanceof Buffer) return new Uint8Array(raw);
    if (typeof raw === 'string') return new TextEncoder().encode(raw);
    if (raw !== undefined && raw !== null) return new TextEncoder().encode(JSON.stringify(raw));
    return new Uint8Array(0);
  }
  get state(): GuardRequestState { return this._state; }
  get scope(): Readonly<Record<string, unknown>> { return {}; }
}

export class FastifyGuardResponse implements GuardResponse {
  private _headers: Record<string, string> = {};
  private _body: Uint8Array | null;

  constructor(readonly statusCode: number, content: string) {
    this._body = new TextEncoder().encode(content);
    this._headers['content-type'] = 'application/json';
  }

  get headers(): Record<string, string> { return this._headers; }
  setHeader(name: string, value: string): void { this._headers[name] = value; }
  get body(): Uint8Array | null { return this._body; }
  get bodyText(): string | null { return this._body ? new TextDecoder().decode(this._body) : null; }
}

export class FastifyResponseFactory implements GuardResponseFactory {
  createResponse(content: string, statusCode: number): GuardResponse {
    return new FastifyGuardResponse(statusCode, JSON.stringify({ detail: content }));
  }

  createRedirectResponse(url: string, statusCode: number): GuardResponse {
    const resp = new FastifyGuardResponse(statusCode, '');
    resp.setHeader('location', url);
    return resp;
  }
}
