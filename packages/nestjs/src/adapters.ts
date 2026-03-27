import type { Request } from 'express';
import type { GuardRequest, GuardRequestState, GuardResponse, GuardResponseFactory } from '@guardcore/core';

export class NestGuardRequest implements GuardRequest {
  private _state: GuardRequestState = {};

  constructor(private readonly req: Request) {}

  get urlPath(): string { return this.req.path; }
  get urlScheme(): string { return this.req.protocol; }
  get urlFull(): string { return `${this.req.protocol}://${this.req.get('host')}${this.req.originalUrl}`; }
  urlReplaceScheme(scheme: string): string { return this.urlFull.replace(/^https?/, scheme); }
  get method(): string { return this.req.method; }
  get clientHost(): string | null { return this.req.socket.remoteAddress ?? null; }
  get headers(): Readonly<Record<string, string>> { return this.req.headers as Record<string, string>; }
  get queryParams(): Readonly<Record<string, string>> { return this.req.query as Record<string, string>; }
  async body(): Promise<Uint8Array> {
    const raw = (this.req as unknown as Record<string, unknown>)['rawBody'];
    if (raw instanceof Uint8Array) return raw;
    if (raw instanceof Buffer) return new Uint8Array(raw);
    return new Uint8Array(0);
  }
  get state(): GuardRequestState { return this._state; }
  get scope(): Readonly<Record<string, unknown>> { return {}; }
}

export class NestGuardResponse implements GuardResponse {
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

export class NestResponseFactory implements GuardResponseFactory {
  createResponse(content: string, statusCode: number): GuardResponse {
    return new NestGuardResponse(statusCode, JSON.stringify({ detail: content }));
  }

  createRedirectResponse(url: string, statusCode: number): GuardResponse {
    const resp = new NestGuardResponse(statusCode, '');
    resp.setHeader('location', url);
    return resp;
  }
}
