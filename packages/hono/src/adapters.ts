import type { HonoRequest } from 'hono';
import type { GuardRequest, GuardRequestState, GuardResponse, GuardResponseFactory } from '@guardcore/core';

export class HonoGuardRequest implements GuardRequest {
  private _state: GuardRequestState = {};
  private _url: URL;

  constructor(private readonly req: HonoRequest, private readonly connectingIp: string | null) {
    this._url = new URL(req.url);
  }

  get urlPath(): string { return this._url.pathname; }
  get urlScheme(): string { return this._url.protocol.replace(':', ''); }
  get urlFull(): string { return this.req.url; }
  urlReplaceScheme(scheme: string): string { return this.urlFull.replace(/^https?/, scheme); }
  get method(): string { return this.req.method; }
  get clientHost(): string | null { return this.connectingIp; }
  get headers(): Readonly<Record<string, string>> { return Object.fromEntries(this.req.raw.headers.entries()); }
  get queryParams(): Readonly<Record<string, string>> { return Object.fromEntries(this._url.searchParams.entries()); }
  async body(): Promise<Uint8Array> { return new Uint8Array(await this.req.arrayBuffer()); }
  get state(): GuardRequestState { return this._state; }
  get scope(): Readonly<Record<string, unknown>> { return {}; }
}

export class HonoGuardResponse implements GuardResponse {
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

export class HonoResponseFactory implements GuardResponseFactory {
  createResponse(content: string, statusCode: number): GuardResponse {
    return new HonoGuardResponse(statusCode, JSON.stringify({ detail: content }));
  }

  createRedirectResponse(url: string, statusCode: number): GuardResponse {
    const resp = new HonoGuardResponse(statusCode, '');
    resp.setHeader('location', url);
    return resp;
  }
}
