import type { Request, Response } from 'express';
import type { GuardRequest, GuardRequestState, GuardResponse, GuardResponseFactory } from '@guardcore/core';

export class ExpressGuardRequest implements GuardRequest {
  private _state: GuardRequestState = {};
  private rawBody: Uint8Array | null = null;

  constructor(private readonly req: Request) {
    const raw = (req as unknown as Record<string, unknown>)['rawBody'];
    if (raw instanceof Uint8Array) {
      this.rawBody = raw;
    } else if (raw instanceof Buffer) {
      this.rawBody = new Uint8Array(raw);
    }
  }

  get urlPath(): string { return this.req.path; }
  get urlScheme(): string { return this.req.protocol; }
  get urlFull(): string { return `${this.req.protocol}://${this.req.get('host')}${this.req.originalUrl}`; }
  urlReplaceScheme(scheme: string): string { return this.urlFull.replace(/^https?/, scheme); }
  get method(): string { return this.req.method; }
  get clientHost(): string | null { return this.req.socket.remoteAddress ?? null; }
  get headers(): Readonly<Record<string, string>> { return this.req.headers as Record<string, string>; }
  get queryParams(): Readonly<Record<string, string>> { return this.req.query as Record<string, string>; }
  async body(): Promise<Uint8Array> { return this.rawBody ?? new Uint8Array(0); }
  get state(): GuardRequestState { return this._state; }
  get scope(): Readonly<Record<string, unknown>> { return {}; }
}

export class ExpressGuardResponse implements GuardResponse {
  private _headers: Record<string, string> = {};
  private _body: Uint8Array | null;

  constructor(
    readonly statusCode: number,
    content: string,
  ) {
    this._body = new TextEncoder().encode(content);
    this._headers['content-type'] = 'application/json';
  }

  get headers(): Record<string, string> { return this._headers; }
  setHeader(name: string, value: string): void { this._headers[name] = value; }
  get body(): Uint8Array | null { return this._body; }
  get bodyText(): string | null {
    return this._body ? new TextDecoder().decode(this._body) : null;
  }
}

export class ExpressResponseFactory implements GuardResponseFactory {
  createResponse(content: string, statusCode: number): GuardResponse {
    return new ExpressGuardResponse(statusCode, JSON.stringify({ detail: content }));
  }

  createRedirectResponse(url: string, statusCode: number): GuardResponse {
    const resp = new ExpressGuardResponse(statusCode, '');
    resp.setHeader('location', url);
    return resp;
  }
}

export function sendGuardResponse(res: Response, guardResponse: GuardResponse): void {
  for (const [name, value] of Object.entries(guardResponse.headers)) {
    res.setHeader(name, value);
  }

  if (guardResponse.headers['location']) {
    res.redirect(guardResponse.statusCode, guardResponse.headers['location']);
    return;
  }

  res.status(guardResponse.statusCode);
  if (guardResponse.body) {
    res.send(Buffer.from(guardResponse.body));
  } else {
    res.end();
  }
}
