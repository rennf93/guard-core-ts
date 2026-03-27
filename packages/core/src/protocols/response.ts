export interface GuardResponse {
  readonly statusCode: number;
  readonly headers: Record<string, string>;
  setHeader(name: string, value: string): void;
  readonly body: Uint8Array | null;
  readonly bodyText: string | null;
}

export interface GuardResponseFactory {
  createResponse(content: string, statusCode: number): GuardResponse;
  createRedirectResponse(url: string, statusCode: number): GuardResponse;
}
