export interface GuardRequestState {
  guardRouteId?: string;
  guardEndpointId?: string;
  guardDecorator?: unknown;
  [key: string]: unknown;
}

export interface GuardRequest {
  readonly urlPath: string;
  readonly urlScheme: string;
  readonly urlFull: string;
  urlReplaceScheme(scheme: string): string;
  readonly method: string;
  readonly clientHost: string | null;
  readonly headers: Readonly<Record<string, string>>;
  readonly queryParams: Readonly<Record<string, string>>;
  body(): Promise<Uint8Array>;
  readonly state: GuardRequestState;
  readonly scope: Readonly<Record<string, unknown>>;
}
