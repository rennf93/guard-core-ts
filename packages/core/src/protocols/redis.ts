export interface RedisHandlerProtocol {
  getKey(namespace: string, key: string): Promise<unknown>;
  setKey(namespace: string, key: string, value: unknown, ttl?: number | null): Promise<boolean | null>;
  delete(namespace: string, key: string): Promise<number | null>;
  keys(pattern: string): Promise<string[] | null>;
  initialize(): Promise<void>;
  getConnection(): AsyncDisposable;
}
