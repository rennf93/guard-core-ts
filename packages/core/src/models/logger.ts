export interface Logger {
  info(message: string, ...args: unknown[]): void;
  warn(message: string, ...args: unknown[]): void;
  error(message: string, ...args: unknown[]): void;
  debug(message: string, ...args: unknown[]): void;
}

export const defaultLogger: Logger = {
  info: (msg, ...args) => console.info(`[guard-core] ${msg}`, ...args),
  warn: (msg, ...args) => console.warn(`[guard-core] ${msg}`, ...args),
  error: (msg, ...args) => console.error(`[guard-core] ${msg}`, ...args),
  debug: (msg, ...args) => console.debug(`[guard-core] ${msg}`, ...args),
};
