import { BaseSecurityDecorator, getRouteDecoratorConfig } from './base.js';
import { AccessControl } from './access-control.js';
import { RateLimiting } from './rate-limiting.js';
import { Authentication } from './authentication.js';
import { ContentFiltering } from './content-filtering.js';
import { Behavioral } from './behavioral.js';
import { Advanced } from './advanced.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- TS mixin composition requires any[]
export const SecurityDecorator = Advanced(
  ContentFiltering(
    Behavioral(
      Authentication(
        RateLimiting(
          AccessControl(
            BaseSecurityDecorator as unknown as new (...args: any[]) => BaseSecurityDecorator,
          ),
        ),
      ),
    ),
  ),
);

export type SecurityDecorator = InstanceType<typeof SecurityDecorator>;

export { BaseSecurityDecorator, getRouteDecoratorConfig };
