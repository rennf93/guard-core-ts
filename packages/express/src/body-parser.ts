import type { Request, Response, NextFunction } from 'express';
import express from 'express';

export function guardBodyParser() {
  return express.json({
    verify: (req: Request, _res: Response, buf: Buffer, _encoding: string) => {
      (req as unknown as Record<string, unknown>)['rawBody'] = buf;
    },
  });
}

export function guardUrlEncodedParser() {
  return express.urlencoded({
    extended: true,
    verify: (req: Request, _res: Response, buf: Buffer, _encoding: string) => {
      (req as unknown as Record<string, unknown>)['rawBody'] = buf;
    },
  });
}
