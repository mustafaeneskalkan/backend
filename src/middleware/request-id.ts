import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

const HEADER_NAME = 'x-request-id';

function coerceHeaderValue(value: unknown): string | undefined {
  if (typeof value === 'string' && value.trim().length > 0) return value;
  if (Array.isArray(value) && typeof value[0] === 'string' && value[0].trim().length > 0) {
    return value[0];
  }
  return undefined;
}

export const requestIdMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  const incoming = coerceHeaderValue(req.headers[HEADER_NAME]);
  const requestId = incoming ?? crypto.randomUUID();

  req.requestId = requestId;
  req.headers[HEADER_NAME] = requestId;
  res.setHeader(HEADER_NAME, requestId);

  next();
};
