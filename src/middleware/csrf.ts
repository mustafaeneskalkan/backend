import type { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { CSRF_COOKIE_NAME, getCsrfCookieOptions } from '../utils/cookies.js';

const CSRF_HEADER_NAME = 'x-xsrf-token';

function base64Url(bytes: Buffer): string {
  return bytes
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function generateCsrfToken(): string {
  return base64Url(crypto.randomBytes(32));
}

function getHeaderToken(req: Request): string | undefined {
  const headerValue = req.headers[CSRF_HEADER_NAME];
  if (typeof headerValue === 'string' && headerValue.trim().length > 0) return headerValue;
  if (Array.isArray(headerValue) && typeof headerValue[0] === 'string' && headerValue[0].trim().length > 0) {
    return headerValue[0];
  }
  return undefined;
}

export const issueCsrfToken = (req: Request, res: Response): void => {
  const token = generateCsrfToken();
  res.cookie(CSRF_COOKIE_NAME, token, getCsrfCookieOptions());
  res.json({ csrfToken: token });
};

export const requireCsrf = (req: Request, res: Response, next: NextFunction): void => {
  const method = req.method.toUpperCase();
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    next();
    return;
  }

  const cookieToken = (req as any).cookies?.[CSRF_COOKIE_NAME] as string | undefined;
  const headerToken = getHeaderToken(req);

  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    res.status(403).json({
      error: 'Invalid CSRF token',
      code: 'CSRF_INVALID'
    });
    return;
  }

  next();
};
