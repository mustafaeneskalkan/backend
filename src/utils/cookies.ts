import type { CookieOptions, Response } from 'express';

type SameSite = 'lax' | 'strict' | 'none';

export const CSRF_COOKIE_NAME = process.env.CSRF_COOKIE_NAME || 'XSRF-TOKEN';
export const ACCESS_TOKEN_COOKIE_NAME = process.env.ACCESS_TOKEN_COOKIE_NAME || 'accessToken';
export const REFRESH_TOKEN_COOKIE_NAME = process.env.REFRESH_TOKEN_COOKIE_NAME || 'refreshToken';
export const SESSION_ID_COOKIE_NAME = process.env.SESSION_ID_COOKIE_NAME || 'sessionId';

function getSameSite(): SameSite {
  const envDefault = (process.env.NODE_ENV || 'development') === 'production' ? 'strict' : 'lax';
  const raw = (process.env.COOKIE_SAME_SITE || envDefault).toLowerCase();
  if (raw === 'strict' || raw === 'none' || raw === 'lax') return raw;
  return envDefault as SameSite;
}

function getSecure(): boolean {
  const raw = process.env.COOKIE_SECURE;
  if (raw === undefined) return (process.env.NODE_ENV || 'development') === 'production';
  return raw === 'true';
}

function getDomain(): string | undefined {
  const domain = process.env.COOKIE_DOMAIN;
  return domain && domain.trim().length > 0 ? domain.trim() : undefined;
}

export function getCsrfCookieOptions(): CookieOptions {
  return {
    httpOnly: false,
    sameSite: getSameSite(),
    secure: getSecure(),
    domain: getDomain(),
    path: '/',
  };
}

export function getAuthCookieOptions(maxAgeMs: number, path = '/'): CookieOptions {
  return {
    httpOnly: true,
    sameSite: getSameSite(),
    secure: getSecure(),
    domain: getDomain(),
    path,
    maxAge: maxAgeMs,
  };
}

export function clearAuthCookies(res: Response): void {
  // Must match cookie paths used when setting cookies
  res.clearCookie(ACCESS_TOKEN_COOKIE_NAME, { path: '/' });
  res.clearCookie(REFRESH_TOKEN_COOKIE_NAME, { path: '/api/users' });
  res.clearCookie(SESSION_ID_COOKIE_NAME, { path: '/api/users' });
}
