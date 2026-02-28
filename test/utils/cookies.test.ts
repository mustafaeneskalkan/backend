import type { Response } from 'express';
import { jest } from '@jest/globals';

describe('cookies utils', () => {
  it('clearAuthCookies clears expected cookie names and paths', async () => {
    const { clearAuthCookies, ACCESS_TOKEN_COOKIE_NAME, REFRESH_TOKEN_COOKIE_NAME, SESSION_ID_COOKIE_NAME } =
      await import('../../src/utils/cookies.js');

    const res = {
      clearCookie: jest.fn(),
    } as unknown as Response;

    clearAuthCookies(res);

    expect(res.clearCookie).toHaveBeenCalledWith(ACCESS_TOKEN_COOKIE_NAME, { path: '/' });
    expect(res.clearCookie).toHaveBeenCalledWith(REFRESH_TOKEN_COOKIE_NAME, { path: '/api/users' });
    expect(res.clearCookie).toHaveBeenCalledWith(SESSION_ID_COOKIE_NAME, { path: '/api/users' });
  });
});
