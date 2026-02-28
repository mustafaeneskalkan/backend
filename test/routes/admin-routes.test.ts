import { jest } from '@jest/globals';
import request from 'supertest';

describe('admin session routes wiring', () => {
  it('GET /api/admin/sessions/stats returns mocked stats', async () => {
    jest.resetModules();
    jest.unstable_mockModule('../../src/middleware/auth.js', () => ({
      authenticateToken: (req: any, res: any, next: any) => next(),
      requireRole: () => (req: any, res: any, next: any) => next(),
      authenticateRefreshToken: (req: any, res: any, next: any) => next(),
      requireEmailVerification: (req: any, res: any, next: any) => next(),
    }));

    jest.unstable_mockModule('../../src/utils/session-cleanup.js', () => ({
      getSessionStats: async () => ({
        totalUsers: 10,
        usersWithActiveSessions: 3,
        totalActiveSessions: 5,
        expiredSessions: 2,
      }),
      cleanupExpiredSessions: async () => undefined,
      startSessionCleanup: () => undefined,
      cleanupUserSessions: async () => undefined,
    }));

    const { createApp } = await import('../../src/app.js');
    const app = createApp();

    const res = await request(app).get('/api/admin/sessions/stats');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      totalUsers: 10,
      usersWithActiveSessions: 3,
      totalActiveSessions: 5,
      expiredSessions: 2,
    });
  });

  it('POST /api/admin/sessions/cleanup requires CSRF for non-GET', async () => {
    jest.resetModules();
    const cleanupExpiredSessions = jest.fn(async () => undefined);

    jest.unstable_mockModule('../../src/middleware/auth.js', () => ({
      authenticateToken: (req: any, res: any, next: any) => next(),
      requireRole: () => (req: any, res: any, next: any) => next(),
      authenticateRefreshToken: (req: any, res: any, next: any) => next(),
      requireEmailVerification: (req: any, res: any, next: any) => next(),
    }));

    jest.unstable_mockModule('../../src/utils/session-cleanup.js', () => ({
      getSessionStats: async () => ({
        totalUsers: 0,
        usersWithActiveSessions: 0,
        totalActiveSessions: 0,
        expiredSessions: 0,
      }),
      cleanupExpiredSessions,
      startSessionCleanup: () => undefined,
      cleanupUserSessions: async () => undefined,
    }));

    const { createApp } = await import('../../src/app.js');
    const app = createApp();
    const agent = request.agent(app);

    const missing = await agent.post('/api/admin/sessions/cleanup');
    expect(missing.status).toBe(403);
    expect(missing.body?.code).toBe('CSRF_INVALID');

    const csrfRes = await agent.get('/csrf-token');
    const token = csrfRes.body.csrfToken as string;

    const ok = await agent.post('/api/admin/sessions/cleanup').set('x-xsrf-token', token);
    expect(ok.status).toBe(200);
    expect(ok.body?.message).toContain('completed');
    expect(cleanupExpiredSessions).toHaveBeenCalled();
  });
});
