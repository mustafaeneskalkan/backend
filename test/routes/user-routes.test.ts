import { jest } from '@jest/globals';
import request from 'supertest';

describe('user routes wiring', () => {
  beforeEach(() => {
    jest.resetModules();
    jest.clearAllMocks();
  });

  it('POST /api/users/register requires CSRF and then calls controller', async () => {
    const register = jest.fn((req: any, res: any) => res.status(201).json({ created: true }));
    const requestPasswordReset = jest.fn((req: any, res: any) => res.json({ ok: true }));

    jest.unstable_mockModule('../../src/controllers/user.js', () => ({
      default: {
        register,
        login: (req: any, res: any) => res.json({ ok: true }),
        loginAdmin: (req: any, res: any) => res.json({ ok: true }),
        refreshToken: (req: any, res: any) => res.json({ ok: true }),
        verifyEmail: (req: any, res: any) => res.json({ ok: true }),
        verifyEmailChange: (req: any, res: any) => res.json({ ok: true }),
        resendVerification: (req: any, res: any) => res.json({ ok: true }),
        logout: (req: any, res: any) => res.json({ ok: true }),
        logoutAll: (req: any, res: any) => res.json({ ok: true }),
        getSession: (req: any, res: any) => res.json({ ok: true }),
        getSessions: (req: any, res: any) => res.json({ ok: true }),
        terminateSession: (req: any, res: any) => res.json({ ok: true }),
        changeEmail: (req: any, res: any) => res.json({ ok: true }),
        changePassword: (req: any, res: any) => res.json({ ok: true }),
        requestPasswordReset,
        resetPassword: (req: any, res: any) => res.json({ ok: true }),
      },
    }));

    const { createApp } = await import('../../src/app.js');
    const app = createApp();
    const agent = request.agent(app);

    const missing = await agent.post('/api/users/register').send({});
    expect(missing.status).toBe(403);
    expect(missing.body?.code).toBe('CSRF_INVALID');

    const csrfRes = await agent.get('/csrf-token');
    const token = csrfRes.body.csrfToken as string;
    expect(typeof token).toBe('string');

    const ok = await agent
      .post('/api/users/register')
      .set('x-xsrf-token', token)
      .send({ email: 'a@b.com', password: 'Password123!' });

    expect(ok.status).toBe(201);
    expect(ok.body).toEqual({ created: true });
    expect(register).toHaveBeenCalled();
  });

  it('POST /api/users/request-password-change requires CSRF and then calls controller', async () => {
    const requestPasswordReset = jest.fn((req: any, res: any) => res.json({ sent: true }));

    jest.unstable_mockModule('../../src/controllers/user.js', () => ({
      default: {
        register: (req: any, res: any) => res.status(201).json({ created: true }),
        login: (req: any, res: any) => res.json({ ok: true }),
        loginAdmin: (req: any, res: any) => res.json({ ok: true }),
        refreshToken: (req: any, res: any) => res.json({ ok: true }),
        verifyEmail: (req: any, res: any) => res.json({ ok: true }),
        verifyEmailChange: (req: any, res: any) => res.json({ ok: true }),
        resendVerification: (req: any, res: any) => res.json({ ok: true }),
        logout: (req: any, res: any) => res.json({ ok: true }),
        logoutAll: (req: any, res: any) => res.json({ ok: true }),
        getSession: (req: any, res: any) => res.json({ ok: true }),
        getSessions: (req: any, res: any) => res.json({ ok: true }),
        terminateSession: (req: any, res: any) => res.json({ ok: true }),
        changeEmail: (req: any, res: any) => res.json({ ok: true }),
        changePassword: (req: any, res: any) => res.json({ ok: true }),
        requestPasswordReset,
        resetPassword: (req: any, res: any) => res.json({ ok: true }),
      },
    }));

    const { createApp } = await import('../../src/app.js');
    const app = createApp();
    const agent = request.agent(app);

    const missing = await agent.post('/api/users/request-password-change').send({ email: 'a@b.com' });
    expect(missing.status).toBe(403);
    expect(missing.body?.code).toBe('CSRF_INVALID');

    const csrfRes = await agent.get('/csrf-token');
    const token = csrfRes.body.csrfToken as string;
    expect(typeof token).toBe('string');

    const ok = await agent
      .post('/api/users/request-password-change')
      .set('x-xsrf-token', token)
      .send({ email: 'a@b.com' });

    expect(ok.status).toBe(200);
    expect(ok.body).toEqual({ sent: true });
    expect(requestPasswordReset).toHaveBeenCalled();
  });
});
