import express from 'express';
import cookieParser from 'cookie-parser';
import request from 'supertest';

describe('csrf middleware', () => {
  it('issues a token cookie and validates double-submit on POST', async () => {
    const { issueCsrfToken, requireCsrf } = await import('../../src/middleware/csrf.js');
    const { CSRF_COOKIE_NAME } = await import('../../src/utils/cookies.js');

    const app = express();
    app.use(cookieParser());
    app.get('/csrf-token', issueCsrfToken);
    app.post('/protected', requireCsrf, (req, res) => res.json({ ok: true }));

    const agent = request.agent(app);
    const tokenRes = await agent.get('/csrf-token');

    expect(tokenRes.status).toBe(200);
    expect(typeof tokenRes.body?.csrfToken).toBe('string');
    expect(tokenRes.body.csrfToken.length).toBeGreaterThan(10);
    const setCookie = tokenRes.headers['set-cookie'];
    const cookieHeader = Array.isArray(setCookie) ? setCookie.join(';') : String(setCookie ?? '');
    expect(cookieHeader).toContain(`${CSRF_COOKIE_NAME}=`);

    const noHeader = await agent.post('/protected');
    expect(noHeader.status).toBe(403);
    expect(noHeader.body?.code).toBe('CSRF_INVALID');

    const ok = await agent
      .post('/protected')
      .set('x-xsrf-token', tokenRes.body.csrfToken);

    expect(ok.status).toBe(200);
    expect(ok.body).toEqual({ ok: true });
  });
});
