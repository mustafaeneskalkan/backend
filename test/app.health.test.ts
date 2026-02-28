import request from 'supertest';

describe('app basic routes', () => {
  it('GET /health returns ok + env', async () => {
    const { createApp } = await import('../src/app.js');
    const app = createApp();

    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok', env: 'test' });
  });
});
