import express from 'express';
import request from 'supertest';

describe('requestIdMiddleware', () => {
  it('sets x-request-id when missing', async () => {
    const { requestIdMiddleware } = await import('../../src/middleware/request-id.js');
    const app = express();
    app.use(requestIdMiddleware);
    app.get('/ping', (req, res) => res.json({ requestId: req.requestId }));

    const res = await request(app).get('/ping');
    expect(res.status).toBe(200);
    expect(typeof res.headers['x-request-id']).toBe('string');
    expect(res.headers['x-request-id'].length).toBeGreaterThan(10);
    expect(res.body.requestId).toBe(res.headers['x-request-id']);
  });

  it('preserves incoming x-request-id', async () => {
    const { requestIdMiddleware } = await import('../../src/middleware/request-id.js');
    const app = express();
    app.use(requestIdMiddleware);
    app.get('/ping', (req, res) => res.json({ requestId: req.requestId }));

    const res = await request(app).get('/ping').set('x-request-id', 'req-123');
    expect(res.status).toBe(200);
    expect(res.headers['x-request-id']).toBe('req-123');
    expect(res.body.requestId).toBe('req-123');
  });
});
