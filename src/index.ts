import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import csurf from 'csurf';
import userRouter from './routes/user.js';
import adminRouter from './routes/admin.js';
import connectDB from './utils/db.js';
import { startSessionCleanup } from './utils/session-cleanup.js';

// Load .env
dotenv.config();

const app = express();

const PORT = process.env.PORT ? Number(process.env.PORT) : 4000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:3000';
const CSRF_COOKIE_NAME = process.env.CSRF_COOKIE_NAME || 'XSRF-TOKEN';

// Basic middleware
app.use(helmet());
app.use(morgan('dev'));
app.use(express.json());
// app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CORS setup - allow credentials and specific origin from .env
app.use(cors({
  origin: CORS_ORIGIN,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true
}));

// CSRF protection using cookies
// csurf requires either cookie or session; here we'll use cookie-based tokens
const csrfProtection = csurf({
  cookie: { httpOnly: true, sameSite: 'lax' },
  value: (req: express.Request) => {
    // read token from header first (common in SPA), fallback to body/_csrf
    return (req.headers['x-xsrf-token'] as string) || (req.body && req.body._csrf) || req.query._csrf;
  }
});

// Expose a route to get CSRF token
app.get('/csrf-token', csrfProtection, (req: express.Request, res: express.Response) => {
  const token = (req as any).csrfToken();
  // also set a readable cookie for client JavaScript to read if needed
  res.cookie(CSRF_COOKIE_NAME, token, { sameSite: 'lax' });
  res.json({ csrfToken: token });
});

// Mount routers (protected routes should use csrfProtection as needed)
app.use('/api/users', userRouter);
app.use('/api/admin/sessions', adminRouter);

// Basic health check
app.get('/health', (req: express.Request, res: express.Response) => res.json({ status: 'ok', env: NODE_ENV }));

// Global error handler
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (err && err.code === 'EBADCSRFTOKEN') {
    res.status(403).json({ error: 'Invalid CSRF token' });
    return;
  }
  console.error(err);
  res.status(err?.status || 500).json({ error: err?.message || 'Internal Server Error' });
});

// Connect to DB then start server
connectDB().then(() => {
  // Start session cleanup scheduler
  startSessionCleanup();
  
  app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
}).catch((err: Error) => {
  console.error('Failed to connect to DB:', err.message || err);
  // Still start server to allow health checks in non-db environments, but warn
  app.listen(PORT, () => console.log(`Server running (no DB) on http://localhost:${PORT}`));
});
