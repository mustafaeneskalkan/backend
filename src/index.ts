import connectDB from './utils/db.js';
import { startSessionCleanup } from './utils/session-cleanup.js';
import { createApp } from './app.js';
import { loadEnv } from './utils/env.js';

// Load env vars (npm run dev => .env.dev, fallback => .env)
loadEnv();

const PORT = process.env.PORT ? Number(process.env.PORT) : 4000;
const app = createApp();

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
