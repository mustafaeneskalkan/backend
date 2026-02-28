import fs from 'node:fs';
import path from 'node:path';
import dotenv from 'dotenv';

function resolveEnvPath(): string | undefined {
  const cwd = process.cwd();
  const lifecycleEvent = process.env.npm_lifecycle_event;

  const candidates: string[] = [];

  // Requirement: `npm run dev` should load `.env.dev`
  if (lifecycleEvent === 'dev') candidates.push('.env.dev');

  // Fallback for other scripts (start/test/build) and local usage
  candidates.push('.env');

  for (const filename of candidates) {
    const fullPath = path.join(cwd, filename);
    if (fs.existsSync(fullPath)) return fullPath;
  }

  return undefined;
}

let loaded = false;

export function loadEnv(): void {
  if (loaded) return;
  loaded = true;

  const envPath = resolveEnvPath();
  if (envPath) {
    dotenv.config({ path: envPath });
  } else {
    dotenv.config();
  }
}
