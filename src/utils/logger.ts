import { createLogger, format, transports } from 'winston';
import fs from 'fs';
import path from 'path';

const customFormat = format.printf(({ timestamp, level, message, ...meta }) => {
  const metaString = Object.keys(meta).length > 0 ? ` ${JSON.stringify(meta, null, 2)}` : '';
  return `${timestamp} ${level}: ${message}${metaString}`;
});

const customFileFormat = format.printf(({ timestamp, level, message, ...meta }) => {
  const metaString = Object.keys(meta).length > 0 ? ` ${JSON.stringify(meta)}` : '';
  return `${timestamp} ${level}: ${message}${metaString}`;
});

const logDir = path.resolve(process.cwd(), 'logs');

let fileTransports: any[] = [];
try {
  fs.mkdirSync(logDir, { recursive: true });
  fileTransports = [
    new transports.File({
      filename: path.join(logDir, 'error.log'),
      level: 'error',
      format: format.combine(
        format.uncolorize(),
        format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        customFileFormat
      )
    }),
    new transports.File({
      filename: path.join(logDir, 'combined.log'),
      format: format.combine(
        format.uncolorize(),
        format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        customFileFormat
      )
    })
  ];
} catch {
  // If file logging can't be initialized (read-only FS, missing permissions, etc.),
  // keep console logging so the app still starts.
  fileTransports = [];
}

const logger = createLogger({
  levels: {
    error: 0,
    warn: 1,
    info: 2,
    http: 3,
    verbose: 4,
    debug: 5,
    silly: 6
  },
  level: process.env.LOG_LEVEL || 'http',
  format: format.combine(
    format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    format.colorize({ level: true }),
    customFormat
  ),
  defaultMeta: { service: 'cms-backend' },
  transports: [
    new transports.Console(),
    ...fileTransports
  ]
});

export default logger;
export { logger };
