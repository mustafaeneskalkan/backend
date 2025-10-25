import { createLogger, format, transports } from 'winston';

const customFormat = format.printf(({ timestamp, level, message, ...meta }) => {
  const metaString = Object.keys(meta).length > 0 ? ` ${JSON.stringify(meta, null, 2)}` : '';
  return `${timestamp} ${level}: ${message}${metaString}`;
});

const customFileFormat = format.printf(({ timestamp, level, message, ...meta }) => {
  const metaString = Object.keys(meta).length > 0 ? ` ${JSON.stringify(meta)}` : '';
  return `${timestamp} ${level}: ${message}${metaString}`;
});

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
    new transports.File({
      filename: 'logs/error.log',
      level: 'error',
      format: format.combine(
        format.uncolorize(), 
        format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), 
        customFileFormat
      )
    }),
    new transports.File({
      filename: 'logs/combined.log',
      format: format.combine(
        format.uncolorize(), 
        format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), 
        customFileFormat
      )
    })
  ]
});

export default logger;
export { logger };
