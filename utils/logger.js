const { createLogger, format, transports, config } = require('winston');

const customFormat = format.printf(({ timestamp, level, message }) => {
  return `${timestamp} ${level}: ${message}`;
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
  level: 'info',
  format: format.combine(
    format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    format.colorize({ level: true }),
    customFormat
  ),
  defaultMeta: { service: 'backend-template' },
  transports: [
    new transports.Console(),
    new transports.File({ filename: 'logs/error.log', level: 'error', format: format.combine(format.uncolorize(), format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), customFormat) }),
    new transports.File({ filename: 'logs/combined.log', format: format.combine(format.uncolorize(), format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), customFormat) })
  ]
});

module.exports = logger;
