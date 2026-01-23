import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import { SecurityMonitor } from '../monitoring/security-monitor';

// Regular expressions for sensitive data redaction
const SENSITIVE_PATTERNS = [
  // Email addresses
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  // Credit card numbers (basic pattern)
  /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
  // IP addresses
  /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
  // Token patterns (common formats)
  /\b(ey[0-9A-Za-z_-]+\.ey[0-9A-Za-z_-]+\.[0-9A-Za-z_-]*)\b/g, // JWT tokens
  /\b[a-fA-F0-9]{64}\b/g, // SHA-256 hex
  /\b[a-zA-Z0-9]{32}\b/g, // Generic API keys/tokens
  // Private key patterns
  /-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----/g,
];

/**
 * Redacts sensitive information from log messages
 */
function redactSensitiveData(message: string): string {
  let redactedMessage = message;
  for (const pattern of SENSITIVE_PATTERNS) {
    redactedMessage = redactedMessage.replace(pattern, '[REDACTED]');
  }
  return redactedMessage;
}

/**
 * Rate limiter for high-volume logs
 */
class LogRateLimiter {
  private logCounts: Map<string, { count: number; resetTime: number }> = new Map();
  private readonly windowMs: number = 60000; // 1 minute window
  private readonly maxLogsPerWindow: number = 100; // Max 100 logs per window

  public shouldLog(key: string): boolean {
    const now = Date.now();
    const entry = this.logCounts.get(key);

    if (!entry || now >= entry.resetTime) {
      // Reset or initialize counter
      this.logCounts.set(key, {
        count: 1,
        resetTime: now + this.windowMs
      });
      return true;
    }

    if (entry.count >= this.maxLogsPerWindow) {
      return false; // Rate limited
    }

    entry.count++;
    return true;
  }
}

const logRateLimiter = new LogRateLimiter();

/**
 * Custom formatter to redact sensitive data and handle rate limiting
 */
const formatWithRedaction = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.json({
    replacer: (key, value) => {
      if (typeof value === 'string') {
        return redactSensitiveData(value);
      }
      return value;
    }
  })
);

/**
 * Winston logger instance with daily rotation and security features
 */
export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: formatWithRedaction,
  transports: [
    new DailyRotateFile({
      filename: 'logs/application-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '100m',
      maxFiles: '30d',
      format: formatWithRedaction,
    }),
    new DailyRotateFile({
      filename: 'logs/error-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '100m',
      maxFiles: '30d',
      level: 'error',
      format: formatWithRedaction,
    }),
  ],
});

// Add console transport in development mode
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
}

/**
 * Secure logger wrapper that handles rate limiting and security monitoring
 */
export class SecureLogger {
  static info(message: string, meta?: Record<string, any>): void {
    const logKey = `info:${message.substring(0, 50)}`;
    if (logRateLimiter.shouldLog(logKey)) {
      logger.info(message, meta);
    }
  }

  static warn(message: string, meta?: Record<string, any>): void {
    const logKey = `warn:${message.substring(0, 50)}`;
    if (logRateLimiter.shouldLog(logKey)) {
      logger.warn(message, meta);
    }
  }

  static error(message: string, meta?: Record<string, any>): void {
    const logKey = `error:${message.substring(0, 50)}`;
    if (logRateLimiter.shouldLog(logKey)) {
      logger.error(message, meta);
      // Also log to security monitor for critical events
      SecurityMonitor.logSecurityEvent('LOG_ERROR', {
        message: redactSensitiveData(message),
        ...meta
      });
    }
  }

  static debug(message: string, meta?: Record<string, any>): void {
    if (process.env.NODE_ENV === 'development') {
      const logKey = `debug:${message.substring(0, 50)}`;
      if (logRateLimiter.shouldLog(logKey)) {
        logger.debug(message, meta);
      }
    }
  }

  /**
   * Log security events with special handling
   */
  static security(level: 'info' | 'warning' | 'critical', event: string, meta?: Record<string, any>): void {
    const logKey = `security:${event}:${level}`;
    if (logRateLimiter.shouldLog(logKey)) {
      const redactedMeta = JSON.parse(JSON.stringify(meta || {}, (key, value) =>
        typeof value === 'string' ? redactSensitiveData(value) : value
      ));
      
      const message = `[SECURITY ${level.toUpperCase()}] ${event}`;
      switch (level) {
        case 'critical':
          logger.error(message, redactedMeta);
          break;
        case 'warning':
          logger.warn(message, redactedMeta);
          break;
        case 'info':
          logger.info(message, redactedMeta);
          break;
      }
      
      // Always forward to security monitor regardless of rate limiting
      SecurityMonitor.logSecurityEvent(event, redactedMeta);
    }
  }
}

export default SecureLogger;