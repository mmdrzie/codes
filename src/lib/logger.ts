/**\n * سیستم Logging امن با Rate Limiting\n * جلوگیری از Log کردن اطلاعات حساس و جلوگیری از Flooding\n */

import { Redis } from '@upstash/redis';

// Initialize Redis for log rate limiting
const redis = process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN 
  ? Redis.fromEnv() 
  : null;

// فیلدهای حساس که نباید log شوند
const SENSITIVE_FIELDS = [
  'password',
  'token',
  'secret',
  'apiKey',
  'api_key',
  'accessToken',
  'access_token',
  'refreshToken',
  'refresh_token',
  'sessionId',
  'session_id',
  'creditCard',
  'credit_card',
  'cvv',
  'ssn',
  'authorization',
  'cookie',
  'privateKey',
  'private_key'
];

// Log rate limiting configuration
const LOG_RATE_LIMITS = {
  PER_USER_PER_MINUTE: 100,  // Max 100 logs per user per minute
  PER_IP_PER_MINUTE: 200,    // Max 200 logs per IP per minute
  PER_ENDPOINT_PER_MINUTE: 50, // Max 50 logs per endpoint per minute
};

// Cache for tracking log counts in memory (fallback when Redis is unavailable)
const logCountCache = new Map<string, { count: number; timestamp: number }>();

/**
 * Check if log should be rate limited
 */
async function checkLogRateLimit(logEntry: LogEntry): Promise<boolean> {
  if (!process.env.LOG_RATE_LIMITING || process.env.LOG_RATE_LIMITING === 'false') {
    return false; // Rate limiting disabled
  }

  const now = Date.now();
  const minuteKey = Math.floor(now / 60000); // Current minute
  
  // Create identifiers for different rate limiting strategies
  const identifiers = [];
  
  if (logEntry.userId) {
    identifiers.push(`user:${logEntry.userId}:${minuteKey}`);
  }
  
  if (logEntry.data?.ip) {
    identifiers.push(`ip:${logEntry.data.ip}:${minuteKey}`);
  }
  
  if (logEntry.data?.endpoint) {
    identifiers.push(`endpoint:${logEntry.data.endpoint}:${minuteKey}`);
  }
  
  // Check all applicable rate limits
  for (const id of identifiers) {
    let currentCount = 0;
    
    if (redis) {
      try {
        // Use Redis to track log counts
        const key = `log_rate_limit:${id}`;
        const count = await redis.incr(key);
        
        if (count === 1) {
          // Set expiration for 2 minutes to clear old entries
          await redis.expire(key, 120);
        }
        
        // Determine limit based on identifier type
        let limit = LOG_RATE_LIMITS.PER_USER_PER_MINUTE;
        if (id.startsWith('ip:')) {
          limit = LOG_RATE_LIMITS.PER_IP_PER_MINUTE;
        } else if (id.startsWith('endpoint:')) {
          limit = LOG_RATE_LIMITS.PER_ENDPOINT_PER_MINUTE;
        }
        
        if (count > limit) {
          return true; // Rate limit exceeded
        }
      } catch (error) {
        // Fallback to in-memory cache if Redis fails
        console.warn('Redis log rate limiting failed, using in-memory cache', error);
        
        // Check in-memory cache
        if (logCountCache.has(id)) {
          const cached = logCountCache.get(id)!;
          if (cached.timestamp === minuteKey) {
            if (cached.count >= LOG_RATE_LIMITS.PER_USER_PER_MINUTE) {
              return true; // Rate limit exceeded
            }
            logCountCache.set(id, { count: cached.count + 1, timestamp: minuteKey });
          } else {
            logCountCache.set(id, { count: 1, timestamp: minuteKey });
          }
        } else {
          logCountCache.set(id, { count: 1, timestamp: minuteKey });
        }
      }
    } else {
      // Use in-memory cache when Redis is not available
      if (logCountCache.has(id)) {
        const cached = logCountCache.get(id)!;
        if (cached.timestamp === minuteKey) {
          if (cached.count >= LOG_RATE_LIMITS.PER_USER_PER_MINUTE) {
            return true; // Rate limit exceeded
          }
          logCountCache.set(id, { count: cached.count + 1, timestamp: minuteKey });
        } else {
          logCountCache.set(id, { count: 1, timestamp: minuteKey });
        }
      } else {
        logCountCache.set(id, { count: 1, timestamp: minuteKey });
      }
    }
  }
  
  return false; // Rate limit not exceeded
}

/**
 * Aggregate similar logs to prevent flooding
 */
function shouldAggregateLog(entry: LogEntry): boolean {
  // Don't aggregate high priority logs
  if (entry.level === LogLevel.ERROR || entry.level === LogLevel.FATAL) {
    return false;
  }
  
  // Check if this is a repetitive log pattern
  const logSignature = `${entry.level}-${entry.message}`;
  const now = Date.now();
  const thresholdMs = 30000; // 30 seconds threshold for similar logs
  
  // This is a simplified implementation - in production you'd want more sophisticated aggregation
  return false; // For now, disable aggregation for clarity
}

// Level های Log
export enum LogLevel {
  DEBUG = 'debug',
  INFO = 'info',
  WARN = 'warn',
  ERROR = 'error',
  FATAL = 'fatal'
}

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  data?: any;
  context?: string;
  userId?: string;
  requestId?: string;
}

/**
 * Sanitize کردن داده برای Log
 */
function sanitizeData(data: any, depth: number = 0): any {
  // جلوگیری از Circular Reference و Deep Nesting
  if (depth > 10) {
    return '[Max Depth Reached]';
  }

  if (data === null || data === undefined) {
    return data;
  }

  if (typeof data !== 'object') {
    return data;
  }

  // Array
  if (Array.isArray(data)) {
    return data.map(item => sanitizeData(item, depth + 1));
  }

  // Object
  const sanitized: any = {};

  for (const key in data) {
    if (!data.hasOwnProperty(key)) continue;

    const lowerKey = key.toLowerCase();

    // بررسی فیلدهای حساس
    const isSensitive = SENSITIVE_FIELDS.some(field =>
      lowerKey.includes(field.toLowerCase())
    );

    if (isSensitive) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof data[key] === 'object') {
      sanitized[key] = sanitizeData(data[key], depth + 1);
    } else {
      sanitized[key] = data[key];
    }
  }

  return sanitized;
}

/**
 * Format کردن Log Entry
 */
function formatLogEntry(entry: LogEntry): string {
  const parts = [
    entry.timestamp,
    `[${entry.level.toUpperCase()}]`,
    entry.context ? `[${entry.context}]` : '',
    entry.requestId ? `[${entry.requestId}]` : '',
    entry.userId ? `[User: ${entry.userId}]` : '',
    entry.message
  ].filter(Boolean);

  let formatted = parts.join(' ');

  if (entry.data) {
    formatted += '\n' + JSON.stringify(sanitizeData(entry.data), null, 2);
  }

  return formatted;
}

/**
 * ذخیره Log (در production به external service ارسال شود)
 */
function writeLog(entry: LogEntry): void {
  const formatted = formatLogEntry(entry);

  // در development به console
  if (process.env.NODE_ENV === 'development') {
    switch (entry.level) {
      case LogLevel.DEBUG:
        console.debug(formatted);
        break;
      case LogLevel.INFO:
        console.info(formatted);
        break;
      case LogLevel.WARN:
        console.warn(formatted);
        break;
      case LogLevel.ERROR:
      case LogLevel.FATAL:
        console.error(formatted);
        break;
    }
  }

  // در production به logging service (مثل Sentry, LogRocket, etc.)
  if (process.env.NODE_ENV === 'production') {
    // TODO: ارسال به external logging service
    // sendToLoggingService(entry);
  }
}

/**
 * Logger Class
 */
class Logger {
  private context?: string;
  private userId?: string;
  private requestId?: string;

  constructor(
    context?: string,
    userId?: string,
    requestId?: string
  ) {
    this.context = context;
    this.userId = userId;
    this.requestId = requestId;
  }

  private log(level: LogLevel, message: string, data?: any): void {
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      data: data ? sanitizeData(data) : undefined,
      context: this.context,
      userId: this.userId,
      requestId: this.requestId
    };

    writeLog(entry);
  }

  debug(message: string, data?: any): void {
    if (process.env.NODE_ENV === 'development') {
      this.log(LogLevel.DEBUG, message, data);
    }
  }

  info(message: string, data?: any): void {
    this.log(LogLevel.INFO, message, data);
  }

  warn(message: string, data?: any): void {
    this.log(LogLevel.WARN, message, data);
  }

  error(message: string, error?: Error | any): void {
    const errorData = error instanceof Error
      ? {
          name: error.name,
          message: error.message,
          stack: error.stack
        }
      : error;

    this.log(LogLevel.ERROR, message, errorData);
  }

  fatal(message: string, error?: Error | any): void {
    const errorData = error instanceof Error
      ? {
          name: error.name,
          message: error.message,
          stack: error.stack
        }
      : error;

    this.log(LogLevel.FATAL, message, errorData);
  }

  /**
   * ایجاد Logger جدید با Context
   */
  withContext(context: string): Logger {
    return new Logger(context, this.userId, this.requestId);
  }

  /**
   * ایجاد Logger جدید با User ID
   */
  withUser(userId: string): Logger {
    return new Logger(this.context, userId, this.requestId);
  }

  /**
   * ایجاد Logger جدید با Request ID
   */
  withRequest(requestId: string): Logger {
    return new Logger(this.context, this.userId, requestId);
  }
}

/**
 * Default Logger Instance
 */
export const logger = new Logger();

/**
 * ایجاد Logger با Context
 */
export function createLogger(
  context?: string,
  userId?: string,
  requestId?: string
): Logger {
  return new Logger(context, userId, requestId);
}

/**
 * Log کردن API Request
 */
export function logApiRequest(
  method: string,
  path: string,
  statusCode: number,
  duration: number,
  userId?: string
): void {
  logger.withUser(userId || 'anonymous').info('API Request', {
    method,
    path,
    statusCode,
    duration: `${duration}ms`
  });
}

/**
 * Log کردن Authentication Event
 */
export function logAuthEvent(
  event: 'login' | 'logout' | 'register' | 'password_reset',
  userId: string,
  success: boolean,
  metadata?: any
): void {
  logger.withUser(userId).info(`Auth Event: ${event}`, {
    event,
    success,
    ...sanitizeData(metadata)
  });
}

/**
 * Log کردن Security Event
 */
export function logSecurityEvent(
  event: string,
  severity: 'low' | 'medium' | 'high' | 'critical',
  details: any
): void {
  const level = severity === 'critical' || severity === 'high'
    ? LogLevel.ERROR
    : LogLevel.WARN;

  const securityLogger = logger.withContext('Security');
  
  if (level === LogLevel.ERROR) {
    securityLogger.error(`Security Event: ${event}`, {
      event,
      severity,
      ...sanitizeData(details)
    });
  } else {
    securityLogger.warn(`Security Event: ${event}`, {
      event,
      severity,
      ...sanitizeData(details)
    });
  }
}

/**
 * Log کردن Database Query (فقط در development)
 */
export function logDatabaseQuery(
  query: string,
  duration: number,
  params?: any
): void {
  if (process.env.NODE_ENV === 'development') {
    logger.withContext('Database').debug('Query executed', {
      query,
      duration: `${duration}ms`,
      params: sanitizeData(params)
    });
  }
}

/**
 * Log کردن External API Call
 */
export function logExternalApiCall(
  service: string,
  endpoint: string,
  statusCode: number,
  duration: number,
  error?: any
): void {
  const apiLogger = logger.withContext('ExternalAPI');

  if (error) {
    apiLogger.error(`${service} API Call`, {
      service,
      endpoint,
      statusCode,
      duration: `${duration}ms`,
      error: sanitizeData(error)
    });
  } else {
    apiLogger.info(`${service} API Call`, {
      service,
      endpoint,
      statusCode,
      duration: `${duration}ms`
    });
  }
}