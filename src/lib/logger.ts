/**
 * سیستم Logging امن
 * جلوگیری از Log کردن اطلاعات حساس
 */

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