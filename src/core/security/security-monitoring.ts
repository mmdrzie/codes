import * as Sentry from '@sentry/nextjs';
import { 
  SecurityEventType, 
  siemService, 
  SeverityLevel 
} from './siem-integration';

// Log rate limiting - prevent log flooding
const LOG_RATE_LIMIT_WINDOW_MS = 60000; // 1 minute window
const LOG_RATE_LIMIT_COUNT = 100; // Max 100 logs per window per type

interface LogRateLimitBucket {
  count: number;
  startTime: number;
}

const logRateLimitBuckets = new Map<string, LogRateLimitBucket>();

function isLogRateLimited(eventType: SecurityEvent): boolean {
  const key = `${eventType}`;
  const now = Date.now();
  const bucket = logRateLimitBuckets.get(key);
  
  if (!bucket || (now - bucket.startTime) > LOG_RATE_LIMIT_WINDOW_MS) {
    // Reset bucket if expired
    logRateLimitBuckets.set(key, {
      count: 1,
      startTime: now
    });
    return false;
  }
  
  if (bucket.count >= LOG_RATE_LIMIT_COUNT) {
    return true;
  }
  
  bucket.count++;
  return false;
}

// Security event types - now mapped to SIEM types
export enum SecurityEvent {
  AUTH_SUCCESS = 'auth_success',
  AUTH_FAILURE = 'auth_failure',
  SIWE_SIGNATURE_ANOMALY = 'siwe_signature_anomaly',
  NONCE_REUSE_ATTEMPT = 'nonce_reuse_attempt',
  CSRF_VIOLATION = 'csrf_violation',
  RATE_LIMIT_BREACH = 'rate_limit_breach',
  SESSION_HIJACK_ATTEMPT = 'session_hijack_attempt',
  REPLAY_ATTACK_DETECTED = 'replay_attack_detected',
  UNAUTHORIZED_ACCESS = 'unauthorized_access',
  SUSPICIOUS_ACTIVITY = 'suspicious_activity',
  PQ_CRYPTO_ERROR = 'pq_crypto_error',
  PQ_SIGNATURE_INVALID = 'pq_signature_invalid',
  PQ_KEY_COMPROMISE_SUSPECTED = 'pq_key_compromise_suspected',
  DEVICE_BINDING_VIOLATION = 'device_binding_violation',
  TOKEN_FRESHNESS_VIOLATION = 'token_freshness_violation',
  GEO_IP_ANOMALY = 'geo_ip_anomaly',
}

// Security context for monitoring
export interface SecurityContext {
  userId?: string;
  ipAddress?: string;
  userAgent?: string;
  sessionId?: string;
  timestamp: Date;
  metadata?: Record<string, any>;
}

export class SecurityMonitor {
  /**
   * Log a security event
   */
  static async logEvent(eventType: SecurityEvent, context: SecurityContext, message?: string): Promise<void> {
    // Check log rate limiting
    if (isLogRateLimited(eventType)) {
      console.warn(`Log rate limit exceeded for event type: ${eventType}. Suppressing further logs.`);
      return;
    }
    
    const securityEvent = {
      eventType,
      context: {
        ...context,
        timestamp: context.timestamp.toISOString(),
      },
      message,
    };

    // Log to console in development
    if (process.env.NODE_ENV !== 'production') {
      console.log('[SECURITY EVENT]', securityEvent);
    }

    // Determine severity level based on event type
    let level: 'info' | 'warning' | 'error' = 'info';
    if (eventType.includes('ANOMALY') || eventType.includes('ATTEMPT') || eventType.includes('VIOLATION')) {
      level = 'warning';
    } else if (eventType.includes('ERROR') || eventType.includes('_FAILURE') || eventType.includes('ATTACK')) {
      level = 'error';
    }

    // Send to Sentry for monitoring
    Sentry.captureMessage(`Security Event: ${eventType}`, {
      level,
      contexts: {
        security: {
          event_type: eventType,
          user_id: context.userId,
          ip_address: context.ipAddress,
          user_agent: context.userAgent,
          session_id: context.sessionId,
          timestamp: context.timestamp.toISOString(),
          metadata: context.metadata,
        },
      },
    });

    // Emit to SIEM system with proper mapping
    try {
      await this.emitToSIEMSystem(eventType, context, message);
    } catch (error) {
      // CRITICAL: If SIEM emission fails, this is a security failure
      logger.error('FAILED TO EMIT SECURITY EVENT TO SIEM - SECURITY COMPROMISED', {
        eventType,
        error: (error as Error).message,
        context
      });
      // In production, you might want to fail closed here
      // For now, log but continue
    }
  }

  /**
   * Log an authentication success event
   */
  static async logAuthSuccess(userId: string, context: Omit<SecurityContext, 'timestamp'>): Promise<void> {
    await this.logEvent(SecurityEvent.AUTH_SUCCESS, {
      ...context,
      userId,
      timestamp: new Date(),
    }, `User ${userId} authenticated successfully`);
  }

  /**
   * Log an authentication failure event
   */
  static async logAuthFailure(userId: string | null, context: Omit<SecurityContext, 'timestamp'>, reason: string): Promise<void> {
    await this.logEvent(SecurityEvent.AUTH_FAILURE, {
      ...context,
      userId: userId || undefined,
      timestamp: new Date(),
    }, `Authentication failed: ${reason}`);
  }

  /**
   * Log SIWE signature anomaly
   */
  static async logSiweAnomaly(context: Omit<SecurityContext, 'timestamp'>, details: string): Promise<void> {
    await this.logEvent(SecurityEvent.SIWE_SIGNATURE_ANOMALY, {
      ...context,
      timestamp: new Date(),
    }, `SIWE signature anomaly detected: ${details}`);
  }

  /**
   * Log nonce reuse attempt
   */
  static async logNonceReuse(context: Omit<SecurityContext, 'timestamp'>, nonce: string): Promise<void> {
    await this.logEvent(SecurityEvent.NONCE_REUSE_ATTEMPT, {
      ...context,
      timestamp: new Date(),
    }, `Nonce reuse attempt detected: ${nonce}`);
  }

  /**
   * Log CSRF violation
   */
  static async logCsrfViolation(context: Omit<SecurityContext, 'timestamp'>, token?: string): Promise<void> {
    await this.logEvent(SecurityEvent.CSRF_VIOLATION, {
      ...context,
      timestamp: new Date(),
    }, `CSRF violation detected${token ? ` with token: ${token.substring(0, 8)}...` : ''}`);
  }

  /**
   * Log rate limit breach
   */
  static async logRateLimitBreach(context: Omit<SecurityContext, 'timestamp'>, limit: number, windowMs: number): Promise<void> {
    await this.logEvent(SecurityEvent.RATE_LIMIT_BREACH, {
      ...context,
      timestamp: new Date(),
    }, `Rate limit breach: ${limit} requests in ${windowMs}ms`);
  }

  /**
   * Log suspicious activity
   */
  static async logSuspiciousActivity(context: Omit<SecurityContext, 'timestamp'>, activity: string): Promise<void> {
    await this.logEvent(SecurityEvent.SUSPICIOUS_ACTIVITY, {
      ...context,
      timestamp: new Date(),
    }, `Suspicious activity: ${activity}`);
  }

  /**
   * Log post-quantum cryptography error
   */
  static async logPqCryptoError(context: Omit<SecurityContext, 'timestamp'>, error: string, operation: string): Promise<void> {
    await this.logEvent(SecurityEvent.PQ_CRYPTO_ERROR, {
      ...context,
      timestamp: new Date(),
    }, `Post-quantum crypto error during ${operation}: ${error}`);
  }

  /**
   * Log classical cryptography error
   */
  static async logClassicalCryptoError(context: Omit<SecurityContext, 'timestamp'>, error: string, operation: string): Promise<void> {
    await this.logEvent(SecurityEvent.PQ_CRYPTO_ERROR, {
      ...context,
      timestamp: new Date(),
    }, `Classical crypto error during ${operation}: ${error}`);
  }

  /**
   * Log quantum threat - critical security event
   */
  static async logQuantumThreat(context: Omit<SecurityContext, 'timestamp'>, details: string): Promise<void> {
    // Quantum threats are critical events that require immediate attention
    const securityEvent = {
      eventType: SecurityEvent.PQ_CRYPTO_ERROR,
      context: {
        ...context,
        timestamp: new Date(),
      },
      message: `QUANTUM THREAT DETECTED: ${details}`,
    };

    // Log to console in development
    if (process.env.NODE_ENV !== 'production') {
      console.log('[QUANTUM THREAT]', securityEvent);
    }

    // Send to Sentry for monitoring with critical priority
    Sentry.captureMessage(`Quantum Threat: ${details}`, {
      level: 'fatal', // Critical priority
      contexts: {
        security: {
          event_type: SecurityEvent.PQ_CRYPTO_ERROR,
          user_id: context.userId,
          ip_address: context.ipAddress,
          user_agent: context.userAgent,
          session_id: context.sessionId,
          timestamp: new Date().toISOString(),
          metadata: context.metadata,
        },
      },
    });

    // Emit to SIEM system with proper mapping
    try {
      await this.emitToSIEMSystem(SecurityEvent.PQ_CRYPTO_ERROR, {
        ...context,
        timestamp: new Date(),
      }, securityEvent.message);
    } catch (error) {
      // CRITICAL: If SIEM emission fails, this is a security failure
      logger.error('FAILED TO EMIT QUANTUM THREAT TO SIEM - SECURITY COMPROMISED', {
        eventType: SecurityEvent.PQ_CRYPTO_ERROR,
        error: (error as Error).message,
        context
      });
    }
  }

  /**
   * Log invalid post-quantum signature
   */
  static async logPqSignatureInvalid(context: Omit<SecurityContext, 'timestamp'>, details: string): Promise<void> {
    await this.logEvent(SecurityEvent.PQ_SIGNATURE_INVALID, {
      ...context,
      timestamp: new Date(),
    }, `Post-quantum signature validation failed: ${details}`);
  }

  /**
   * Log suspected post-quantum key compromise
   */
  static async logPqKeyCompromiseSuspected(context: Omit<SecurityContext, 'timestamp'>, keyId: string): Promise<void> {
    await this.logEvent(SecurityEvent.PQ_KEY_COMPROMISE_SUSPECTED, {
      ...context,
      timestamp: new Date(),
    }, `Post-quantum key compromise suspected: ${keyId}`);
  }

  /**
   * Log device binding violation
   */
  static async logDeviceBindingViolation(context: Omit<SecurityContext, 'timestamp'>, expected: string, actual: string): Promise<void> {
    await this.logEvent(SecurityEvent.DEVICE_BINDING_VIOLATION, {
      ...context,
      timestamp: new Date(),
    }, `Device binding violation: expected ${expected}, got ${actual}`);
  }

  /**
   * Log token freshness violation
   */
  static async logTokenFreshnessViolation(context: Omit<SecurityContext, 'timestamp'>, ageSeconds: number): Promise<void> {
    await this.logEvent(SecurityEvent.TOKEN_FRESHNESS_VIOLATION, {
      ...context,
      timestamp: new Date(),
    }, `Token freshness violation: token is ${ageSeconds} seconds old`);
  }

  /**
   * Log geo/IP anomaly
   */
  static async logGeoIpAnomaly(context: Omit<SecurityContext, 'timestamp'>, previousLocation?: string, currentLocation?: string): Promise<void> {
    await this.logEvent(SecurityEvent.GEO_IP_ANOMALY, {
      ...context,
      timestamp: new Date(),
    }, `Geographic/IP anomaly detected: ${previousLocation ? `from ${previousLocation} ` : ''}to ${currentLocation || 'unknown location'}`);
  }

  /**
   * Emit security event to SIEM system with proper mapping
   */
  private static async emitToSIEMSystem(eventType: SecurityEvent, context: SecurityContext, message?: string): Promise<void> {
    // Map SecurityEvent to SecurityEventType for SIEM
    const siemEventType = this.mapToSIEMEventType(eventType);
    const severity = this.mapToSIEMSeverity(eventType);
    
    // Determine outcome based on event type
    let outcome: 'success' | 'failure' | 'blocked' | 'detected' = 'detected';
    if (eventType === SecurityEvent.AUTH_SUCCESS) {
      outcome = 'success';
    } else if (eventType === SecurityEvent.AUTH_FAILURE) {
      outcome = 'failure';
    } else if (eventType === SecurityEvent.RATE_LIMIT_BREACH) {
      outcome = 'blocked';
    }
    
    // Determine source based on event type
    let source: 'auth' | 'session' | 'api' | 'network' | 'application' = 'auth';
    if (eventType === SecurityEvent.CSRF_VIOLATION || eventType.includes('SIGNATURE') || eventType.includes('CRYPTO')) {
      source = 'application';
    } else if (eventType.includes('SESSION') || eventType.includes('BINDING')) {
      source = 'session';
    } else if (eventType.includes('RATE_LIMIT')) {
      source = 'api';
    } else if (eventType.includes('GEO_IP')) {
      source = 'network';
    }
    
    // Emit to SIEM service
    await siemService.emitSecurityEvent({
      event_type: siemEventType,
      severity,
      ip_address: context.ipAddress || 'unknown',
      user_agent: context.userAgent || 'unknown',
      user_id: context.userId,
      session_id: context.sessionId,
      route: context.metadata?.route || 'unknown',
      outcome,
      source,
      details: {
        original_event_type: eventType,
        message,
        ...context.metadata
      }
    });
  }
  
  /**
   * Map SecurityEvent to SecurityEventType for SIEM
   */
  private static mapToSIEMEventType(eventType: SecurityEvent): SecurityEventType {
    switch (eventType) {
      case SecurityEvent.AUTH_FAILURE:
        return SecurityEventType.AUTH_FAILURE;
      case SecurityEvent.REPLAY_ATTACK_DETECTED:
        return SecurityEventType.REPLAY_ATTACK;
      case SecurityEvent.SESSION_HIJACK_ATTEMPT:
        return SecurityEventType.SESSION_HIJACK_ATTEMPT;
      case SecurityEvent.RATE_LIMIT_BREACH:
        return SecurityEventType.RATE_LIMIT_BREACH;
      case SecurityEvent.UNAUTHORIZED_ACCESS:
        return SecurityEventType.UNAUTHORIZED_ACCESS;
      case SecurityEvent.SUSPICIOUS_ACTIVITY:
        return SecurityEventType.SUSPICIOUS_ACTIVITY;
      case SecurityEvent.GEO_IP_ANOMALY:
        return SecurityEventType.GEO_IP_ANOMALY;
      case SecurityEvent.CSRF_VIOLATION:
        return SecurityEventType.CSRF_VIOLATION;
      case SecurityEvent.NONCE_REUSE_ATTEMPT:
        return SecurityEventType.TOKEN_REUSE;
      case SecurityEvent.DEVICE_BINDING_VIOLATION:
        return SecurityEventType.DEVICE_MISMATCH;
      default:
        return SecurityEventType.SUSPICIOUS_ACTIVITY;
    }
  }
  
  /**
   * Map SecurityEvent to appropriate severity level
   */
  private static mapToSIEMSeverity(eventType: SecurityEvent): SeverityLevel {
    if (eventType.includes('ERROR') || eventType.includes('_FAILURE') || eventType.includes('ATTACK') || eventType.includes('HIJACK')) {
      return 'critical';
    } else if (eventType.includes('ANOMALY') || eventType.includes('VIOLATION') || eventType.includes('ATTEMPT')) {
      return 'high';
    } else if (eventType.includes('LIMIT') || eventType.includes('MISMATCH')) {
      return 'medium';
    } else {
      return 'low';
    }
  }

  /**
   * Capture error with security context
   */
  static captureError(error: Error, context: Omit<SecurityContext, 'timestamp'>): void {
    Sentry.captureException(error, {
      contexts: {
        security: {
          user_id: context.userId,
          ip_address: context.ipAddress,
          user_agent: context.userAgent,
          session_id: context.sessionId,
          timestamp: new Date().toISOString(),
          metadata: context.metadata,
        },
      },
    });
  }

  /**
   * Start performance monitoring for auth operations
   */
  static startAuthSpan(operation: string): any {
    return Sentry.startSpan({
      name: `auth.${operation}`,
      op: 'authentication',
    });
  }

  /**
   * Monitor auth performance
   */
  static monitorAuthPerformance<T>(operation: string, fn: () => Promise<T>): Promise<T> {
    return Sentry.startSpan(
      {
        name: `auth.${operation}`,
        op: 'authentication',
      },
      async (span) => {
        try {
          const result = await fn();
          span?.setStatus('ok');
          return result;
        } catch (error) {
          span?.setStatus('internal_error');
          throw error;
        } finally {
          span?.end();
        }
      }
    );
  }
}