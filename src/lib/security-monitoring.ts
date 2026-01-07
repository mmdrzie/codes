import * as Sentry from '@sentry/nextjs';

// Security event types
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
  static logEvent(eventType: SecurityEvent, context: SecurityContext, message?: string): void {
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

    // Send to Sentry for monitoring
    Sentry.captureMessage(`Security Event: ${eventType}`, {
      level: 'info',
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

    // In production, also emit to SIEM system
    if (process.env.NODE_ENV === 'production') {
      this.emitToSIEM(securityEvent);
    }
  }

  /**
   * Log an authentication success event
   */
  static logAuthSuccess(userId: string, context: Omit<SecurityContext, 'timestamp'>): void {
    this.logEvent(SecurityEvent.AUTH_SUCCESS, {
      ...context,
      userId,
      timestamp: new Date(),
    }, `User ${userId} authenticated successfully`);
  }

  /**
   * Log an authentication failure event
   */
  static logAuthFailure(userId: string | null, context: Omit<SecurityContext, 'timestamp'>, reason: string): void {
    this.logEvent(SecurityEvent.AUTH_FAILURE, {
      ...context,
      userId: userId || undefined,
      timestamp: new Date(),
    }, `Authentication failed: ${reason}`);
  }

  /**
   * Log SIWE signature anomaly
   */
  static logSiweAnomaly(context: Omit<SecurityContext, 'timestamp'>, details: string): void {
    this.logEvent(SecurityEvent.SIWE_SIGNATURE_ANOMALY, {
      ...context,
      timestamp: new Date(),
    }, `SIWE signature anomaly detected: ${details}`);
  }

  /**
   * Log nonce reuse attempt
   */
  static logNonceReuse(context: Omit<SecurityContext, 'timestamp'>, nonce: string): void {
    this.logEvent(SecurityEvent.NONCE_REUSE_ATTEMPT, {
      ...context,
      timestamp: new Date(),
    }, `Nonce reuse attempt detected: ${nonce}`);
  }

  /**
   * Log CSRF violation
   */
  static logCsrfViolation(context: Omit<SecurityContext, 'timestamp'>, token?: string): void {
    this.logEvent(SecurityEvent.CSRF_VIOLATION, {
      ...context,
      timestamp: new Date(),
    }, `CSRF violation detected${token ? ` with token: ${token.substring(0, 8)}...` : ''}`);
  }

  /**
   * Log rate limit breach
   */
  static logRateLimitBreach(context: Omit<SecurityContext, 'timestamp'>, limit: number, windowMs: number): void {
    this.logEvent(SecurityEvent.RATE_LIMIT_BREACH, {
      ...context,
      timestamp: new Date(),
    }, `Rate limit breach: ${limit} requests in ${windowMs}ms`);
  }

  /**
   * Log suspicious activity
   */
  static logSuspiciousActivity(context: Omit<SecurityContext, 'timestamp'>, activity: string): void {
    this.logEvent(SecurityEvent.SUSPICIOUS_ACTIVITY, {
      ...context,
      timestamp: new Date(),
    }, `Suspicious activity: ${activity}`);
  }

  /**
   * Emit security event to SIEM system (placeholder implementation)
   */
  private static emitToSIEM(event: any): void {
    // In a real implementation, this would send to:
    // - ELK stack (Elasticsearch, Logstash, Kibana)
    // - Splunk
    // - Datadog
    // - Custom SIEM solution
    
    // For now, we'll just log to console
    console.log('[SIEM INTEGRATION]', JSON.stringify(event, null, 2));
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