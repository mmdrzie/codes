/**
 * Bank-Grade SIEM Integration Module
 * Real-time security event emission to external SIEM systems
 */

import { Redis } from '@upstash/redis';
import { logger } from './logger';

// Security event types for SIEM
export enum SecurityEventType {
  AUTH_FAILURE = 'auth_failure',
  TOKEN_REUSE = 'token_reuse',
  BRUTE_FORCE = 'brute_force',
  SESSION_REVOKED = 'session_revoked',
  PRIVILEGE_VIOLATION = 'privilege_violation',
  SESSION_HIJACK_ATTEMPT = 'session_hijack_attempt',
  REPLAY_ATTACK = 'replay_attack',
  UNAUTHORIZED_ACCESS = 'unauthorized_access',
  SUSPICIOUS_ACTIVITY = 'suspicious_activity',
  RATE_LIMIT_BREACH = 'rate_limit_breach',
  GEO_IP_ANOMALY = 'geo_ip_anomaly',
  CSRF_VIOLATION = 'csrf_violation',
  XSS_ATTEMPT = 'xss_attempt',
  SQL_INJECTION_ATTEMPT = 'sql_injection_attempt',
  PATH_TRAVERSAL_ATTEMPT = 'path_traversal_attempt',
  ACCOUNT_LOCKOUT = 'account_lockout',
  PASSWORD_RESET_REQUEST = 'password_reset_request',
  MFA_BYPASS_ATTEMPT = 'mfa_bypass_attempt',
  DEVICE_MISMATCH = 'device_mismatch'
}

export type SeverityLevel = 'low' | 'medium' | 'high' | 'critical';

// Security event schema - machine readable format
export interface SecurityEvent {
  event_type: SecurityEventType;
  severity: SeverityLevel;
  timestamp: string; // UTC, ISO-8601
  user_id?: string;
  session_id?: string;
  ip_address: string;
  user_agent: string;
  request_id?: string;
  route: string;
  outcome: 'success' | 'failure' | 'blocked' | 'detected';
  correlation_id: string;
  details?: {
    [key: string]: any;
  };
  source: 'auth' | 'session' | 'api' | 'network' | 'application';
}

// External SIEM emitter interface
interface SIEMEmitter {
  emit(event: SecurityEvent): Promise<void>;
}

// RFC 5424 Syslog emitter
class SyslogEmitter implements SIEMEmitter {
  private syslogServer: string;
  private port: number;

  constructor(syslogServer: string = process.env.SYSLOG_SERVER || 'localhost', port: number = 514) {
    this.syslogServer = syslogServer;
    this.port = port;
  }

  async emit(event: SecurityEvent): Promise<void> {
    try {
      // Construct RFC 5424 syslog message
      const priority = this.getPriorityFromSeverity(event.severity);
      const timestamp = new Date(event.timestamp).toISOString();
      
      // Format according to RFC 5424
      const syslogMessage = `<${priority}>1 ${timestamp} ${process.env.HOSTNAME || 'app'} ${process.env.APP_NAME || 'quantumiq'} - - [security@12345 event="${event.event_type}" severity="${event.severity}" userId="${event.user_id || 'unknown'}" ip="${event.ip_address}" outcome="${event.outcome}"] Security event: ${event.event_type}`;
      
      // Send to external syslog server
      const dgram = require('dgram');
      const client = dgram.createSocket('udp4');
      
      const messageBuffer = Buffer.from(syslogMessage);
      
      client.send(messageBuffer, 0, messageBuffer.length, 514, this.syslogServer, (err: Error | null) => {
        if (err) {
          logger.error('Failed to send syslog message', { error: err.message, syslogMessage });
        }
        client.close();
      });
      
      // Also log to application logs
      logger.info('Syslog event emitted', { 
        event_type: event.event_type, 
        severity: event.severity, 
        user_id: event.user_id,
        ip_address: event.ip_address
      });
    } catch (error) {
      logger.error('Failed to emit to Syslog', { error: (error as Error).message, event });
    }
  }

  private getPriorityFromSeverity(severity: SeverityLevel): number {
    switch (severity) {
      case 'critical': return 11; // User level 3 (critical)
      case 'high': return 12;     // User level 4 (error)
      case 'medium': return 13;   // User level 5 (warning)
      case 'low': return 14;      // User level 6 (notice)
      default: return 14;
    }
  }
}

// HTTPS Webhook emitter for SIEM integration
class WebhookEmitter implements SIEMEmitter {
  private webhookUrl: string;
  private apiKey: string;
  private retries: number;

  constructor(webhookUrl: string, apiKey: string, retries: number = 3) {
    this.webhookUrl = webhookUrl;
    this.apiKey = apiKey;
    this.retries = retries;
  }

  async emit(event: SecurityEvent): Promise<void> {
    try {
      // Add signature for authenticity verification
      const signedEvent = {
        ...event,
        signature: this.generateSignature(event),
        timestamp_sent: new Date().toISOString()
      };

      let attempt = 0;
      let lastError: any;

      while (attempt < this.retries) {
        try {
          // Using AbortController for proper timeout handling
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout
      
      const response = await fetch(this.webhookUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${this.apiKey}`,
              'X-Event-Signature': signedEvent.signature,
              'X-Event-Timestamp': signedEvent.timestamp_sent
            },
            body: JSON.stringify(signedEvent),
            signal: controller.signal
          });
          
      clearTimeout(timeoutId);

          if (response.ok) {
            logger.info('Webhook event sent successfully', { 
              event_type: event.event_type, 
              status: response.status 
            });
            return;
          } else {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
          }
        } catch (error) {
          lastError = error;
          logger.warn('Webhook attempt failed, retrying...', { 
            attempt: attempt + 1, 
            error: (error as Error).message,
            event_type: event.event_type
          });
          attempt++;
          
          // Wait before retry with exponential backoff
          if (attempt < this.retries) {
            await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 1000));
          }
        }
      }

      // All retries failed
      throw lastError;
    } catch (error) {
      logger.error('Failed to emit to Webhook SIEM', { 
        error: (error as Error).message, 
        event: event.event_type,
        webhook_url: this.webhookUrl 
      });
      throw error;
    }
  }

  private generateSignature(event: SecurityEvent): string {
    // Simple signature generation - in production use proper HMAC
    const data = JSON.stringify({
      event_type: event.event_type,
      timestamp: event.timestamp,
      user_id: event.user_id,
      ip_address: event.ip_address
    });
    
    // This is simplified - use proper crypto in production
    return require('crypto').createHash('sha256').update(data + this.apiKey).digest('hex');
  }
}

// Message Queue emitter (abstraction for Kafka/PubSub/SQS)
class MessageQueueEmitter implements SIEMEmitter {
  private redis: Redis;
  private queueName: string;

  constructor(queueName: string = 'security_events') {
    this.redis = Redis.fromEnv();
    this.queueName = queueName;
  }

  async emit(event: SecurityEvent): Promise<void> {
    try {
      // Add event hash for tamper resistance
      const eventWithHash = {
        ...event,
        hash: this.calculateEventHash(event)
      };

      // Push to Redis list (can be consumed by SIEM processor)
      await this.redis.lpush(this.queueName, JSON.stringify(eventWithHash));
      
      // Set TTL to clean up old events
      await this.redis.expire(this.queueName, 86400 * 7); // 7 days
      
      logger.info('Security event queued for SIEM processing', { 
        event_type: event.event_type,
        queue: this.queueName
      });
    } catch (error) {
      logger.error('Failed to queue security event', { 
        error: (error as Error).message, 
        event: event.event_type 
      });
    }
  }

  private calculateEventHash(event: SecurityEvent): string {
    // Calculate SHA-256 hash of the event for tamper detection
    const crypto = require('crypto');
    const data = JSON.stringify({
      event_type: event.event_type,
      timestamp: event.timestamp,
      user_id: event.user_id,
      ip_address: event.ip_address,
      correlation_id: event.correlation_id
    });
    
    return crypto.createHash('sha256').update(data).digest('hex');
  }
}

// Main SIEM integration service
export class SIEMIntegrationService {
  private emitters: SIEMEmitter[] = [];
  private enabled: boolean;
  
  constructor() {
    this.enabled = process.env.SIEM_ENABLED === 'true';
    
    // Initialize emitters based on configuration
    if (process.env.SYSLOG_ENABLED === 'true') {
      this.emitters.push(new SyslogEmitter());
    }
    
    if (process.env.WEBHOOK_SIEM_URL && process.env.WEBHOOK_SIEM_API_KEY) {
      this.emitters.push(new WebhookEmitter(
        process.env.WEBHOOK_SIEM_URL,
        process.env.WEBHOOK_SIEM_API_KEY
      ));
    }
    
    if (process.env.MESSAGE_QUEUE_ENABLED === 'true') {
      this.emitters.push(new MessageQueueEmitter());
    }
  }

  /**
   * Emit a security event to all configured SIEM systems
   */
  async emitSecurityEvent(event: Omit<SecurityEvent, 'timestamp' | 'correlation_id'>): Promise<void> {
    if (!this.enabled) {
      logger.warn('SIEM integration disabled, skipping event emission', { event_type: event.event_type });
      return;
    }

    // Add required fields
    const securityEvent: SecurityEvent = {
      ...event,
      timestamp: new Date().toISOString(),
      correlation_id: event.correlation_id || this.generateCorrelationId()
    };

    // Validate event schema
    if (!this.validateEventSchema(securityEvent)) {
      logger.error('Invalid security event schema', { event: securityEvent });
      throw new Error('Invalid security event schema');
    }

    // Emit to all configured emitters
    const results = await Promise.allSettled(
      this.emitters.map(emitter => emitter.emit(securityEvent))
    );

    // Log any failures
    const failures = results.filter(result => result.status === 'rejected');
    if (failures.length > 0) {
      logger.error('Some SIEM emitters failed', { 
        failures: failures.map(f => (f as PromiseRejectedResult).reason),
        event_type: securityEvent.event_type
      });
    }

    // If all emitters failed, consider this a critical failure
    if (results.every(result => result.status === 'rejected')) {
      logger.error('All SIEM emitters failed - security event lost', { 
        event: securityEvent,
        failures: failures.map(f => (f as PromiseRejectedResult).reason)
      });
      // Don't throw here as it could cause service disruption, but log as critical
      // In a real system, you might want to implement local logging as backup
      console.error('CRITICAL: All SIEM emitters failed - security events may be lost!');
    }
  }

  /**
   * Validate that the event conforms to our security schema
   */
  private validateEventSchema(event: SecurityEvent): boolean {
    return (
      event.event_type &&
      Object.values(SecurityEventType).includes(event.event_type) &&
      event.severity &&
      ['low', 'medium', 'high', 'critical'].includes(event.severity) &&
      event.timestamp &&
      event.ip_address &&
      event.user_agent &&
      event.route &&
      event.outcome &&
      event.correlation_id &&
      event.source
    );
  }

  private generateCorrelationId(): string {
    return `corr_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Quick emit functions for common security events
   */
  async emitAuthFailure(
    ip_address: string,
    user_agent: string,
    user_id: string | null,
    route: string,
    details?: any
  ): Promise<void> {
    await this.emitSecurityEvent({
      event_type: SecurityEventType.AUTH_FAILURE,
      severity: 'high',
      ip_address,
      user_agent,
      user_id: user_id || undefined,
      route,
      outcome: 'failure',
      source: 'auth',
      details
    });
  }

  async emitTokenReuse(
    ip_address: string,
    user_agent: string,
    user_id: string,
    token_type: string,
    route: string
  ): Promise<void> {
    await this.emitSecurityEvent({
      event_type: SecurityEventType.TOKEN_REUSE,
      severity: 'critical',
      ip_address,
      user_agent,
      user_id,
      route,
      outcome: 'detected',
      source: 'auth',
      details: { token_type }
    });
  }

  async emitBruteForce(
    ip_address: string,
    user_agent: string,
    user_id: string | null,
    route: string,
    attempts_count: number
  ): Promise<void> {
    await this.emitSecurityEvent({
      event_type: SecurityEventType.BRUTE_FORCE,
      severity: 'critical',
      ip_address,
      user_agent,
      user_id: user_id || undefined,
      route,
      outcome: 'detected',
      source: 'auth',
      details: { attempts_count }
    });
  }

  async emitReplayAttack(
    ip_address: string,
    user_agent: string,
    user_id: string,
    token_jti: string,
    route: string
  ): Promise<void> {
    await this.emitSecurityEvent({
      event_type: SecurityEventType.REPLAY_ATTACK,
      severity: 'critical',
      ip_address,
      user_agent,
      user_id,
      route,
      outcome: 'detected',
      source: 'auth',
      details: { token_jti }
    });
  }

  async emitSessionHijackAttempt(
    ip_address: string,
    user_agent: string,
    user_id: string,
    session_id: string,
    route: string,
    details?: any
  ): Promise<void> {
    await this.emitSecurityEvent({
      event_type: SecurityEventType.SESSION_HIJACK_ATTEMPT,
      severity: 'critical',
      ip_address,
      user_agent,
      user_id,
      session_id,
      route,
      outcome: 'detected',
      source: 'session',
      details
    });
  }

  async emitRateLimitBreach(
    ip_address: string,
    user_agent: string,
    user_id: string | null,
    route: string,
    limit_type: string,
    attempts: number
  ): Promise<void> {
    await this.emitSecurityEvent({
      event_type: SecurityEventType.RATE_LIMIT_BREACH,
      severity: 'medium',
      ip_address,
      user_agent,
      user_id: user_id || undefined,
      route,
      outcome: 'blocked',
      source: 'api',
      details: { limit_type, attempts }
    });
  }

  async emitUnauthorizedAccess(
    ip_address: string,
    user_agent: string,
    user_id: string | null,
    route: string,
    required_permission: string
  ): Promise<void> {
    await this.emitSecurityEvent({
      event_type: SecurityEventType.UNAUTHORIZED_ACCESS,
      severity: 'high',
      ip_address,
      user_agent,
      user_id: user_id || undefined,
      route,
      outcome: 'blocked',
      source: 'application',
      details: { required_permission }
    });
  }

  async emitGeoIPAnomaly(
    ip_address: string,
    user_agent: string,
    user_id: string,
    route: string,
    previous_location?: string,
    current_location?: string
  ): Promise<void> {
    await this.emitSecurityEvent({
      event_type: SecurityEventType.GEO_IP_ANOMALY,
      severity: 'high',
      ip_address,
      user_agent,
      user_id,
      route,
      outcome: 'detected',
      source: 'network',
      details: { previous_location, current_location }
    });
  }
}

// Global SIEM service instance
export const siemService = new SIEMIntegrationService();

// Export for use in other modules
export default siemService;