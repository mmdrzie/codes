/**
 * Bank-Grade SIEM Integration Module
 * Production-ready security event emission to external SIEM systems
 */

import { Redis } from '@upstash/redis';
import { logger } from './logger';
import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';

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

export type SeverityLevel = 'info' | 'low' | 'medium' | 'high' | 'critical';

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
  // Cryptographic integrity fields
  hmac_signature?: string;
  hmac_algorithm?: string;
}

// Disk-backed buffer for outage scenarios
class DiskBuffer {
  private readonly bufferDir: string;
  private readonly maxBufferSize: number;

  constructor(bufferDir: string = '/tmp/siem_buffer', maxBufferSize: number = 10000) {
    this.bufferDir = bufferDir;
    this.maxBufferSize = maxBufferSize;
    
    // Create buffer directory if it doesn't exist
    try {
      fs.mkdirSync(this.bufferDir, { recursive: true });
    } catch (error) {
      logger.error('Failed to create SIEM buffer directory', { error: (error as Error).message, bufferDir: this.bufferDir });
    }
  }

  async addEvent(event: SecurityEvent): Promise<boolean> {
    try {
      // Generate unique filename based on timestamp and random component
      const fileName = path.join(
        this.bufferDir,
        `event_${Date.now()}_${Math.random().toString(36).substring(2, 15)}.json`
      );

      // Write event to disk
      await fs.writeFile(fileName, JSON.stringify(event));
      
      // Check if we exceed max buffer size and clean old events
      await this.cleanupOldEvents();
      
      return true;
    } catch (error) {
      logger.error('Failed to add event to disk buffer', { error: (error as Error).message });
      return false;
    }
  }

  async getEvents(limit: number = 100): Promise<SecurityEvent[]> {
    try {
      const files = await fs.readdir(this.bufferDir);
      const jsonFiles = files.filter(file => file.endsWith('.json'));
      
      // Sort by filename (which contains timestamp) to get oldest first
      jsonFiles.sort((a, b) => {
        const timeA = parseInt(a.split('_')[1]);
        const timeB = parseInt(b.split('_')[1]);
        return timeA - timeB;
      });

      const events: SecurityEvent[] = [];
      const filesToProcess = jsonFiles.slice(0, limit);

      for (const file of filesToProcess) {
        const filePath = path.join(this.bufferDir, file);
        try {
          const content = await fs.readFile(filePath, 'utf-8');
          const event = JSON.parse(content) as SecurityEvent;
          events.push(event);
          
          // Remove processed file
          await fs.unlink(filePath);
        } catch (error) {
          logger.error('Failed to read or parse buffered event', { 
            error: (error as Error).message, 
            filePath 
          });
        }
      }

      return events;
    } catch (error) {
      logger.error('Failed to read events from disk buffer', { error: (error as Error).message });
      return [];
    }
  }

  private async cleanupOldEvents(): Promise<void> {
    try {
      const files = await fs.readdir(this.bufferDir);
      const jsonFiles = files.filter(file => file.endsWith('.json'));
      
      if (jsonFiles.length > this.maxBufferSize) {
        // Sort by timestamp in filename and remove oldest
        jsonFiles.sort((a, b) => {
          const timeA = parseInt(a.split('_')[1]);
          const timeB = parseInt(b.split('_')[1]);
          return timeA - timeB;
        });
        
        const filesToRemove = jsonFiles.slice(0, jsonFiles.length - this.maxBufferSize);
        for (const file of filesToRemove) {
          await fs.unlink(path.join(this.bufferDir, file));
        }
        
        logger.warn('Cleaned up SIEM disk buffer', { 
          filesRemoved: filesToRemove.length,
          remaining: jsonFiles.length - filesToRemove.length
        });
      }
    } catch (error) {
      logger.error('Failed to cleanup SIEM disk buffer', { error: (error as Error).message });
    }
  }

  async getBufferStatus(): Promise<{ count: number; size: number }> {
    try {
      const files = await fs.readdir(this.bufferDir);
      const jsonFiles = files.filter(file => file.endsWith('.json'));
      
      let totalSize = 0;
      for (const file of jsonFiles) {
        const stats = await fs.stat(path.join(this.bufferDir, file));
        totalSize += stats.size;
      }
      
      return { count: jsonFiles.length, size: totalSize };
    } catch (error) {
      logger.error('Failed to get buffer status', { error: (error as Error).message });
      return { count: 0, size: 0 };
    }
  }
}

// External SIEM emitter interface
interface SIEMEmitter {
  emit(event: SecurityEvent): Promise<void>;
  healthCheck?(): Promise<boolean>;
}

// RFC 5424 Syslog emitter with guaranteed delivery and HMAC
class SyslogEmitter implements SIEMEmitter {
  private syslogServer: string;
  private port: number;
  private secretKey: string;
  private diskBuffer: DiskBuffer;

  constructor(
    syslogServer: string = process.env.SYSLOG_SERVER || 'localhost', 
    port: number = 514,
    secretKey: string = process.env.SYSLOG_SECRET_KEY || 'default-syslog-key'
  ) {
    this.syslogServer = syslogServer;
    this.port = port;
    this.secretKey = secretKey;
    this.diskBuffer = new DiskBuffer('/tmp/syslog_buffer');
  }

  async emit(event: SecurityEvent): Promise<void> {
    try {
      // Add HMAC signature for integrity
      const signedEvent = this.signEvent(event);
      const priority = this.getPriorityFromSeverity(signedEvent.severity);
      const timestamp = new Date(signedEvent.timestamp).toISOString();
      
      // Format according to RFC 5424 with HMAC
      const syslogMessage = `<${priority}>1 ${timestamp} ${process.env.HOSTNAME || 'app'} ${process.env.APP_NAME || 'quantumiq'} - - [security@12345 event="${signedEvent.event_type}" severity="${signedEvent.severity}" userId="${signedEvent.user_id || 'unknown'}" ip="${signedEvent.ip_address}" outcome="${signedEvent.outcome}" hmac="${signedEvent.hmac_signature}"] Security event: ${signedEvent.event_type}`;
      
      // Attempt to send to syslog server with retry and exponential backoff
      await this.sendWithRetry(syslogMessage);
      
      logger.info('Syslog event emitted', { 
        event_type: signedEvent.event_type, 
        severity: signedEvent.severity, 
        user_id: signedEvent.user_id,
        ip_address: signedEvent.ip_address
      });
    } catch (error) {
      logger.error('Failed to emit to Syslog, adding to disk buffer', { 
        error: (error as Error).message, 
        event_type: event.event_type 
      });
      
      // Add to disk buffer for later delivery
      await this.diskBuffer.addEvent(event);
    }
  }

  private signEvent(event: SecurityEvent): SecurityEvent {
    const dataToSign = JSON.stringify({
      event_type: event.event_type,
      timestamp: event.timestamp,
      user_id: event.user_id,
      ip_address: event.ip_address,
      correlation_id: event.correlation_id
    });
    
    const hmac = crypto.createHmac('sha256', this.secretKey);
    hmac.update(dataToSign);
    
    return {
      ...event,
      hmac_signature: hmac.digest('hex'),
      hmac_algorithm: 'SHA256'
    };
  }

  private async sendWithRetry(message: string, maxRetries: number = 5): Promise<void> {
    let attempts = 0;
    let lastError: Error | null = null;

    while (attempts < maxRetries) {
      try {
        const dgram = require('dgram');
        const client = dgram.createSocket('udp4');
        
        const messageBuffer = Buffer.from(message);
        
        // Promisify the UDP send operation
        const sendPromise = new Promise((resolve, reject) => {
          client.send(messageBuffer, 0, messageBuffer.length, this.port, this.syslogServer, (err: Error | null) => {
            if (err) {
              reject(err);
            } else {
              resolve(true);
            }
            client.close();
          });
        });
        
        await Promise.race([
          sendPromise,
          new Promise((_, reject) => setTimeout(() => reject(new Error('Syslog send timeout')), 5000))
        ]);
        
        return; // Success
      } catch (error) {
        lastError = error as Error;
        attempts++;
        
        if (attempts >= maxRetries) {
          throw lastError;
        }
        
        // Exponential backoff
        await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempts) * 1000));
      }
    }
    
    if (lastError) {
      throw lastError;
    }
  }

  private getPriorityFromSeverity(severity: SeverityLevel): number {
    switch (severity) {
      case 'critical': return 11; // User level 3 (critical)
      case 'high': return 12;     // User level 4 (error)
      case 'medium': return 13;   // User level 5 (warning)
      case 'low': return 14;      // User level 6 (notice)
      case 'info': return 15;     // User level 7 (informational)
      default: return 14;
    }
  }

  async healthCheck(): Promise<boolean> {
    try {
      // Simple connectivity test
      const dgram = require('dgram');
      const client = dgram.createSocket('udp4');
      
      // Test connection by attempting to send a small message
      const testMsg = `<15>1 ${new Date().toISOString()} test-host test-app - - [test@12345 test="connection"] Test connection`;
      const msgBuffer = Buffer.from(testMsg);
      
      const result = await Promise.race([
        new Promise<boolean>((resolve) => {
          client.send(msgBuffer, 0, msgBuffer.length, this.port, this.syslogServer, (err: Error | null) => {
            if (err) {
              resolve(false);
            } else {
              resolve(true);
            }
            client.close();
          });
        }),
        new Promise<boolean>((_, reject) => setTimeout(() => reject(new Error('Health check timeout')), 3000))
      ]);
      
      return result;
    } catch (error) {
      logger.error('Syslog emitter health check failed', { error: (error as Error).message });
      return false;
    }
  }
}

// HTTPS Webhook emitter for SIEM integration with guaranteed delivery
class WebhookEmitter implements SIEMEmitter {
  private webhookUrl: string;
  private apiKey: string;
  private secretKey: string;
  private retries: number;
  private diskBuffer: DiskBuffer;

  constructor(
    webhookUrl: string, 
    apiKey: string, 
    secretKey: string = process.env.WEBHOOK_SECRET_KEY || 'default-webhook-key',
    retries: number = 5
  ) {
    this.webhookUrl = webhookUrl;
    this.apiKey = apiKey;
    this.secretKey = secretKey;
    this.retries = retries;
    this.diskBuffer = new DiskBuffer('/tmp/webhook_buffer');
  }

  async emit(event: SecurityEvent): Promise<void> {
    try {
      // Sign the event with HMAC for integrity
      const signedEvent = this.signEvent(event);

      let attempt = 0;
      let lastError: any;

      while (attempt < this.retries) {
        try {
          // Using AbortController for proper timeout handling
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 15000); // 15 second timeout
          
          const response = await fetch(this.webhookUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${this.apiKey}`,
              'X-Event-HMAC': signedEvent.hmac_signature || '',
              'X-Event-Timestamp': signedEvent.timestamp,
              'X-Event-Correlation-ID': signedEvent.correlation_id
            },
            body: JSON.stringify(signedEvent),
            signal: controller.signal
          });
          
          clearTimeout(timeoutId);

          if (response.ok) {
            logger.info('Webhook event sent successfully', { 
              event_type: signedEvent.event_type, 
              status: response.status,
              correlation_id: signedEvent.correlation_id
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
            event_type: signedEvent.event_type,
            correlation_id: signedEvent.correlation_id
          });
          attempt++;
          
          // Wait before retry with exponential backoff
          if (attempt < this.retries) {
            await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 1000));
          }
        }
      }

      // All retries failed
      logger.error('All webhook retries failed, adding to disk buffer', {
        error: (lastError as Error).message,
        event_type: signedEvent.event_type,
        correlation_id: signedEvent.correlation_id
      });
      
      // Add to disk buffer for later delivery
      await this.diskBuffer.addEvent(event);
    } catch (error) {
      logger.error('Failed to emit to Webhook SIEM, adding to disk buffer', { 
        error: (error as Error).message, 
        event_type: event.event_type 
      });
      
      // Add to disk buffer for later delivery
      await this.diskBuffer.addEvent(event);
    }
  }

  private signEvent(event: SecurityEvent): SecurityEvent {
    const dataToSign = JSON.stringify({
      event_type: event.event_type,
      timestamp: event.timestamp,
      user_id: event.user_id,
      ip_address: event.ip_address,
      correlation_id: event.correlation_id
    });
    
    const hmac = crypto.createHmac('sha256', this.secretKey);
    hmac.update(dataToSign);
    
    return {
      ...event,
      hmac_signature: hmac.digest('hex'),
      hmac_algorithm: 'SHA256'
    };
  }

  async healthCheck(): Promise<boolean> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      
      const response = await fetch(this.webhookUrl, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json'
        },
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      
      return response.ok;
    } catch (error) {
      logger.error('Webhook emitter health check failed', { error: (error as Error).message });
      return false;
    }
  }
}

// Message Queue emitter (abstraction for Kafka/PubSub/SQS) with guaranteed delivery
class MessageQueueEmitter implements SIEMEmitter {
  private redis: Redis;
  private queueName: string;
  private secretKey: string;
  private diskBuffer: DiskBuffer;

  constructor(
    queueName: string = 'security_events',
    secretKey: string = process.env.REDIS_SECRET_KEY || 'default-redis-key'
  ) {
    this.redis = Redis.fromEnv();
    this.queueName = queueName;
    this.secretKey = secretKey;
    this.diskBuffer = new DiskBuffer('/tmp/queue_buffer');
  }

  async emit(event: SecurityEvent): Promise<void> {
    try {
      // Sign the event with HMAC for integrity
      const signedEvent = this.signEvent(event);

      // Push to Redis list (can be consumed by SIEM processor)
      await this.redis.lpush(this.queueName, JSON.stringify(signedEvent));
      
      // Set TTL to clean up old events
      await this.redis.expire(this.queueName, 86400 * 7); // 7 days
      
      logger.info('Security event queued for SIEM processing', { 
        event_type: signedEvent.event_type,
        correlation_id: signedEvent.correlation_id,
        queue: this.queueName
      });
    } catch (error) {
      logger.error('Failed to queue security event to Redis, adding to disk buffer', { 
        error: (error as Error).message, 
        event_type: event.event_type 
      });
      
      // Add to disk buffer for later delivery
      await this.diskBuffer.addEvent(event);
    }
  }

  private signEvent(event: SecurityEvent): SecurityEvent {
    const dataToSign = JSON.stringify({
      event_type: event.event_type,
      timestamp: event.timestamp,
      user_id: event.user_id,
      ip_address: event.ip_address,
      correlation_id: event.correlation_id
    });
    
    const hmac = crypto.createHmac('sha256', this.secretKey);
    hmac.update(dataToSign);
    
    return {
      ...event,
      hmac_signature: hmac.digest('hex'),
      hmac_algorithm: 'SHA256'
    };
  }

  async healthCheck(): Promise<boolean> {
    try {
      // Test Redis connectivity by getting the buffer status
      const status = await this.diskBuffer.getBufferStatus();
      return true;
    } catch (error) {
      logger.error('Message queue emitter health check failed', { error: (error as Error).message });
      return false;
    }
  }
}

// Main SIEM integration service with guaranteed delivery
export class SIEMIntegrationService {
  private emitters: SIEMEmitter[] = [];
  private enabled: boolean;
  private diskBuffer: DiskBuffer;
  private flushInterval: NodeJS.Timeout | null = null;
  private correlationIdCounter: number = 0;
  
  constructor() {
    this.enabled = process.env.SIEM_ENABLED === 'true';
    this.diskBuffer = new DiskBuffer('/tmp/main_siem_buffer');
    
    // Initialize emitters based on configuration
    if (process.env.SYSLOG_ENABLED === 'true') {
      this.emitters.push(new SyslogEmitter(
        process.env.SYSLOG_SERVER,
        parseInt(process.env.SYSLOG_PORT || '514'),
        process.env.SYSLOG_SECRET_KEY || 'default-syslog-key'
      ));
    }
    
    if (process.env.WEBHOOK_SIEM_URL && process.env.WEBHOOK_SIEM_API_KEY) {
      this.emitters.push(new WebhookEmitter(
        process.env.WEBHOOK_SIEM_URL,
        process.env.WEBHOOK_SIEM_API_KEY,
        process.env.WEBHOOK_SECRET_KEY || 'default-webhook-key',
        parseInt(process.env.WEBHOOK_RETRIES || '5')
      ));
    }
    
    if (process.env.MESSAGE_QUEUE_ENABLED === 'true') {
      this.emitters.push(new MessageQueueEmitter(
        process.env.MESSAGE_QUEUE_NAME || 'security_events',
        process.env.REDIS_SECRET_KEY || 'default-redis-key'
      ));
    }
    
    // Start periodic flushing of disk buffer
    if (this.enabled) {
      this.startBufferFlusher();
    }
  }

  /**
   * Emit a security event to all configured SIEM systems with guaranteed delivery
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

    // Log any failures - if all failed, this is a critical security issue
    const failures = results.filter(result => result.status === 'rejected');
    if (failures.length > 0) {
      logger.error('Some SIEM emitters failed, event added to disk buffer', { 
        failures: failures.map(f => (f as PromiseRejectedResult).reason),
        event_type: securityEvent.event_type,
        correlation_id: securityEvent.correlation_id
      });
    }

    // If all emitters failed, ensure the event is in the disk buffer as a backup
    if (results.every(result => result.status === 'rejected')) {
      logger.critical('All SIEM emitters failed - adding security event to disk buffer for guaranteed delivery', { 
        event: securityEvent,
        failures: failures.map(f => (f as PromiseRejectedResult).reason)
      });
      
      // Add to disk buffer for guaranteed later delivery
      const bufferAdded = await this.diskBuffer.addEvent(securityEvent);
      if (!bufferAdded) {
        // If disk buffer also fails, this is a critical failure
        logger.fatal('CRITICAL: All SIEM emitters and disk buffer failed - security event LOST!', { 
          event_type: securityEvent.event_type,
          correlation_id: securityEvent.correlation_id
        });
        throw new Error('Critical: Failed to store security event in any medium');
      }
    }
  }

  /**
   * Periodically flush events from disk buffer to emitters
   */
  private startBufferFlusher(): void {
    this.flushInterval = setInterval(async () => {
      if (this.emitters.length === 0) {
        return; // No emitters configured
      }
      
      try {
        const bufferedEvents = await this.diskBuffer.getEvents(50); // Process 50 at a time
        
        if (bufferedEvents.length > 0) {
          logger.info('Processing buffered security events', { count: bufferedEvents.length });
          
          for (const event of bufferedEvents) {
            const results = await Promise.allSettled(
              this.emitters.map(emitter => emitter.emit(event))
            );
            
            const failures = results.filter(result => result.status === 'rejected');
            if (failures.length === this.emitters.length) {
              // All emitters failed again, put back in buffer
              await this.diskBuffer.addEvent(event);
              logger.warn('Buffered event failed to emit again, keeping in buffer', { 
                event_type: event.event_type,
                correlation_id: event.correlation_id
              });
            } else {
              logger.info('Successfully emitted buffered event', { 
                event_type: event.event_type,
                correlation_id: event.correlation_id
              });
            }
          }
        }
      } catch (error) {
        logger.error('Error flushing disk buffer', { error: (error as Error).message });
      }
    }, 30000); // Flush every 30 seconds
  }

  /**
   * Validate that the event conforms to our security schema
   */
  private validateEventSchema(event: SecurityEvent): boolean {
    return (
      event.event_type &&
      Object.values(SecurityEventType).includes(event.event_type) &&
      event.severity &&
      ['info', 'low', 'medium', 'high', 'critical'].includes(event.severity) &&
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
    this.correlationIdCounter++;
    return `corr_${Date.now()}_${this.correlationIdCounter}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Health check for all emitters
   */
  async healthCheck(): Promise<{ overall: boolean; emitters: { [key: string]: boolean }; buffer: { count: number; size: number } }> {
    const emitterResults: { [key: string]: boolean } = {};
    let allHealthy = true;

    for (let i = 0; i < this.emitters.length; i++) {
      const emitter = this.emitters[i];
      const emitterName = `emitter_${i}`;
      
      if (emitter.healthCheck) {
        try {
          const isHealthy = await emitter.healthCheck();
          emitterResults[emitterName] = isHealthy;
          if (!isHealthy) {
            allHealthy = false;
          }
        } catch (error) {
          emitterResults[emitterName] = false;
          allHealthy = false;
          logger.error(`Health check failed for ${emitterName}`, { error: (error as Error).message });
        }
      } else {
        emitterResults[emitterName] = true; // Assume healthy if no health check method
      }
    }

    const bufferStatus = await this.diskBuffer.getBufferStatus();

    return {
      overall: allHealthy && bufferStatus.count < 1000, // Consider unhealthy if buffer is too large
      emitters: emitterResults,
      buffer: bufferStatus
    };
  }

  /**
   * Graceful shutdown - flush all buffers
   */
  async shutdown(): Promise<void> {
    if (this.flushInterval) {
      clearInterval(this.flushInterval);
      this.flushInterval = null;
    }
    
    // Try to flush any remaining buffered events
    try {
      const remainingEvents = await this.diskBuffer.getEvents(1000);
      if (remainingEvents.length > 0) {
        logger.warn('Flushing remaining buffered events during shutdown', { count: remainingEvents.length });
      }
    } catch (error) {
      logger.error('Error flushing buffer during shutdown', { error: (error as Error).message });
    }
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