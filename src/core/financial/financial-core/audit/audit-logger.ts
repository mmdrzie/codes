import { createHash, randomBytes } from 'crypto';
import { logger } from '../logger';
import { getLedger } from '../ledger/immutable-ledger';

export interface AuditEvent {
  id: string;
  timestamp: number;
  eventType: string;
  userId?: string;
  sessionId?: string;
  ipAddress?: string;
  userAgent?: string;
  action: string;
  resource: string;
  outcome: 'success' | 'failure' | 'error';
  details: Record<string, any>;
  correlationId: string;
  signature: string; // Cryptographic signature of the event
}

export interface AuditConfig {
  logSensitiveOperations: boolean;
  retentionPeriodDays: number;
  enableRealTimeAlerts: boolean;
  criticalEvents: string[];
}

export class AuditLogger {
  private readonly config: AuditConfig;
  private readonly events: AuditEvent[] = [];
  private readonly privateKey: Buffer;
  private readonly publicKey: Buffer;

  constructor(config?: Partial<AuditConfig>) {
    this.config = {
      logSensitiveOperations: config?.logSensitiveOperations ?? true,
      retentionPeriodDays: config?.retentionPeriodDays ?? 365,
      enableRealTimeAlerts: config?.enableRealTimeAlerts ?? true,
      criticalEvents: config?.criticalEvents ?? [
        'account_access', 
        'transaction_attempt', 
        'admin_action', 
        'security_event',
        'wallet_creation',
        'balance_change'
      ]
    };

    // In production, these should come from HSM
    const { privateKey, publicKey } = this.generateKeyPair();
    this.privateKey = privateKey;
    this.publicKey = publicKey;

    logger.info('Audit Logger initialized', {
      component: 'audit',
      config: this.config
    });
  }

  /**
   * Log a financial action with full audit trail
   */
  async logFinancialAction(eventType: string, details: Record<string, any>): Promise<AuditEvent> {
    const event: AuditEvent = {
      id: this.generateId(),
      timestamp: Date.now(),
      eventType,
      action: details.action || eventType,
      resource: details.resource || 'unknown',
      outcome: details.outcome || 'success',
      details,
      correlationId: details.correlationId || this.generateCorrelationId(),
      userId: details.userId,
      sessionId: details.sessionId,
      ipAddress: details.ipAddress,
      userAgent: details.userAgent,
      signature: ''
    };

    // Sign the event for non-repudiation
    event.signature = await this.signEvent(event);

    // Store in local array (in production, this would go to secure audit log storage)
    this.events.push(event);

    // Log to main logger as well
    logger.audit(`Financial Action: ${eventType}`, {
      ...details,
      eventId: event.id,
      correlationId: event.correlationId
    });

    // Check if this is a critical event that requires immediate attention
    if (this.config.criticalEvents.includes(eventType) && this.config.enableRealTimeAlerts) {
      this.handleCriticalEvent(event);
    }

    // Also record in the immutable ledger for financial transactions
    if (eventType.startsWith('transaction') || eventType.includes('balance')) {
      const ledger = getLedger();
      await ledger.addEntry({
        transactionId: event.id,
        userId: event.userId || 'system',
        action: event.action as any,
        amount: details.amount,
        currency: details.currency,
        fromWallet: details.fromWallet,
        toWallet: details.toWallet,
        status: event.outcome === 'success' ? 'confirmed' : 'failed',
        metadata: {
          ...details,
          auditEventId: event.id,
          ipAddress: event.ipAddress
        }
      });
    }

    return event;
  }

  /**
   * Log a security event
   */
  async logSecurityEvent(eventType: string, details: Record<string, any>): Promise<AuditEvent> {
    const event: AuditEvent = {
      id: this.generateId(),
      timestamp: Date.now(),
      eventType,
      action: details.action || eventType,
      resource: details.resource || 'unknown',
      outcome: details.outcome || 'success',
      details,
      correlationId: details.correlationId || this.generateCorrelationId(),
      userId: details.userId,
      sessionId: details.sessionId,
      ipAddress: details.ipAddress,
      userAgent: details.userAgent,
      signature: ''
    };

    // Sign the event for non-repudiation
    event.signature = await this.signEvent(event);

    // Store in local array (in production, this would go to secure audit log storage)
    this.events.push(event);

    // Log to main logger as well
    logger.securityEvent(`Security Event: ${eventType}`, {
      ...details,
      eventId: event.id,
      correlationId: event.correlationId
    });

    // Handle critical security events
    this.handleCriticalEvent(event);

    return event;
  }

  /**
   * Verify the integrity of an audit event
   */
  async verifyEventSignature(event: AuditEvent): Promise<boolean> {
    try {
      // Create a copy of the event without the signature for verification
      const { signature, ...unsignedEvent } = event;
      
      const serialized = JSON.stringify(unsignedEvent, Object.keys(unsignedEvent).sort());
      const expectedSignature = createHash('sha256')
        .update(serialized)
        .digest('hex');

      return signature === expectedSignature;
    } catch (error) {
      logger.error('Audit event signature verification failed', {
        component: 'audit',
        error: error instanceof Error ? error.message : String(error),
        eventId: event.id
      });
      return false;
    }
  }

  /**
   * Get audit events by user
   */
  getEventsByUser(userId: string): AuditEvent[] {
    return this.events.filter(event => event.userId === userId);
  }

  /**
   * Get audit events by type
   */
  getEventsByType(eventType: string): AuditEvent[] {
    return this.events.filter(event => event.eventType === eventType);
  }

  /**
   * Get audit events by time range
   */
  getEventsByTimeRange(startTime: number, endTime: number): AuditEvent[] {
    return this.events.filter(event => 
      event.timestamp >= startTime && event.timestamp <= endTime
    );
  }

  /**
   * Verify the integrity of all audit logs
   */
  async verifyAuditLogIntegrity(): Promise<boolean> {
    for (const event of this.events) {
      if (!(await this.verifyEventSignature(event))) {
        logger.error('Audit log integrity violation detected', {
          component: 'audit',
          eventId: event.id
        });
        return false;
      }
    }
    return true;
  }

  /**
   * Export audit events (in production, this would be to secure storage)
   */
  exportEvents(): AuditEvent[] {
    // Return a deep copy to prevent modification
    return JSON.parse(JSON.stringify(this.events));
  }

  private generateId(): string {
    return `audit-${Date.now()}-${randomBytes(8).toString('hex')}`;
  }

  private generateCorrelationId(): string {
    return randomBytes(16).toString('hex');
  }

  private generateKeyPair(): { privateKey: Buffer; publicKey: Buffer } {
    // In production, keys should come from HSM
    // This is for demonstration purposes only
    const { generateKeyPairSync } = require('crypto') as typeof import('crypto');
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: 'prime256v1'
    });
    
    return {
      privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }),
      publicKey: publicKey.export({ type: 'spki', format: 'der' })
    };
  }

  private async signEvent(event: AuditEvent): Promise<string> {
    // Create a copy of the event without the signature for signing
    const { signature: _, ...unsignedEvent } = event;
    
    const serialized = JSON.stringify(unsignedEvent, Object.keys(unsignedEvent).sort());
    
    // In production, this would be signed by an HSM
    // For now, we use a simple hash-based signature
    return createHash('sha256')
      .update(serialized)
      .digest('hex');
  }

  private handleCriticalEvent(event: AuditEvent): void {
    logger.emergency(`CRITICAL EVENT DETECTED: ${event.eventType}`, {
      component: 'audit',
      eventId: event.id,
      userId: event.userId,
      action: event.action,
      resource: event.resource,
      details: event.details
    });

    // In production, this would trigger alerts to security team
    // and potentially engage the kill switch
  }
}

// Global instance
let auditLogger: AuditLogger | null = null;

export function getAuditLogger(): AuditLogger {
  if (!auditLogger) {
    auditLogger = new AuditLogger();
  }
  return auditLogger;
}

// Convenience functions for common audit operations
export async function auditFinancialAction(
  eventType: string, 
  details: Record<string, any>
): Promise<AuditEvent> {
  const auditor = getAuditLogger();
  return await auditor.logFinancialAction(eventType, details);
}

export async function auditSecurityEvent(
  eventType: string, 
  details: Record<string, any>
): Promise<AuditEvent> {
  const auditor = getAuditLogger();
  return await auditor.logSecurityEvent(eventType, details);
}