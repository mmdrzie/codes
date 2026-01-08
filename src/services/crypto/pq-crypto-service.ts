import { logger } from '@/lib/logger';

/**
 * Security monitoring service for cryptographic operations
 * This replaces the fake post-quantum crypto service with proper security monitoring
 */
export class SecurityMonitoringService {
  /**
   * Monitor cryptographic operations for security events
   */
  static async monitorCryptoOperation(operation: string, details: Record<string, any>) {
    logger.info('Cryptographic operation monitored', {
      operation,
      timestamp: new Date().toISOString(),
      ...details
    });
  }

  /**
   * Monitor signature generation
   */
  static async monitorSignatureGeneration(address: string, domain: string, chainId: number) {
    logger.info('Signature generation monitored', {
      address,
      domain,
      chainId,
      timestamp: new Date().toISOString(),
      operation: 'signature_generation'
    });
  }

  /**
   * Monitor signature verification
   */
  static async monitorSignatureVerification(address: string, domain: string, isValid: boolean) {
    logger.info('Signature verification monitored', {
      address,
      domain,
      isValid,
      timestamp: new Date().toISOString(),
      operation: 'signature_verification'
    });

    if (!isValid) {
      logger.warn('Invalid signature detected', {
        address,
        domain,
        timestamp: new Date().toISOString(),
        operation: 'invalid_signature'
      });
    }
  }

  /**
   * Monitor potential security threats
   */
  static async monitorSecurityThreat(threatType: string, details: Record<string, any>) {
    logger.warn('Security threat detected', {
      threatType,
      timestamp: new Date().toISOString(),
      ...details
    });
  }

  /**
   * Monitor authentication attempts
   */
  static async monitorAuthAttempt(address: string, success: boolean, reason?: string) {
    if (success) {
      logger.info('Successful authentication', {
        address,
        timestamp: new Date().toISOString(),
        operation: 'auth_success'
      });
    } else {
      logger.warn('Failed authentication', {
        address,
        reason,
        timestamp: new Date().toISOString(),
        operation: 'auth_failure'
      });
    }
  }

  /**
   * Monitor suspicious activities
   */
  static async monitorSuspiciousActivity(activityType: string, address: string, details: Record<string, any>) {
    logger.warn('Suspicious activity detected', {
      activityType,
      address,
      timestamp: new Date().toISOString(),
      ...details
    });
  }
}