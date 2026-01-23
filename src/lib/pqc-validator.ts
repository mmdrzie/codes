/**
 * Post-Quantum Cryptography Validator
 * Ensures the system fails closed if PQC libraries are unavailable
 */

import { logger } from './logger';
import { PQCryptoService } from '../services/crypto/pq-crypto-service';
import { siemService } from './siem-integration';
import { SecurityEventType } from './siem-integration';

export class PQCValidator {
  private static isInitialized = false;
  private static pqcAvailable = false;

  /**
   * Validates that post-quantum cryptographic libraries are available
   * System will fail closed if PQC is not available
   */
  static async validatePQC(): Promise<boolean> {
    try {
      // Check for Open Quantum Safe (OQS) library availability
      const oqsAvailable = await this.checkOQSAvailability();
      
      // Check for other PQC library availability (like PQClean, liboqs-js, etc.)
      const otherPQCLibsAvailable = await this.checkOtherPQCLibraries();
      
      // Check for hybrid signature capability
      const hybridCapability = await this.checkHybridSignatureCapability();
      
      // Combine all checks
      this.pqcAvailable = oqsAvailable && otherPQCLibsAvailable && hybridCapability;
      
      if (!this.pqcAvailable) {
        const errorMsg = 'Post-Quantum Cryptography libraries are not available. System failing closed.';
        logger.error(errorMsg);
        
        // Log security event to SIEM
        await this.logSecurityEvent({
          eventType: 'PQC_UNAVAILABLE',
          severity: 'critical',
          message: errorMsg,
          timestamp: new Date().toISOString()
        });
        
        // Throw error to cause system failure (fail closed)
        throw new Error(errorMsg);
      }
      
      logger.info('Post-Quantum Cryptography validation passed');
      this.isInitialized = true;
      return true;
    } catch (error) {
      logger.error('PQC validation failed', { error: (error as Error).message });
      // Log the error to SIEM
      await this.logSecurityEvent({
        eventType: 'PQC_VALIDATION_FAILED',
        severity: 'critical',
        message: `PQC validation failed: ${(error as Error).message}`,
        timestamp: new Date().toISOString(),
        details: { error: (error as Error).message }
      });
      throw error; // Re-throw to ensure system fails closed
    }
  }

  /**
   * Checks for Open Quantum Safe (OQS) library availability
   */
  private static async checkOQSAvailability(): Promise<boolean> {
    try {
      // Use the PQCryptoService to check if real OQS is supported
      const isSupported = PQCryptoService.isRealPQSupported();
      
      if (isSupported) {
        logger.info('OQS library available and functional');
        return true;
      } else {
        logger.warn('OQS library not available or not functional');
        return false;
      }
    } catch (error) {
      logger.warn('OQS library check failed', { error: (error as Error).message });
      return false;
    }
  }

  /**
   * Checks for other PQC libraries availability
   */
  private static async checkOtherPQCLibraries(): Promise<boolean> {
    try {
      // Get PQ status from the service
      const pqStatus = PQCryptoService.getPQStatus();
      
      if (pqStatus.isAvailable && pqStatus.isRealPQ) {
        logger.info('PQC libraries available', { 
          available: pqStatus.algorithms 
        });
        return true;
      } else {
        logger.warn('No PQC libraries available or using simulated crypto');
        return false;
      }
    } catch (error) {
      logger.warn('Other PQC libraries check failed', { error: (error as Error).message });
      return false;
    }
  }

  /**
   * Checks for hybrid signature capability (Ed25519 + SLH-DSA)
   */
  private static async checkHybridSignatureCapability(): Promise<boolean> {
    try {
      // Try to generate and verify a hybrid signature to ensure the capability works
      const testMessage = new TextEncoder().encode('test message for hybrid signature validation');
      
      // Generate a test key pair
      const keyPair = await PQCryptoService.generateHybridKeyPair();
      
      // Generate a hybrid signature
      const signature = await PQCryptoService.generateHybridSignature(
        testMessage,
        keyPair.pqPrivateKey,
        keyPair.classicalPrivateKey
      );
      
      // Verify the hybrid signature
      const isValid = await PQCryptoService.verifyHybridSignature(
        testMessage,
        signature,
        keyPair.pqPublicKey,
        keyPair.classicalPublicKey
      );
      
      if (isValid) {
        logger.info('Hybrid signature capability confirmed');
        return true;
      } else {
        logger.warn('Hybrid signature capability failed validation');
        return false;
      }
    } catch (error) {
      logger.warn('Hybrid signature capability check failed', { error: (error as Error).message });
      return false;
    }
  }

  /**
   * Logs security events to SIEM
   */
  private static async logSecurityEvent(event: {
    eventType: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    message: string;
    timestamp: string;
    details?: any;
  }): Promise<void> {
    try {
      // Map our event type to SIEM event type
      let siemEventType: SecurityEventType = SecurityEventType.SUSPICIOUS_ACTIVITY;
      
      switch (event.eventType) {
        case 'PQC_UNAVAILABLE':
          siemEventType = SecurityEventType.AUTH_FAILURE;
          break;
        case 'PQC_VALIDATION_FAILED':
          siemEventType = SecurityEventType.AUTH_FAILURE;
          break;
        default:
          siemEventType = SecurityEventType.SUSPICIOUS_ACTIVITY;
      }
      
      // Determine severity
      let siemSeverity: 'low' | 'medium' | 'high' | 'critical' = event.severity;
      
      // Emit to SIEM
      await siemService.emitSecurityEvent({
        event_type: siemEventType,
        severity: siemSeverity,
        ip_address: 'system',
        user_agent: 'system',
        route: 'security',
        outcome: 'failure',
        source: 'application',
        details: {
          original_event_type: event.eventType,
          message: event.message,
          ...event.details
        }
      });
    } catch (error) {
      logger.error('Failed to log security event to SIEM', { error: (error as Error).message });
      // Don't throw here as it would cause a cascade failure
    }
  }

  /**
   * Checks if PQC validation has been completed
   */
  static isPQCValidated(): boolean {
    return this.isInitialized && this.pqcAvailable;
  }

  /**
   * Gets PQC validation status
   */
  static getPQCStatus(): {
    initialized: boolean;
    available: boolean;
    valid: boolean;
  } {
    return {
      initialized: this.isInitialized,
      available: this.pqcAvailable,
      valid: this.isInitialized && this.pqcAvailable
    };
  }
}

/**
 * Wrapper function to ensure PQC validation happens before any crypto operations
 */
export async function ensurePQCValidation(): Promise<void> {
  if (!PQCValidator.isPQCValidated()) {
    await PQCValidator.validatePQC();
  }
}

/**
 * Function to perform PQC operations (ensures validation first)
 */
export async function performPQCOps<T>(operation: () => Promise<T>): Promise<T> {
  // Ensure PQC is validated before proceeding
  await ensurePQCValidation();
  
  // Perform the operation
  return await operation();
}