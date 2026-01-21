/**
 * Financial Security Bindings
 * Cryptographic binding between ledger entries, transaction IDs, actor identity,
 * device/session fingerprint, and timestamp
 */

import { Redis } from '@upstash/redis';
import { logger } from '../logger';
import { SecurityMonitor } from '../security-monitoring';
import { siemService } from '../siem-integration';
import { AppJwtPayload } from '../tokenUtils';
import { verifyAccessToken } from '../tokenUtils';
import { FinancialCore, FinancialTransaction, LedgerEntry } from './index';

// Redis for security state management
const redis = Redis.fromEnv();
const SECURITY_BINDINGS_PREFIX = 'security_binding:';
const TRANSACTION_IDENTITY_BINDINGS = 'tx_identity_bindings:';
const DEVICE_SESSION_BINDINGS = 'device_session_bindings:';

// Security binding interface
export interface SecurityBinding {
  transactionId: string;
  userId: string;
  sessionId?: string;
  deviceId?: string;
  ipAddress: string;
  userAgent: string;
  timestamp: number;
  tokenJti?: string; // JWT unique identifier
  signature: string; // Cryptographic binding signature
  encryptedPayload: string; // Encrypted transaction details
  bindingHash: string; // Hash of the binding
}

// Enhanced security context for financial operations
export interface FinancialSecurityContext {
  userId: string;
  sessionId?: string;
  deviceId?: string;
  ipAddress: string;
  userAgent: string;
  tokenJti?: string;
  timestamp: number;
}

export class FinancialSecurityBindings {
  /**
   * Create a cryptographic binding between a transaction and security context
   */
  static async createTransactionBinding(
    transaction: FinancialTransaction,
    securityContext: FinancialSecurityContext
  ): Promise<SecurityBinding> {
    try {
      const binding: SecurityBinding = {
        transactionId: transaction.id,
        userId: securityContext.userId,
        sessionId: securityContext.sessionId,
        deviceId: securityContext.deviceId,
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        timestamp: securityContext.timestamp,
        tokenJti: securityContext.tokenJti,
        bindingHash: this.computeBindingHash(transaction, securityContext),
        signature: await this.generateBindingSignature(transaction, securityContext),
        encryptedPayload: this.encryptTransactionDetails(transaction)
      };

      // Store the binding
      const bindingKey = `${SECURITY_BINDINGS_PREFIX}${transaction.id}`;
      await redis.setex(bindingKey, 86400 * 30, JSON.stringify(binding)); // Keep for 30 days

      // Create binding index
      await redis.sadd(
        `${TRANSACTION_IDENTITY_BINDINGS}${securityContext.userId}`,
        transaction.id
      );

      logger.info('Financial transaction binding created', {
        transactionId: transaction.id,
        userId: securityContext.userId,
        ipAddress: securityContext.ipAddress
      });

      return binding;
    } catch (error) {
      logger.error('Failed to create transaction binding', {
        transactionId: transaction.id,
        userId: securityContext.userId,
        error: (error as Error).message
      });

      await SecurityMonitor.logAuthFailure(
        securityContext.userId,
        {
          ipAddress: securityContext.ipAddress,
          userAgent: securityContext.userAgent,
          timestamp: new Date(),
          metadata: {
            transactionId: transaction.id,
            operation: 'create_binding',
            error: (error as Error).message
          }
        },
        'Failed to create financial transaction binding'
      );

      throw error;
    }
  }

  /**
   * Verify a transaction binding
   */
  static async verifyTransactionBinding(
    transactionId: string,
    securityContext: FinancialSecurityContext
  ): Promise<boolean> {
    try {
      const bindingKey = `${SECURITY_BINDINGS_PREFIX}${transactionId}`;
      const bindingStr = await redis.get(bindingKey);

      if (!bindingStr) {
        logger.warn('Transaction binding not found', {
          transactionId,
          userId: securityContext.userId
        });

        return false;
      }

      const binding = JSON.parse(bindingStr as string) as SecurityBinding;

      // Verify the binding hash
      const expectedHash = this.computeBindingHash(
        { id: transactionId } as FinancialTransaction,
        securityContext
      );

      if (binding.bindingHash !== expectedHash) {
        logger.error('Transaction binding hash verification failed', {
          transactionId,
          userId: securityContext.userId
        });

        await SecurityMonitor.logAuthFailure(
          securityContext.userId,
          {
            ipAddress: securityContext.ipAddress,
            userAgent: securityContext.userAgent,
            timestamp: new Date(),
            metadata: {
              transactionId,
              operation: 'verify_binding_hash',
              check: 'hash_verification_failed'
            }
          },
          'Transaction binding hash verification failed'
        );

        return false;
      }

      // Verify the signature
      const signatureValid = await this.verifyBindingSignature(
        { id: transactionId } as FinancialTransaction,
        securityContext,
        binding.signature
      );

      if (!signatureValid) {
        logger.error('Transaction binding signature verification failed', {
          transactionId,
          userId: securityContext.userId
        });

        await SecurityMonitor.logAuthFailure(
          securityContext.userId,
          {
            ipAddress: securityContext.ipAddress,
            userAgent: securityContext.userAgent,
            timestamp: new Date(),
            metadata: {
              transactionId,
              operation: 'verify_binding_signature',
              check: 'signature_verification_failed'
            }
          },
          'Transaction binding signature verification failed'
        );

        return false;
      }

      logger.info('Transaction binding verified successfully', {
        transactionId,
        userId: securityContext.userId
      });

      return true;
    } catch (error) {
      logger.error('Transaction binding verification error', {
        transactionId,
        userId: securityContext.userId,
        error: (error as Error).message
      });

      await SecurityMonitor.logAuthFailure(
        securityContext.userId,
        {
          ipAddress: securityContext.ipAddress,
          userAgent: securityContext.userAgent,
          timestamp: new Date(),
          metadata: {
            transactionId,
            operation: 'verify_binding_error',
            error: (error as Error).message
          }
        },
        'Transaction binding verification error'
      );

      return false;
    }
  }

  /**
   * Validate security context from JWT token
   */
  static async validateSecurityContextFromToken(
    token: string,
    ipAddress: string,
    userAgent: string
  ): Promise<FinancialSecurityContext | null> {
    try {
      const tokenPayload = await verifyAccessToken(token);
      
      if (!tokenPayload) {
        logger.warn('Invalid access token for financial operation', {
          token: token.substring(0, 10) + '...',
          ipAddress
        });

        await SecurityMonitor.logAuthFailure(
          tokenPayload?.userId || null,
          {
            ipAddress,
            userAgent,
            timestamp: new Date(),
            metadata: {
              operation: 'validate_security_context',
              check: 'invalid_token'
            }
          },
          'Invalid access token for financial operation'
        );

        return null;
      }

      // Validate session/device binding if present
      if (tokenPayload.deviceFingerprint) {
        const bindingValid = await this.validateDeviceBinding(
          tokenPayload.userId,
          tokenPayload.deviceFingerprint,
          ipAddress,
          userAgent
        );

        if (!bindingValid) {
          logger.warn('Device binding validation failed', {
            userId: tokenPayload.userId,
            ipAddress,
            userAgent
          });

          await SecurityMonitor.logDeviceBindingViolation(
            {
              userId: tokenPayload.userId,
              ipAddress,
              userAgent,
              timestamp: new Date(),
              metadata: {
                operation: 'validate_device_binding',
                check: 'binding_violation'
              }
            },
            JSON.stringify(tokenPayload.deviceFingerprint),
            `${ipAddress}/${userAgent}`
          );

          return null;
        }
      }

      const securityContext: FinancialSecurityContext = {
        userId: tokenPayload.userId,
        sessionId: tokenPayload.jti,
        deviceId: tokenPayload.deviceFingerprint?.sessionId,
        ipAddress,
        userAgent,
        tokenJti: tokenPayload.jti,
        timestamp: Date.now()
      };

      logger.info('Security context validated successfully', {
        userId: tokenPayload.userId,
        ipAddress,
        userAgent
      });

      return securityContext;
    } catch (error) {
      logger.error('Security context validation error', {
        error: (error as Error).message,
        ipAddress,
        userAgent
      });

      await SecurityMonitor.logAuthFailure(
        null,
        {
          ipAddress,
          userAgent,
          timestamp: new Date(),
          metadata: {
            operation: 'validate_security_context_error',
            error: (error as Error).message
          }
        },
        'Security context validation error'
      );

      return null;
    }
  }

  /**
   * Validate device/session binding
   */
  private static async validateDeviceBinding(
    userId: string,
    deviceFingerprint: any,
    currentIpAddress: string,
    currentUserAgent: string
  ): Promise<boolean> {
    // Check if the device fingerprint matches the current request
    if (deviceFingerprint.ipAddress && deviceFingerprint.ipAddress !== currentIpAddress) {
      logger.warn('IP address binding violation', {
        userId,
        expected: deviceFingerprint.ipAddress,
        actual: currentIpAddress
      });
      return false;
    }

    if (deviceFingerprint.userAgent && !currentUserAgent.includes(deviceFingerprint.userAgent)) {
      logger.warn('User agent binding violation', {
        userId,
        expected: deviceFingerprint.userAgent,
        actual: currentUserAgent
      });
      return false;
    }

    return true;
  }

  /**
   * Compute binding hash
   */
  private static computeBindingHash(
    transaction: Pick<FinancialTransaction, 'id'>,
    securityContext: FinancialSecurityContext
  ): string {
    const crypto = require('crypto');
    const data = JSON.stringify({
      transactionId: transaction.id,
      userId: securityContext.userId,
      sessionId: securityContext.sessionId,
      deviceId: securityContext.deviceId,
      ipAddress: securityContext.ipAddress,
      userAgent: securityContext.userAgent,
      timestamp: securityContext.timestamp,
      tokenJti: securityContext.tokenJti
    });

    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Generate binding signature
   */
  private static async generateBindingSignature(
    transaction: FinancialTransaction,
    securityContext: FinancialSecurityContext
  ): Promise<string> {
    // In a real system, this would use proper cryptographic signing
    // For now, we'll use a simple hash-based approach
    const crypto = require('crypto');
    const data = JSON.stringify({
      transactionId: transaction.id,
      userId: securityContext.userId,
      timestamp: securityContext.timestamp
    });

    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Verify binding signature
   */
  private static async verifyBindingSignature(
    transaction: Pick<FinancialTransaction, 'id'>,
    securityContext: FinancialSecurityContext,
    signature: string
  ): Promise<boolean> {
    // Recompute the expected signature
    const expectedSignature = await this.generateBindingSignature(
      transaction as FinancialTransaction,
      securityContext
    );

    // Compare signatures securely
    const crypto = require('crypto');
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  }

  /**
   * Encrypt transaction details
   */
  private static encryptTransactionDetails(transaction: FinancialTransaction): string {
    // For this implementation, we'll just serialize the transaction
    // In a real system, this would use proper encryption
    return JSON.stringify({
      id: transaction.id,
      type: transaction.type,
      amount: transaction.amount,
      description: transaction.description,
      timestamp: transaction.timestamp
    });
  }

  /**
   * Authenticate and authorize a financial operation
   */
  static async authenticateFinancialOperation(
    token: string,
    ipAddress: string,
    userAgent: string,
    operation: 'transfer' | 'deposit' | 'withdraw' | 'balance_check' | 'statement'
  ): Promise<FinancialSecurityContext | null> {
    // Validate security context from token
    const securityContext = await this.validateSecurityContextFromToken(
      token,
      ipAddress,
      userAgent
    );

    if (!securityContext) {
      return null;
    }

    // Additional security checks based on operation type
    switch (operation) {
      case 'transfer':
      case 'withdraw':
        // These operations might require additional MFA or higher privileges
        logger.info('Sensitive financial operation authenticated', {
          userId: securityContext.userId,
          operation,
          ipAddress: securityContext.ipAddress
        });
        break;
      case 'balance_check':
      case 'statement':
        // These are less sensitive but still require authentication
        logger.info('Standard financial operation authenticated', {
          userId: securityContext.userId,
          operation,
          ipAddress: securityContext.ipAddress
        });
        break;
      default:
        logger.info('Financial operation authenticated', {
          userId: securityContext.userId,
          operation,
          ipAddress: securityContext.ipAddress
        });
    }

    return securityContext;
  }

  /**
   * Enforce both PQ and classical signature verification for financial operations
   */
  static async enforceHybridSignatureVerification(
    message: string,
    pqSignature: Uint8Array,
    classicalSignature: Uint8Array,
    pqPublicKey: Uint8Array,
    classicalPublicKey: Uint8Array
  ): Promise<boolean> {
    try {
      // Import the PQ crypto service dynamically to avoid circular dependencies
      const { PQCryptoService } = await import('../services/crypto/pq-crypto-service');
      
      // Verify both signatures independently
      const pqValid = await PQCryptoService.verifyPQSignature(
        new TextEncoder().encode(message),
        pqSignature,
        pqPublicKey
      );
      
      const classicalValid = await PQCryptoService.verifyClassicalSignature(
        new TextEncoder().encode(message),
        classicalSignature,
        classicalPublicKey
      );

      // Both signatures must be valid
      const bothValid = pqValid && classicalValid;

      if (!bothValid) {
        logger.error('Hybrid signature verification failed', {
          pqValid,
          classicalValid
        });

        // Log security event
        await SecurityMonitor.logPqSignatureInvalid(
          {
            timestamp: new Date(),
            metadata: {
              verificationType: 'hybrid_signature',
              pqValid,
              classicalValid,
              operation: 'financial_operation'
            }
          },
          `Hybrid signature verification failed - PQ: ${pqValid}, Classical: ${classicalValid}`
        );
      } else {
        logger.info('Hybrid signature verification succeeded');
      }

      return bothValid;
    } catch (error) {
      logger.error('Hybrid signature verification error', {
        error: (error as Error).message
      });

      await SecurityMonitor.logPqCryptoError(
        {
          timestamp: new Date(),
          metadata: {
            operation: 'hybrid_signature_verification',
            error: (error as Error).message
          }
        },
        (error as Error).message,
        'hybrid_signature_verification'
      );

      return false;
    }
  }

  /**
   * Handle SIEM failure by tripping circuit breaker
   */
  static async handleSIEMFailure(): Promise<void> {
    logger.error('SIEM system failure detected - tripping circuit breaker');

    // Set circuit breaker flag
    await redis.setex('circuit_breaker_siem_failure', 300, 'true'); // 5 minutes

    // Log to local system as backup
    console.error('CRITICAL: SIEM system failure - circuit breaker engaged');

    // Trigger emergency procedures
    await SecurityMonitor.logAuthFailure(
      null,
      {
        ipAddress: 'system',
        userAgent: 'Financial Core',
        timestamp: new Date(),
        metadata: {
          operation: 'siem_failure',
          action: 'circuit_breaker_engaged',
          duration: 300 // 5 minutes
        }
      },
      'SIEM system failure - stopping state-changing operations'
    );

    // In a real system, you might want to stop accepting new transactions
    // until SIEM is restored
  }

  /**
   * Check if circuit breaker is active
   */
  static async isCircuitBreakerActive(): Promise<boolean> {
    const breaker = await redis.get('circuit_breaker_siem_failure');
    return !!breaker;
  }
}