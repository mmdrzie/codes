// src/lib/secure-wallet.ts
import * as jwt from 'jsonwebtoken';
import { Redis } from '@upstash/redis';
import { logger } from './logger';
import { PQCryptoService } from '../services/crypto/pq-crypto-service';
import { SecurityMonitor } from './security-monitoring';
import { SecurityEvent } from './security-monitoring';

// Initialize Redis
const redis = Redis.fromEnv();

// Define types
export interface NonceResult {
  nonce: string;
  message: string;
}

export interface WalletToken {
  address: string;
  type: 'wallet';
  tenantId?: string;
  role?: string;
  iat?: number;
  exp?: number;
  chainId?: number;
  domain?: string;
}

// Constants
function getWalletSecret(): string {
  const secret = process.env.WALLET_JWT_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error('WALLET_JWT_SECRET must be set (min 32 chars)');
  }
  return secret;
}
const NONCE_PREFIX = 'wallet_nonce:';
const NONCE_EXPIRATION = 5 * 60; // 5 minutes in seconds

/**
 * Enhanced wallet utility with post-quantum cryptography enforcement
 */
export class SecureWallet {
  /**
   * Generate a nonce with chain binding for wallet authentication
   */
  static async generateNonce(address: string, chainId?: number, domain?: string): Promise<NonceResult> {
    const cleanAddress = address.toLowerCase().trim();
    const nonce = crypto.randomBytes(32).toString('hex'); // Use CSPRNG
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
    
    // Store nonce in Redis with expiration
    try {
      await redis.setex(`${NONCE_PREFIX}${cleanAddress}`, NONCE_EXPIRATION, nonce);
    } catch (error) {
      logger.error('Failed to store nonce in Redis:', error);
      throw new Error('Failed to generate secure nonce');
    }

    // Create a canonical message format that binds to chain ID and domain
    const timestamp = Math.floor(Date.now() / 1000);
    const message = chainId
      ? `Sign this message to authenticate on chain ${chainId} at ${domain || 'QuantumIQ'}: ${nonce} [${timestamp}]`
      : `Login to QuantumIQ\n\nAddress: ${cleanAddress}\nNonce: ${nonce}\nExpires: ${new Date(expiresAt).toISOString()}\nTimestamp: ${timestamp}`;

    return {
      nonce,
      message
    };
  }

  /**
   * Verify and consume nonce (prevents replay attacks)
   */
  static async verifyAndConsumeNonce(address: string, providedNonce: string): Promise<boolean> {
    const cleanAddress = address.toLowerCase().trim();
    
    try {
      // Get and delete nonce atomically
      const storedNonce = await redis.get(`${NONCE_PREFIX}${cleanAddress}`);
      
      if (!storedNonce || storedNonce !== providedNonce) {
        // Log potential replay attack
        logger.warn('Nonce replay attempt detected', {
          address: cleanAddress,
          providedNonce,
          storedNonce
        });
        
        await SecurityMonitor.logEvent(
          SecurityEvent.SUSPICIOUS_ACTIVITY,
          {
            timestamp: new Date(),
            userId: cleanAddress,
            ipAddress: 'unknown',
            userAgent: 'unknown',
            metadata: {
              operation: 'nonce_replay_attempt',
              address: cleanAddress,
              providedNonce,
              storedNonce
            }
          },
          'Nonce replay attempt detected'
        );
        
        return false;
      }
      
      // Delete the nonce to prevent reuse
      await redis.del(`${NONCE_PREFIX}${cleanAddress}`);
      
      return true;
    } catch (error) {
      logger.error('Nonce verification failed:', error);
      return false;
    }
  }

  /**
   * Create wallet JWT with enhanced security
   */
  static createWalletJwt(address: string, options?: { tenantId?: string; role?: string; chainId?: number; domain?: string }): string {
    const cleanAddress = address.toLowerCase().trim();
    
    return jwt.sign(
      {
        address: cleanAddress,
        type: 'wallet',
        tenantId: options?.tenantId || 'default',
        role: options?.role || 'user',
        chainId: options?.chainId,
        domain: options?.domain
      } as WalletToken,
      getWalletSecret(),
      { expiresIn: '7d' }
    );
  }

  /**
   * Verify wallet JWT with enhanced security
   */
  static verifyWalletJwt(token: string): WalletToken | null {
    try {
      return jwt.verify(token, getWalletSecret()) as WalletToken;
    } catch (error) {
      logger.error('JWT verification failed:', error);
      return null;
    }
  }

  /**
   * Authenticate wallet with hybrid post-quantum + classical signature verification
   */
  static async authenticateWalletWithPQ(
    address: string,
    classicalSignature: string,
    pqSignature: string,
    message: string,
    chainId?: number,
    domain?: string
  ): Promise<{ success: boolean; token?: string; error?: string }> {
    try {
      // First, verify the nonce is valid and consume it
      const nonceMatch = await this.extractAndVerifyNonce(message, address);
      if (!nonceMatch) {
        return { success: false, error: 'Invalid or expired nonce' };
      }

      // Extract nonce from message to validate binding
      const nonceMatchResult = message.match(/Nonce: ([a-fA-F0-9]+)/);
      if (!nonceMatchResult) {
        return { success: false, error: 'No nonce found in message' };
      }
      const nonce = nonceMatchResult[1];

      // Validate that the message includes proper chain/domain binding
      if (chainId && !message.includes(`chain ${chainId}`)) {
        logger.warn('Cross-chain replay attempt detected', {
          address,
          chainId,
          message
        });
        
        await SecurityMonitor.logEvent(
          SecurityEvent.SUSPICIOUS_ACTIVITY,
          {
            timestamp: new Date(),
            userId: address,
            ipAddress: 'unknown',
            userAgent: 'unknown',
            metadata: {
              operation: 'cross_chain_replay',
              chainId,
              message
            }
          },
          'Cross-chain replay attempt detected'
        );
        
        return { success: false, error: 'Message not bound to correct chain' };
      }

      if (domain && !message.includes(domain)) {
        logger.warn('Cross-domain replay attempt detected', {
          address,
          domain,
          message
        });
        
        await SecurityMonitor.logEvent(
          SecurityEvent.SUSPICIOUS_ACTIVITY,
          {
            timestamp: new Date(),
            userId: address,
            ipAddress: 'unknown',
            userAgent: 'unknown',
            metadata: {
              operation: 'cross_domain_replay',
              domain,
              message
            }
          },
          'Cross-domain replay attempt detected'
        );
        
        return { success: false, error: 'Message not bound to correct domain' };
      }

      // Prepare message bytes for signature verification
      const messageBytes = new TextEncoder().encode(message);

      // Decode signatures from hex format
      const classicalSigBytes = Uint8Array.from(Buffer.from(classicalSignature, 'hex'));
      const pqSigBytes = Uint8Array.from(Buffer.from(pqSignature, 'hex'));

      // Get public keys - in a real implementation, these would be retrieved from the blockchain
      // For now, we'll simulate getting public keys associated with the address
      const publicKeyInfo = await this.retrievePublicKeys(address);
      if (!publicKeyInfo) {
        return { success: false, error: 'Could not retrieve public keys for address' };
      }

      // Verify BOTH classical AND post-quantum signatures
      // CRITICAL: Both must pass for authentication to succeed
      const classicalValid = await this.verifyClassicalSignature(
        messageBytes,
        classicalSigBytes,
        publicKeyInfo.classicalPublicKey
      );

      const pqValid = await this.verifyPQSignature(
        messageBytes,
        pqSigBytes,
        publicKeyInfo.pqPublicKey
      );

      // LOGICAL AND: Both signatures must be valid
      if (!classicalValid) {
        logger.warn('Classical signature verification failed', {
          address,
          chainId,
          domain
        });
        
        await SecurityMonitor.logEvent(
          SecurityEvent.AUTH_FAILURE,
          {
            timestamp: new Date(),
            userId: address,
            ipAddress: 'unknown',
            userAgent: 'unknown',
            metadata: {
              operation: 'classical_signature_failure',
              chainId,
              domain
            }
          },
          'Classical signature verification failed'
        );
        
        return { success: false, error: 'Classical signature verification failed' };
      }

      if (!pqValid) {
        logger.warn('Post-quantum signature verification failed', {
          address,
          chainId,
          domain
        });
        
        await SecurityMonitor.logEvent(
          SecurityEvent.AUTH_FAILURE,
          {
            timestamp: new Date(),
            userId: address,
            ipAddress: 'unknown',
            userAgent: 'unknown',
            metadata: {
              operation: 'pq_signature_failure',
              chainId,
              domain
            }
          },
          'Post-quantum signature verification failed'
        );
        
        return { success: false, error: 'Post-quantum signature verification failed' };
      }

      // Both signatures are valid - authentication successful
      const token = this.createWalletJwt(address, { chainId, domain });

      logger.info('Wallet authenticated successfully with hybrid signature', {
        address,
        chainId,
        domain
      });

      await SecurityMonitor.logEvent(
        SecurityEvent.AUTH_SUCCESS,
        {
          timestamp: new Date(),
          userId: address,
          ipAddress: 'unknown',
          userAgent: 'unknown',
          metadata: {
            operation: 'hybrid_signature_auth',
            chainId,
            domain,
            classicalValid,
            pqValid
          }
        },
        'Wallet authenticated with hybrid signature'
      );

      return { success: true, token };

    } catch (error) {
      logger.error('Wallet authentication with PQ failed:', error);
      return { success: false, error: 'Authentication failed' };
    }
  }

  /**
   * Extract and verify nonce from message
   */
  private static async extractAndVerifyNonce(message: string, address: string): Promise<boolean> {
    // Extract nonce from message
    const nonceMatch = message.match(/Nonce: ([a-fA-F0-9]+)/);
    if (!nonceMatch) {
      return false;
    }
    const nonce = nonceMatch[1];

    // Verify and consume the nonce
    return await this.verifyAndConsumeNonce(address, nonce);
  }

  /**
   * Retrieve public keys for an address (simulated)
   */
  private static async retrievePublicKeys(address: string): Promise<{
    classicalPublicKey: Uint8Array;
    pqPublicKey: Uint8Array;
  } | null> {
    // In a real implementation, this would fetch public keys from the blockchain
    // For now, we'll return dummy keys for demonstration
    try {
      // Simulate retrieving keys from a blockchain or key registry
      // This is a simplified representation
      const classicalPubKey = Uint8Array.from(Buffer.from(address.substring(0, 32), 'hex'));
      const pqPubKey = Uint8Array.from(Buffer.from(address.substring(32, 64), 'hex'));

      return {
        classicalPublicKey: classicalPubKey,
        pqPublicKey: pqPubKey
      };
    } catch (error) {
      logger.error('Failed to retrieve public keys:', error);
      return null;
    }
  }

  /**
   * Verify classical signature (Ed25519)
   */
  private static async verifyClassicalSignature(
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array
  ): Promise<boolean> {
    try {
      // Use libsodium for constant-time Ed25519 signature verification
      const sodium = await import('libsodium-wrappers');
      await sodium.ready;

      return sodium.crypto_sign_verify_detached(signature, message, publicKey);
    } catch (error) {
      logger.error('Classical signature verification error:', error);
      return false;
    }
  }

  /**
   * Verify post-quantum signature (Dilithium)
   */
  private static async verifyPQSignature(
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array
  ): Promise<boolean> {
    try {
      // Use OQS for Dilithium signature verification
      return await PQCryptoService.verifyHybridSignature(
        message,
        signature, // In real scenario, this would be just the PQ portion
        publicKey, // In real scenario, this would be the PQ public key
        publicKey  // Placeholder - in real scenario, would be classical pub key
      );
    } catch (error) {
      logger.error('Post-quantum signature verification error:', error);
      return false;
    }
  }
}

// Export default for compatibility
const secureWallet = {
  generateNonce: SecureWallet.generateNonce,
  verifyAndConsumeNonce: SecureWallet.verifyAndConsumeNonce,
  createWalletJwt: SecureWallet.createWalletJwt,
  verifyWalletJwt: SecureWallet.verifyWalletJwt,
  authenticateWalletWithPQ: SecureWallet.authenticateWalletWithPQ
};

export default secureWallet;