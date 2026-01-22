/**
 * Key Management Service for QuantumIQ Project
 * Provides secure key generation, storage, rotation, and access control
 */

import { logger } from './logger';
import { siemService } from './siem-integration';
import { SecurityEventType } from './siem-integration';
import { keyManager } from './advanced-security-config';

export interface KeyMetadata {
  id: string;
  algorithm: string;
  purpose: string;
  owner: string;
  createdAt: Date;
  expiresAt: Date;
  isRevoked: boolean;
  rotationCount: number;
  lastRotated: Date;
  accessControlList: string[]; // List of allowed service IDs
}

export interface KeyUsageMetrics {
  encryptionCount: number;
  decryptionCount: number;
  signingCount: number;
  verificationCount: number;
  lastUsed: Date;
  totalUsage: number;
}

export class KeyManagementService {
  private static instance: KeyManagementService;
  private keys: Map<string, KeyMetadata> = new Map();
  private usageMetrics: Map<string, KeyUsageMetrics> = new Map();

  private constructor() {}

  public static getInstance(): KeyManagementService {
    if (!KeyManagementService.instance) {
      KeyManagementService.instance = new KeyManagementService();
    }
    return KeyManagementService.instance;
  }

  /**
   * Generates a new cryptographic key with specified parameters
   */
  async generateKey(
    algorithm: string,
    purpose: string,
    owner: string,
    accessControlList: string[] = []
  ): Promise<{ keyId: string; publicKey?: string; privateKey?: string }> {
    try {
      // Generate the key based on the algorithm
      let keyData: { publicKey: string; privateKey: string } | { key: string };
      
      switch (algorithm) {
        case 'rsa-4096':
          keyData = await keyManager.generateRSAKeyPair();
          break;
        case 'ed25519':
          keyData = await keyManager.generateEd25519KeyPair();
          break;
        case 'aes-256-gcm':
          const aesKeyBuffer = await keyManager.generateSecureKey('aes-256-gcm');
          keyData = { key: aesKeyBuffer.toString('base64') } as any;
          break;
        case 'slh-dsa-shake-128s': // Post-Quantum algorithm
          // For post-quantum algorithms, we'd use the proper library
          // This is a placeholder for now
          keyData = await keyManager.generateEd25519KeyPair();
          break;
        default:
          throw new Error(`Unsupported algorithm: ${algorithm}`);
      }

      // Create key metadata
      const keyId = `key_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const now = new Date();
      const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000); // 30 days
      
      const keyMetadata: KeyMetadata = {
        id: keyId,
        algorithm,
        purpose,
        owner,
        createdAt: now,
        expiresAt,
        isRevoked: false,
        rotationCount: 0,
        lastRotated: now,
        accessControlList
      };

      // Store the key in the key manager
      await keyManager.storeKey(keyId, {
        publicKey: (keyData as any).publicKey || (keyData as any).key,
        privateKey: (keyData as any).privateKey || (keyData as any).key,
        algorithm,
        createdAt: now,
        expiresAt,
        owner,
        purpose
      });

      // Store metadata locally
      this.keys.set(keyId, keyMetadata);
      
      // Initialize usage metrics
      this.usageMetrics.set(keyId, {
        encryptionCount: 0,
        decryptionCount: 0,
        signingCount: 0,
        verificationCount: 0,
        lastUsed: now,
        totalUsage: 0
      });

      logger.info('Key generated successfully', { 
        keyId, 
        algorithm, 
        purpose, 
        owner 
      });

      // Log security event
      await siemService.emitSecurityEvent({
        event_type: SecurityEventType.SESSION_REVOKED, // This is a placeholder - would need a new event type
        severity: 'medium',
        ip_address: 'system',
        user_agent: 'KeyManagementService',
        route: '/keys/generate',
        outcome: 'success',
        source: 'application',
        details: { keyId, algorithm, purpose, owner }
      });

      return {
        keyId,
        publicKey: (keyData as any).publicKey,
        privateKey: (keyData as any).privateKey
      };
    } catch (error) {
      logger.error('Key generation failed', { 
        error: (error as Error).message, 
        algorithm, 
        purpose, 
        owner 
      });
      
      throw error;
    }
  }

  /**
   * Retrieves a key for use, with access control validation
   */
  async getKey(
    keyId: string,
    requesterId: string,
    purpose: 'encryption' | 'decryption' | 'signing' | 'verification' | 'other'
  ): Promise<{ publicKey?: string; privateKey?: string; algorithm: string } | null> {
    try {
      // Validate access control
      const keyMetadata = this.keys.get(keyId);
      if (!keyMetadata) {
        logger.warn('Key not found', { keyId, requesterId });
        return null;
      }

      // Check if key is revoked
      if (keyMetadata.isRevoked) {
        logger.warn('Attempt to access revoked key', { keyId, requesterId });
        return null;
      }

      // Check access control
      if (keyMetadata.accessControlList.length > 0 && 
          !keyMetadata.accessControlList.includes(requesterId)) {
        logger.warn('Unauthorized key access attempt', { keyId, requesterId });
        
        // Log security event
        await siemService.emitSecurityEvent({
          event_type: SecurityEventType.UNAUTHORIZED_ACCESS,
          severity: 'high',
          ip_address: 'system',
          user_agent: 'KeyManagementService',
          user_id: requesterId,
          route: `/keys/${keyId}`,
          outcome: 'blocked',
          source: 'application',
          details: { keyId, requesterId, purpose }
        });
        
        return null;
      }

      // Update usage metrics
      const metrics = this.usageMetrics.get(keyId) || {
        encryptionCount: 0,
        decryptionCount: 0,
        signingCount: 0,
        verificationCount: 0,
        lastUsed: new Date(),
        totalUsage: 0
      };

      switch (purpose) {
        case 'encryption':
          metrics.encryptionCount++;
          break;
        case 'decryption':
          metrics.decryptionCount++;
          break;
        case 'signing':
          metrics.signingCount++;
          break;
        case 'verification':
          metrics.verificationCount++;
          break;
      }
      metrics.totalUsage++;
      metrics.lastUsed = new Date();

      this.usageMetrics.set(keyId, metrics);

      // Retrieve key from key manager
      const key = await keyManager.getKey(keyId);
      if (!key) {
        return null;
      }

      logger.info('Key retrieved successfully', { 
        keyId, 
        requesterId, 
        purpose 
      });

      return {
        publicKey: key.publicKey,
        privateKey: key.privateKey,
        algorithm: key.algorithm
      };
    } catch (error) {
      logger.error('Key retrieval failed', { 
        error: (error as Error).message, 
        keyId, 
        requesterId 
      });
      
      throw error;
    }
  }

  /**
   * Rotates a key, generating a new key while maintaining the same ID
   */
  async rotateKey(keyId: string, requesterId: string): Promise<string> {
    try {
      // Validate access control
      const keyMetadata = this.keys.get(keyId);
      if (!keyMetadata) {
        logger.warn('Key not found for rotation', { keyId, requesterId });
        throw new Error('Key not found');
      }

      // Check access control
      if (keyMetadata.accessControlList.length > 0 && 
          !keyMetadata.accessControlList.includes(requesterId)) {
        logger.warn('Unauthorized key rotation attempt', { keyId, requesterId });
        throw new Error('Unauthorized key rotation');
      }

      // Perform rotation
      const newKeyId = await keyManager.rotateKey(keyId);

      // Update metadata
      if (keyMetadata) {
        keyMetadata.rotationCount++;
        keyMetadata.lastRotated = new Date();
        keyMetadata.id = newKeyId;
        this.keys.set(newKeyId, keyMetadata);
        this.keys.delete(keyId); // Remove old key reference
      }

      logger.info('Key rotated successfully', { 
        oldKeyId: keyId, 
        newKeyId, 
        requesterId 
      });

      return newKeyId;
    } catch (error) {
      logger.error('Key rotation failed', { 
        error: (error as Error).message, 
        keyId, 
        requesterId 
      });
      
      throw error;
    }
  }

  /**
   * Revokes a key, making it unusable
   */
  async revokeKey(keyId: string, requesterId: string, reason: string = 'Manual revocation'): Promise<void> {
    try {
      // Validate access control
      const keyMetadata = this.keys.get(keyId);
      if (!keyMetadata) {
        logger.warn('Key not found for revocation', { keyId, requesterId });
        throw new Error('Key not found');
      }

      // Check access control - allow owner or specific admin roles
      if (keyMetadata.owner !== requesterId && 
          !keyMetadata.accessControlList.includes(requesterId)) {
        logger.warn('Unauthorized key revocation attempt', { keyId, requesterId });
        throw new Error('Unauthorized key revocation');
      }

      // Revoke key
      await keyManager.revokeKey(keyId);

      // Update metadata
      keyMetadata.isRevoked = true;
      this.keys.set(keyId, keyMetadata);

      logger.info('Key revoked successfully', { 
        keyId, 
        requesterId, 
        reason 
      });

      // Log security event
      await siemService.emitSecurityEvent({
        event_type: SecurityEventType.SESSION_REVOKED, // Placeholder - needs specific key event type
        severity: 'high',
        ip_address: 'system',
        user_agent: 'KeyManagementService',
        user_id: requesterId,
        route: `/keys/${keyId}/revoke`,
        outcome: 'success',
        source: 'application',
        details: { keyId, requesterId, reason }
      });
    } catch (error) {
      logger.error('Key revocation failed', { 
        error: (error as Error).message, 
        keyId, 
        requesterId 
      });
      
      throw error;
    }
  }

  /**
   * Checks if a key has expired
   */
  isKeyExpired(keyId: string): boolean {
    const keyMetadata = this.keys.get(keyId);
    if (!keyMetadata) {
      return true; // Treat missing keys as expired
    }
    
    return new Date() > keyMetadata.expiresAt;
  }

  /**
   * Checks if a key is revoked
   */
  isKeyRevoked(keyId: string): boolean {
    const keyMetadata = this.keys.get(keyId);
    if (!keyMetadata) {
      return true; // Treat missing keys as revoked
    }
    
    return keyMetadata.isRevoked;
  }

  /**
   * Gets key metadata
   */
  getKeyMetadata(keyId: string): KeyMetadata | undefined {
    return this.keys.get(keyId);
  }

  /**
   * Gets key usage metrics
   */
  getKeyUsageMetrics(keyId: string): KeyUsageMetrics | undefined {
    return this.usageMetrics.get(keyId);
  }

  /**
   * Performs automated key rotation based on schedule
   */
  async performScheduledRotation(): Promise<void> {
    const now = new Date();
    
    for (const [keyId, metadata] of this.keys.entries()) {
      // Skip revoked keys
      if (metadata.isRevoked) {
        continue;
      }

      // Check if key needs rotation (based on age or usage)
      const ageInDays = (now.getTime() - metadata.lastRotated.getTime()) / (1000 * 60 * 60 * 24);
      const metrics = this.usageMetrics.get(keyId);
      
      if (ageInDays > 30 || // Rotate if older than 30 days
          (metrics && metrics.totalUsage > 10000)) { // Or if heavily used
        try {
          await this.rotateKey(keyId, 'system_scheduler');
          logger.info('Automated key rotation completed', { keyId });
        } catch (error) {
          logger.error('Automated key rotation failed', { 
            keyId, 
            error: (error as Error).message 
          });
        }
      }
    }
  }

  /**
   * Performs security audit of all keys
   */
  async auditKeys(): Promise<{
    totalKeys: number;
    activeKeys: number;
    expiredKeys: number;
    revokedKeys: number;
    keysNeedingRotation: number;
  }> {
    const now = new Date();
    let activeKeys = 0;
    let expiredKeys = 0;
    let revokedKeys = 0;
    let keysNeedingRotation = 0;

    for (const [keyId, metadata] of this.keys.entries()) {
      if (metadata.isRevoked) {
        revokedKeys++;
      } else if (this.isKeyExpired(keyId)) {
        expiredKeys++;
      } else {
        activeKeys++;
        
        // Check if key needs rotation
        const ageInDays = (now.getTime() - metadata.lastRotated.getTime()) / (1000 * 60 * 60 * 24);
        if (ageInDays > 25) { // Alert if approaching rotation date
          keysNeedingRotation++;
        }
      }
    }

    const result = {
      totalKeys: this.keys.size,
      activeKeys,
      expiredKeys,
      revokedKeys,
      keysNeedingRotation
    };

    logger.info('Key audit completed', result);

    return result;
  }
}

// Export singleton instance
export const keyManagementService = KeyManagementService.getInstance();