import { KMSClient } from '@aws-sdk/client-kms';
import { CryptoOperations } from './crypto-operations';
import { KeyVersioning } from './key-versioning';

interface KeyConfig {
  type: string;
  rotationInterval: number; // in days
  algorithm: string;
}

export class KeyRotationManager {
  private kmsClient: KMSClient;
  private cryptoOps: CryptoOperations;
  private keyVersioning: KeyVersioning;
  private keyConfigs: Map<string, KeyConfig>;

  constructor() {
    this.kmsClient = new KMSClient({ region: process.env.AWS_REGION || 'us-east-1' });
    this.cryptoOps = new CryptoOperations();
    this.keyVersioning = new KeyVersioning();
    this.keyConfigs = new Map();

    // Initialize default configurations
    this.initializeDefaultKeyConfigs();
  }

  private initializeDefaultKeyConfigs(): void {
    const defaultConfigs: KeyConfig[] = [
      {
        type: 'session',
        rotationInterval: parseInt(process.env.SESSION_KEY_ROTATION_DAYS || '90'),
        algorithm: 'AES_256'
      },
      {
        type: 'jwt',
        rotationInterval: parseInt(process.env.JWT_KEY_ROTATION_DAYS || '90'),
        algorithm: 'RSA_2048'
      },
      {
        type: 'api',
        rotationInterval: parseInt(process.env.API_KEY_ROTATION_DAYS || '90'),
        algorithm: 'AES_256'
      },
      {
        type: 'database',
        rotationInterval: parseInt(process.env.DB_KEY_ROTATION_DAYS || '90'),
        algorithm: 'AES_256'
      }
    ];

    for (const config of defaultConfigs) {
      this.keyConfigs.set(config.type, config);
    }
  }

  /**
   * Rotates keys for a specific type
   */
  async rotateKeys(keyType: string): Promise<boolean> {
    try {
      const config = this.keyConfigs.get(keyType);
      if (!config) {
        throw new Error(`Unknown key type: ${keyType}`);
      }

      // Create new key in KMS
      const newKeyId = await this.createKeyInKMS(config);

      // Update key version
      await this.keyVersioning.updateCurrentKeyVersion(keyType, newKeyId);

      console.log(`[KEY_ROTATION] Successfully rotated ${keyType} key. New key ID: ${newKeyId}`);

      return true;
    } catch (error) {
      console.error(`[KEY_ROTATION] Failed to rotate ${keyType} key:`, error);
      return false;
    }
  }

  /**
   * Creates a new key in KMS
   */
  private async createKeyInKMS(config: KeyConfig): Promise<string> {
    // In a real implementation, we would call KMS to create a new key
    // For now, we'll simulate this with a UUID
    const crypto = await import('crypto');
    return crypto.randomUUID();
  }

  /**
   * Checks if rotation is needed for any key type
   */
  async checkAndRotateIfNeeded(): Promise<void> {
    for (const [keyType, config] of this.keyConfigs.entries()) {
      const lastRotation = await this.keyVersioning.getLastRotationDate(keyType);
      
      if (!lastRotation) {
        // First time setup
        await this.rotateKeys(keyType);
        continue;
      }

      const daysSinceLastRotation = Math.floor(
        (Date.now() - lastRotation.getTime()) / (1000 * 60 * 60 * 24)
      );

      if (daysSinceLastRotation >= config.rotationInterval) {
        await this.rotateKeys(keyType);
      }
    }
  }

  /**
   * Performs a manual key rotation
   */
  async manualRotate(keyType: string): Promise<boolean> {
    console.log(`[KEY_ROTATION] Manual rotation initiated for ${keyType}`);
    return await this.rotateKeys(keyType);
  }

  /**
   * Handles key compromise by immediately rotating affected keys
   */
  async handleKeyCompromise(keyType: string): Promise<boolean> {
    console.warn(`[KEY_ROTATION] Key compromise detected for ${keyType}, initiating emergency rotation`);
    
    // Log the compromise event
    console.log(`[SECURITY_EVENT] Key compromise reported for type: ${keyType}, timestamp: ${new Date().toISOString()}`);
    
    // Rotate the key immediately
    const success = await this.rotateKeys(keyType);
    
    if (success) {
      console.log(`[KEY_ROTATION] Emergency rotation completed for ${keyType}`);
    } else {
      console.error(`[KEY_ROTATION] Emergency rotation failed for ${keyType}`);
    }
    
    return success;
  }

  /**
   * Gets the current key for a specific type
   */
  getCurrentKey(keyType: string): Promise<string | null> {
    return this.keyVersioning.getCurrentKeyVersion(keyType);
  }

  /**
   * Gets all historical keys for a specific type
   */
  getHistoricalKeys(keyType: string): Promise<string[]> {
    return this.keyVersioning.getHistoricalKeyVersions(keyType);
  }
}