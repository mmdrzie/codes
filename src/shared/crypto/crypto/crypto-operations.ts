import { createCipheriv, createDecipheriv, createHmac, randomBytes, pbkdf2Sync, timingSafeEqual } from 'crypto';
import { KeyRotationManager } from './key-rotation-manager';
import { KeyVersioning } from './key-versioning';

export class CryptoOperations {
  private keyRotationManager: KeyRotationManager;
  private keyVersioning: KeyVersioning;

  constructor() {
    this.keyRotationManager = new KeyRotationManager();
    this.keyVersioning = new KeyVersioning();
  }

  /**
   * Encrypts data using AES-256-GCM with key rotation support
   */
  async encrypt(data: string, keyType: string = 'general'): Promise<{ encryptedData: string, iv: string, tag?: string, keyVersion: number }> {
    try {
      // Get current key for the specified type
      const keyHex = await this.keyRotationManager.getCurrentKey(keyType);
      if (!keyHex) {
        throw new Error(`No current key found for type: ${keyType}`);
      }

      // Convert hex key to buffer
      const key = Buffer.from(keyHex, 'hex');

      // Generate random IV
      const iv = randomBytes(16);

      // Determine algorithm based on key type
      let cipher, encrypted;
      if (keyType === 'jwt') {
        // For JWT signing, we don't use encryption but HMAC
        throw new Error('Use sign method for JWT tokens');
      } else {
        // Use AES-GCM for general encryption (provides authentication)
        cipher = createCipheriv('aes-256-gcm', key, iv);
        encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        const tag = cipher.getAuthTag();
        
        return {
          encryptedData: encrypted,
          iv: iv.toString('hex'),
          tag: tag.toString('hex'),
          keyVersion: await this.getCurrentKeyVersion(keyType)
        };
      }
    } catch (error) {
      console.error(`[CRYPTO] Error encrypting data:`, error);
      throw error;
    }
  }

  /**
   * Decrypts data using AES-256-GCM with key rotation support
   */
  async decrypt(encryptedData: string, iv: string, tag?: string, keyType: string = 'general', keyVersion?: number): Promise<string> {
    try {
      let keyHex: string | null = null;
      
      if (keyVersion !== undefined) {
        // Find key for specific version
        keyHex = await this.keyVersioning.findDecryptionKeyByVersion(keyType, keyVersion);
      } else {
        // Use current key
        keyHex = await this.keyRotationManager.getCurrentKey(keyType);
      }

      if (!keyHex) {
        throw new Error(`No key found for type: ${keyType}${keyVersion ? `, version: ${keyVersion}` : ''}`);
      }

      const key = Buffer.from(keyHex, 'hex');
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));

      if (tag) {
        decipher.setAuthTag(Buffer.from(tag, 'hex'));
      }

      let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      return decrypted;
    } catch (error) {
      console.error(`[CRYPTO] Error decrypting data:`, error);
      throw error;
    }
  }

  /**
   * Signs data using HMAC-SHA256
   */
  async sign(data: string, keyType: string = 'jwt'): Promise<{ signature: string, keyVersion: number }> {
    try {
      const keyHex = await this.keyRotationManager.getCurrentKey(keyType);
      if (!keyHex) {
        throw new Error(`No current key found for type: ${keyType}`);
      }

      const key = Buffer.from(keyHex, 'hex');
      const hmac = createHmac('sha256', key);
      const signature = hmac.update(data).digest('hex');

      return {
        signature,
        keyVersion: await this.getCurrentKeyVersion(keyType)
      };
    } catch (error) {
      console.error(`[CRYPTO] Error signing data:`, error);
      throw error;
    }
  }

  /**
   * Verifies HMAC signature
   */
  async verifySignature(data: string, signature: string, keyType: string = 'jwt', keyVersion?: number): Promise<boolean> {
    try {
      let keyHex: string | null = null;
      
      if (keyVersion !== undefined) {
        // Find key for specific version
        keyHex = await this.keyVersioning.findDecryptionKeyByVersion(keyType, keyVersion);
      } else {
        // Use current key
        keyHex = await this.keyRotationManager.getCurrentKey(keyType);
      }

      if (!keyHex) {
        throw new Error(`No key found for type: ${keyType}${keyVersion ? `, version: ${keyVersion}` : ''}`);
      }

      const key = Buffer.from(keyHex, 'hex');
      const hmac = createHmac('sha256', key);
      const expectedSignature = hmac.update(data).digest('hex');

      // Use timing-safe comparison to prevent timing attacks
      const actualSigBuffer = Buffer.from(signature, 'hex');
      const expectedSigBuffer = Buffer.from(expectedSignature, 'hex');

      if (actualSigBuffer.length !== expectedSigBuffer.length) {
        return false;
      }

      return timingSafeEqual(actualSigBuffer, expectedSigBuffer);
    } catch (error) {
      console.error(`[CRYPTO] Error verifying signature:`, error);
      return false;
    }
  }

  /**
   * Hashes password using PBKDF2
   */
  async hashPassword(password: string, salt?: string): Promise<{ hash: string, salt: string }> {
    try {
      if (!salt) {
        salt = randomBytes(32).toString('hex');
      }

      const iterations = parseInt(process.env.PBKDF2_ITERATIONS || '100000');
      const keylen = parseInt(process.env.HASH_KEYLEN || '64');
      const digest = process.env.HASH_DIGEST || 'sha512';

      const hash = pbkdf2Sync(password, salt, iterations, keylen, digest).toString('hex');

      return { hash, salt };
    } catch (error) {
      console.error('[CRYPTO] Error hashing password:', error);
      throw error;
    }
  }

  /**
   * Verifies password against hash
   */
  async verifyPassword(password: string, hash: string, salt: string): Promise<boolean> {
    try {
      const iterations = parseInt(process.env.PBKDF2_ITERATIONS || '100000');
      const keylen = parseInt(process.env.HASH_KEYLEN || '64');
      const digest = process.env.HASH_DIGEST || 'sha512';

      const computedHash = pbkdf2Sync(password, salt, iterations, keylen, digest).toString('hex');

      // Use timing-safe comparison to prevent timing attacks
      const hashBuffer = Buffer.from(hash, 'hex');
      const computedHashBuffer = Buffer.from(computedHash, 'hex');

      if (hashBuffer.length !== computedHashBuffer.length) {
        return false;
      }

      return timingSafeEqual(hashBuffer, computedHashBuffer);
    } catch (error) {
      console.error('[CRYPTO] Error verifying password:', error);
      return false;
    }
  }

  /**
   * Gets the current key version for a specific type
   */
  private async getCurrentKeyVersion(keyType: string): Promise<number> {
    // In a real implementation, this would track key versions properly
    // For now, returning a placeholder
    return 1;
  }
}