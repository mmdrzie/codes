import { 
  KMSClient, 
  CreateKeyCommand, 
  GenerateDataKeyCommand, 
  DecryptCommand, 
  EncryptCommand,
  ScheduleKeyDeletionCommand,
  EnableKeyRotationCommand
} from '@aws-sdk/client-kms';

export class KMSIntegration {
  private client: KMSClient;

  constructor() {
    this.client = new KMSClient({ 
      region: process.env.AWS_REGION || 'us-east-1' 
    });
  }

  /**
   * Creates a new KMS key with automatic rotation enabled
   */
  async createKey(description: string, keyUsage: 'ENCRYPT_DECRYPT' | 'SIGN_VERIFY' = 'ENCRYPT_DECRYPT'): Promise<string> {
    try {
      const command = new CreateKeyCommand({
        Description: description,
        KeyUsage: keyUsage,
        Origin: 'AWS_KMS'
      });

      const response = await this.client.send(command);
      const keyId = response.KeyMetadata?.KeyId;

      if (!keyId) {
        throw new Error('Failed to create KMS key: no KeyId returned');
      }

      // Enable automatic rotation
      await this.enableKeyRotation(keyId);

      console.log(`[KMS] Created new key: ${keyId}`);
      return keyId;
    } catch (error) {
      console.error('[KMS] Error creating key:', error);
      throw error;
    }
  }

  /**
   * Enables automatic rotation for a KMS key
   */
  async enableKeyRotation(keyId: string): Promise<void> {
    try {
      const command = new EnableKeyRotationCommand({
        KeyId: keyId
      });

      await this.client.send(command);
      console.log(`[KMS] Enabled automatic rotation for key: ${keyId}`);
    } catch (error) {
      console.error(`[KMS] Error enabling rotation for key ${keyId}:`, error);
      throw error;
    }
  }

  /**
   * Generates a data key using KMS
   */
  async generateDataKey(keyId: string, keySpec: 'AES_256' | 'AES_128' = 'AES_256'): Promise<{ plaintext: Uint8Array, ciphertext: Uint8Array }> {
    try {
      const command = new GenerateDataKeyCommand({
        KeyId: keyId,
        KeySpec: keySpec
      });

      const response = await this.client.send(command);

      if (!response.Plaintext || !response.CiphertextBlob) {
        throw new Error('Failed to generate data key: no plaintext or ciphertext returned');
      }

      return {
        plaintext: response.Plaintext,
        ciphertext: response.CiphertextBlob
      };
    } catch (error) {
      console.error('[KMS] Error generating data key:', error);
      throw error;
    }
  }

  /**
   * Encrypts data using a KMS key
   */
  async encrypt(keyId: string, plaintext: Uint8Array): Promise<Uint8Array> {
    try {
      const command = new EncryptCommand({
        KeyId: keyId,
        Plaintext: plaintext
      });

      const response = await this.client.send(command);

      if (!response.CiphertextBlob) {
        throw new Error('Failed to encrypt data: no ciphertext returned');
      }

      console.log(`[KMS] Encrypted data using key: ${keyId}`);
      return response.CiphertextBlob;
    } catch (error) {
      console.error('[KMS] Error encrypting data:', error);
      throw error;
    }
  }

  /**
   * Decrypts data using a KMS key
   */
  async decrypt(ciphertext: Uint8Array): Promise<Uint8Array> {
    try {
      const command = new DecryptCommand({
        CiphertextBlob: ciphertext
      });

      const response = await this.client.send(command);

      if (!response.Plaintext) {
        throw new Error('Failed to decrypt data: no plaintext returned');
      }

      console.log(`[KMS] Decrypted data`);
      return response.Plaintext;
    } catch (error) {
      console.error('[KMS] Error decrypting data:', error);
      throw error;
    }
  }

  /**
   * Schedules a KMS key for deletion (after 7-30 days)
   */
  async scheduleKeyDeletion(keyId: string, pendingWindowInDays: number = 30): Promise<void> {
    try {
      const command = new ScheduleKeyDeletionCommand({
        KeyId: keyId,
        PendingWindowInDays: pendingWindowInDays
      });

      await this.client.send(command);
      console.log(`[KMS] Scheduled key deletion for key: ${keyId} in ${pendingWindowInDays} days`);
    } catch (error) {
      console.error(`[KMS] Error scheduling key deletion for ${keyId}:`, error);
      throw error;
    }
  }

  /**
   * Gets the current status of a KMS key
   */
  async getKeyStatus(keyId: string): Promise<string> {
    // In a real implementation, we would fetch the actual key status
    // For now, returning a placeholder
    return 'Enabled';
  }

  /**
   * Retrieves and caches keys to improve performance
   */
  async getCachedKey(keyId: string): Promise<Uint8Array> {
    // In a real implementation, this would cache keys securely
    // For now, returning a placeholder
    const crypto = await import('crypto');
    return crypto.randomBytes(32); // 256-bit key
  }
}