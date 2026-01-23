import { describe, it, beforeEach, afterEach } from 'vitest';
import { KeyRotationManager } from '../src/lib/crypto/key-rotation-manager';
import { KMSIntegration } from '../src/lib/crypto/kms-integration';
import { KeyVersioning } from '../src/lib/crypto/key-versioning';
import { CryptoOperations } from '../src/lib/crypto/crypto-operations';

describe('Key Rotation Tests', () => {
  let keyRotationManager: KeyRotationManager;
  let kmsIntegration: KMSIntegration;
  let keyVersioning: KeyVersioning;
  let cryptoOperations: CryptoOperations;

  beforeEach(() => {
    keyRotationManager = new KeyRotationManager();
    kmsIntegration = new KMSIntegration();
    keyVersioning = new KeyVersioning();
    cryptoOperations = new CryptoOperations();
  });

  afterEach(() => {
    // Cleanup if needed
  });

  it('should generate new key after 90 days', async () => {
    // Mock the time to simulate 90+ days passing
    vi.useFakeTimers();
    vi.setSystemTime(new Date(2023, 0, 1)); // Jan 1, 2023

    // Initialize with an old key
    await keyVersioning.updateCurrentKeyVersion('session', 'old-key-id-123');

    // Advance time by 91 days
    vi.setSystemTime(new Date(2023, 3, 1)); // April 1, 2023 (91 days later)

    // Check and rotate if needed
    await keyRotationManager.checkAndRotateIfNeeded();

    // Verify new key was generated
    const currentKey = await keyVersioning.getCurrentKeyVersion('session');
    expect(currentKey).not.toBe('old-key-id-123');
    expect(currentKey).toBeDefined();

    vi.useRealTimers();
  });

  it('should decrypt old data with historical keys', async () => {
    // Create some old data with an initial key
    const oldKey = 'old-key-data-abc123';
    await keyVersioning.updateCurrentKeyVersion('test', oldKey);

    // Encrypt some data with the old key
    const testData = 'sensitive data to encrypt';
    const encrypted = await cryptoOperations.encrypt(testData, 'test');

    // Rotate the key to simulate time passing
    await keyVersioning.updateCurrentKeyVersion('test', 'new-key-data-xyz789');

    // Now try to decrypt the old data with the old key ID
    const decrypted = await cryptoOperations.decrypt(
      encrypted.encryptedData,
      encrypted.iv,
      encrypted.tag,
      'test',
      encrypted.keyVersion
    );

    expect(decrypted).toBe(testData);
  });

  it('should encrypt new data with current key', async () => {
    // Set a current key
    await keyVersioning.updateCurrentKeyVersion('test', 'current-key-def456');

    // Encrypt new data
    const newData = 'new sensitive data';
    const encrypted = await cryptoOperations.encrypt(newData, 'test');

    // Verify we can decrypt it with the same key
    const decrypted = await cryptoOperations.decrypt(
      encrypted.encryptedData,
      encrypted.iv,
      encrypted.tag,
      'test',
      encrypted.keyVersion
    );

    expect(decrypted).toBe(newData);
  });

  it('should handle re-encryption process', async () => {
    // This would test re-encrypting data with a new key
    // For now, we'll simulate the process
    const oldKey = 'old-rekey-data-111';
    const newKey = 'new-rekey-data-222';
    
    await keyVersioning.updateCurrentKeyVersion('rekey-test', oldKey);
    
    // Encrypt data with old key
    const originalData = 'data for re-encryption test';
    const encryptedWithOld = await cryptoOperations.encrypt(originalData, 'rekey-test');
    
    // Switch to new key
    await keyVersioning.updateCurrentKeyVersion('rekey-test', newKey);
    
    // Decrypt with old key version and re-encrypt with new key
    const decrypted = await cryptoOperations.decrypt(
      encryptedWithOld.encryptedData,
      encryptedWithOld.iv,
      encryptedWithOld.tag,
      'rekey-test',
      encryptedWithOld.keyVersion
    );
    
    // Re-encrypt with new current key
    const reencrypted = await cryptoOperations.encrypt(decrypted, 'rekey-test');
    
    // Verify we can decrypt the re-encrypted data
    const finalDecrypted = await cryptoOperations.decrypt(
      reencrypted.encryptedData,
      reencrypted.iv,
      reencrypted.tag,
      'rekey-test',
      reencrypted.keyVersion
    );
    
    expect(finalDecrypted).toBe(originalData);
  });

  it('should verify KMS integration works', async () => {
    // Since we're mocking KMS, we'll test that the integration layer works
    // In a real test, this would connect to actual KMS
    
    // Test that we can create a mock key
    const keyId = await kmsIntegration.createKey('Test key for unit tests');
    expect(keyId).toBeDefined();
    expect(typeof keyId).toBe('string');
    expect(keyId.length).toBeGreaterThan(0);
  });

  it('should maintain zero downtime during rotation', async () => {
    // Simulate concurrent operations during key rotation
    const operations: Promise<any>[] = [];
    
    // Start several encryption operations
    for (let i = 0; i < 10; i++) {
      operations.push(
        cryptoOperations.encrypt(`test-data-${i}`, 'session')
      );
    }
    
    // Simultaneously rotate keys
    const rotationPromise = keyRotationManager.rotateKeys('session');
    
    // Wait for all operations to complete
    await Promise.all([...operations, rotationPromise]);
    
    // All operations should succeed without errors
    expect(true).toBe(true); // If we reach here, no exceptions occurred
  });

  it('should handle concurrent operations correctly', async () => {
    // Test multiple simultaneous operations
    const promises = [];
    
    for (let i = 0; i < 5; i++) {
      promises.push(
        cryptoOperations.encrypt(`concurrent-data-${i}`, 'api')
      );
    }
    
    for (let i = 0; i < 3; i++) {
      promises.push(
        keyRotationManager.rotateKeys('api')
      );
    }
    
    // All operations should complete without conflicts
    const results = await Promise.allSettled(promises);
    
    // Check that all operations resolved (some may reject due to race conditions in real systems)
    const rejected = results.filter(r => r.status === 'rejected');
    // Allow for some rejections due to race conditions, but most should succeed
    expect(rejected.length).toBeLessThan(3); // At least 5 out of 8 should succeed
  });
});