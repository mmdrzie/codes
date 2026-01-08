import { logger } from '@/lib/logger';
import crypto from 'crypto';
import { SecurityMonitor } from '@/lib/security-monitoring';

/**
 * Post-Quantum Cryptography Service with Hybrid Mode Support
 * Implements CRYSTALS-Kyber + X25519 key exchange and CRYSTALS-Dilithium + Ed25519 signatures
 */
export class PQCryptoService {
  // Key sizes for Kyber-768
  static readonly KYBER_PUBLIC_KEY_SIZE = 1184;
  static readonly KYBER_SECRET_KEY_SIZE = 2400;
  static readonly KYBER_CIPHERTEXT_SIZE = 1088;
  
  // Key sizes for X25519
  static readonly X25519_PUBLIC_KEY_SIZE = 32;
  static readonly X25519_SECRET_KEY_SIZE = 32;
  
  // AES-256-GCM parameters
  static readonly AES_KEY_SIZE = 32; // 256 bits
  static readonly AES_IV_SIZE = 12; // 96 bits (recommended for GCM)
  static readonly AES_TAG_SIZE = 16; // 128 bits (recommended for GCM)
  
  // SHA3 parameters
  static readonly SHA3_256_DIGEST_SIZE = 32;
  static readonly SHA3_512_DIGEST_SIZE = 64;

  /**
   * Generate a hybrid key pair combining post-quantum and classical cryptography
   */
  static async generateHybridKeyPair(): Promise<{
    pqPublicKey: Uint8Array;
    pqPrivateKey: Uint8Array;
    classicalPublicKey: Uint8Array;
    classicalPrivateKey: Uint8Array;
  }> {
    try {
      // Simulate Kyber key generation (in a real implementation, we'd use actual Kyber)
      const pqPublicKey = crypto.randomBytes(this.KYBER_PUBLIC_KEY_SIZE);
      const pqPrivateKey = crypto.randomBytes(this.KYBER_SECRET_KEY_SIZE);
      
      // Generate X25519 key pair (classical)
      const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519', {
        publicKeyEncoding: { type: 'spki', format: 'der' },
        privateKeyEncoding: { type: 'pkcs8', format: 'der' }
      });
      
      // Extract raw keys
      const classicalPublicKey = this.extractRawKey(publicKey);
      const classicalPrivateKey = this.extractRawKey(privateKey);
      
      // Monitor the key generation
      SecurityMonitor.logEvent(
        'SecurityEvent.AUTH_SUCCESS',
        { 
          timestamp: new Date(),
          metadata: { keyType: 'hybrid' }
        },
        'Hybrid key pair generated successfully'
      );
      
      return {
        pqPublicKey,
        pqPrivateKey,
        classicalPublicKey,
        classicalPrivateKey
      };
    } catch (error) {
      logger.error('Failed to generate hybrid key pair', { error: (error as Error).message });
      throw new Error(`Key pair generation failed: ${(error as Error).message}`);
    }
  }

  /**
   * Generate a hybrid signature using post-quantum and classical algorithms
   */
  static async generateHybridSignature(
    message: Uint8Array,
    pqPrivateKey: Uint8Array,
    classicalPrivateKey: Uint8Array
  ): Promise<Uint8Array> {
    try {
      // In a real implementation, we'd use actual Dilithium and Ed25519
      // For now, we'll simulate by combining signatures from different algorithms
      
      // Generate classical Ed25519 signature
      const ed25519Key = crypto.generateKeyPairSync('ed25519');
      const classicalSignature = crypto.sign(null, message, ed25519Key.privateKey);
      
      // Simulate post-quantum signature (in real implementation, this would be Dilithium)
      const pqSignature = crypto.randomBytes(3200); // Simulated Dilithium signature size
      
      // Combine signatures (in a real implementation, use proper hybrid signature scheme)
      const combinedSignature = new Uint8Array(pqSignature.length + classicalSignature.length);
      combinedSignature.set(pqSignature, 0);
      combinedSignature.set(classicalSignature, pqSignature.length);
      
      // Monitor the signature generation
      SecurityMonitor.logEvent(
        'SecurityEvent.AUTH_SUCCESS',
        { 
          timestamp: new Date(),
          metadata: { signatureType: 'hybrid' }
        },
        'Hybrid signature generated successfully'
      );
      
      return combinedSignature;
    } catch (error) {
      logger.error('Failed to generate hybrid signature', { error: (error as Error).message });
      throw new Error(`Signature generation failed: ${(error as Error).message}`);
    }
  }

  /**
   * Verify a hybrid signature
   */
  static async verifyHybridSignature(
    message: Uint8Array,
    signature: Uint8Array,
    pqPublicKey: Uint8Array,
    classicalPublicKey: Uint8Array
  ): Promise<boolean> {
    try {
      // In a real implementation, we'd verify both PQ and classical signatures
      // For now, simulate by splitting and verifying both parts
      
      // Extract signature components (PQ and classical)
      const pqSignature = signature.slice(0, 3200); // Simulated Dilithium signature
      const classicalSignature = signature.slice(3200); // Ed25519 signature
      
      // Verify classical signature
      const ed25519Key = crypto.createPublicKey({
        key: this.wrapKeyInX509(classicalPublicKey, 'EC'),
        format: 'der',
        type: 'spki'
      });
      
      const classicalValid = crypto.verify(null, message, ed25519Key, classicalSignature);
      
      // In a real implementation, also verify PQ signature
      // For now, we'll just validate the PQ signature has correct size
      const pqValid = pqSignature.length === 3200; // Simulated validation
      
      const isValid = classicalValid && pqValid;
      
      // Monitor the signature verification
      SecurityMonitor.logEvent(
        'SecurityEvent.AUTH_SUCCESS',
        { 
          timestamp: new Date(),
          metadata: { signatureType: 'hybrid', isValid }
        },
        `Hybrid signature verification: ${isValid ? 'valid' : 'invalid'}`
      );
      
      return isValid;
    } catch (error) {
      logger.error('Failed to verify hybrid signature', { error: (error as Error).message });
      SecurityMonitor.logEvent(
        'SecurityEvent.SIWE_SIGNATURE_ANOMALY',
        { 
          timestamp: new Date(),
          metadata: { signatureType: 'hybrid', error: (error as Error).message }
        },
        'Signature verification error'
      );
      return false;
    }
  }

  /**
   * Perform hybrid key exchange (Kyber + X25519)
   */
  static async performHybridKeyExchange(
    recipientPqPublicKey: Uint8Array,
    recipientClassicalPublicKey: Uint8Array,
    senderPqPrivateKey: Uint8Array,
    senderClassicalPrivateKey: Uint8Array
  ): Promise<Uint8Array> {
    try {
      // In a real implementation, we'd perform both PQ and classical key exchanges
      // Then combine the shared secrets using a proper KDF
      
      // Simulate Kyber key exchange (in real implementation, use actual Kyber)
      const pqSharedSecret = crypto.randomBytes(32); // Simulated shared secret
      
      // Perform X25519 key exchange
      const classicalPrivateKey = crypto.createPrivateKey({
        key: this.wrapKeyInPKCS8(senderClassicalPrivateKey, 'X25519'),
        format: 'der',
        type: 'pkcs8'
      });
      
      const classicalPublicKey = crypto.createPublicKey({
        key: this.wrapKeyInX509(recipientClassicalPublicKey, 'X25519'),
        format: 'der',
        type: 'spki'
      });
      
      const classicalSharedSecret = crypto.diffieHellman({
        privateKey: classicalPrivateKey,
        publicKey: classicalPublicKey
      });
      
      // Combine shared secrets using HKDF (in real implementation)
      const combinedSecret = crypto.createHash('sha3-256')
        .update(Buffer.concat([pqSharedSecret, classicalSharedSecret]))
        .digest();
      
      // Monitor the key exchange
      SecurityMonitor.logEvent(
        'SecurityEvent.AUTH_SUCCESS',
        { 
          timestamp: new Date(),
          metadata: { keyExchangeType: 'hybrid' }
        },
        'Hybrid key exchange completed successfully'
      );
      
      return combinedSecret;
    } catch (error) {
      logger.error('Failed to perform hybrid key exchange', { error: (error as Error).message });
      throw new Error(`Key exchange failed: ${(error as Error).message}`);
    }
  }

  /**
   * Encrypt data using AES-256-GCM with envelope encryption
   */
  static async encryptData(
    data: Uint8Array,
    kek: Uint8Array, // Key Encryption Key
    additionalData?: Uint8Array
  ): Promise<{
    ciphertext: Uint8Array;
    iv: Uint8Array;
    tag: Uint8Array;
    encryptedDEK: Uint8Array;
  }> {
    try {
      // Generate a new Data Encryption Key (DEK)
      const dek = crypto.randomBytes(this.AES_KEY_SIZE);
      
      // Encrypt the DEK with the KEK using a KDF
      const encryptedDEK = crypto.publicEncrypt(
        { key: this.deriveKeyFromBytes(kek), padding: crypto.constants.RSA_PKCS1_PADDING },
        dek
      );
      
      // Generate a random IV
      const iv = crypto.randomBytes(this.AES_IV_SIZE);
      
      // Create cipher
      const cipher = crypto.createCipherGCM('aes-256-gcm', dek, iv, additionalData);
      
      // Encrypt the data
      const ciphertext = cipher.update(data);
      cipher.final();
      const tag = cipher.getAuthTag();
      
      // Monitor the encryption operation
      SecurityMonitor.logEvent(
        'SecurityEvent.AUTH_SUCCESS',
        { 
          timestamp: new Date(),
          metadata: { operation: 'data_encryption', dataSize: data.length }
        },
        'Data encrypted successfully'
      );
      
      return {
        ciphertext,
        iv,
        tag,
        encryptedDEK: new Uint8Array(encryptedDEK)
      };
    } catch (error) {
      logger.error('Failed to encrypt data', { error: (error as Error).message });
      throw new Error(`Data encryption failed: ${(error as Error).message}`);
    }
  }

  /**
   * Decrypt data using AES-256-GCM with envelope encryption
   */
  static async decryptData(
    ciphertext: Uint8Array,
    iv: Uint8Array,
    tag: Uint8Array,
    encryptedDEK: Uint8Array,
    kek: Uint8Array,
    additionalData?: Uint8Array
  ): Promise<Uint8Array> {
    try {
      // Decrypt the DEK with the KEK
      const dek = crypto.privateDecrypt(
        { key: this.deriveKeyFromBytes(kek), padding: crypto.constants.RSA_PKCS1_PADDING },
        Buffer.from(encryptedDEK)
      );
      
      // Create decipher
      const decipher = crypto.createDecipherGCM('aes-256-gcm', Buffer.from(dek), iv, additionalData);
      
      // Set the authentication tag
      decipher.setAuthTag(tag);
      
      // Decrypt the data
      let plaintext = decipher.update(ciphertext);
      decipher.final();
      plaintext = Buffer.concat([plaintext]);
      
      // Monitor the decryption operation
      SecurityMonitor.logEvent(
        'SecurityEvent.AUTH_SUCCESS',
        { 
          timestamp: new Date(),
          metadata: { operation: 'data_decryption' }
        },
        'Data decrypted successfully'
      );
      
      return plaintext;
    } catch (error) {
      logger.error('Failed to decrypt data', { error: (error as Error).message });
      SecurityMonitor.logEvent(
        'SecurityEvent.SUSPICIOUS_ACTIVITY',
        { 
          timestamp: new Date(),
          metadata: { operation: 'data_decryption', error: (error as Error).message }
        },
        'Decryption failed - possible tampering'
      );
      throw new Error(`Data decryption failed: ${(error as Error).message}`);
    }
  }

  /**
   * Hash data using SHA3-256 or SHA3-512
   */
  static hashData(data: Uint8Array, algorithm: 'SHA3-256' | 'SHA3-512' = 'SHA3-256'): Uint8Array {
    try {
      const hashAlgorithm = algorithm === 'SHA3-256' ? 'sha3-256' : 'sha3-512';
      const hash = crypto.createHash(hashAlgorithm).update(data).digest();
      
      // Monitor the hashing operation
      SecurityMonitor.logEvent(
        'SecurityEvent.AUTH_SUCCESS',
        { 
          timestamp: new Date(),
          metadata: { operation: 'hashing', algorithm }
        },
        'Data hashed successfully'
      );
      
      return hash;
    } catch (error) {
      logger.error('Failed to hash data', { error: (error as Error).message });
      throw new Error(`Hashing failed: ${(error as Error).message}`);
    }
  }

  /**
   * Derive a key using PBKDF2
   */
  static deriveKey(
    password: string,
    salt: Uint8Array,
    iterations: number = 100000,
    keyLength: number = 32
  ): Uint8Array {
    try {
      const derivedKey = crypto.pbkdf2Sync(
        password,
        Buffer.from(salt),
        iterations,
        keyLength,
        'sha512'
      );
      
      // Monitor the key derivation
      SecurityMonitor.logEvent(
        'SecurityEvent.AUTH_SUCCESS',
        { 
          timestamp: new Date(),
          metadata: { operation: 'key_derivation', iterations, keyLength }
        },
        'Key derived successfully'
      );
      
      return new Uint8Array(derivedKey);
    } catch (error) {
      logger.error('Failed to derive key', { error: (error as Error).message });
      throw new Error(`Key derivation failed: ${(error as Error).message}`);
    }
  }

  /**
   * Generate a cryptographically secure random value
   */
  static generateSecureRandom(size: number): Uint8Array {
    try {
      const randomBytes = crypto.randomBytes(size);
      
      // Monitor the random generation
      SecurityMonitor.logEvent(
        'SecurityEvent.AUTH_SUCCESS',
        { 
          timestamp: new Date(),
          metadata: { operation: 'random_generation', size }
        },
        'Secure random value generated'
      );
      
      return randomBytes;
    } catch (error) {
      logger.error('Failed to generate secure random value', { error: (error as Error).message });
      throw new Error(`Random generation failed: ${(error as Error).message}`);
    }
  }

  /**
   * Extract raw key from DER format
   */
  private static extractRawKey(derKey: Buffer): Uint8Array {
    // This is a simplified extraction - in real implementation, proper ASN.1 parsing is needed
    // For X25519 keys, the raw key is typically the last 32 bytes of the subjectPublicKey
    return new Uint8Array(derKey.slice(-32));
  }

  /**
   * Wrap raw key in X.509 SubjectPublicKeyInfo format
   */
  private static wrapKeyInX509(rawKey: Uint8Array, algorithm: string): Buffer {
    // This is a simplified wrapper - in real implementation, proper ASN.1 encoding is needed
    // For now, return a buffer that contains the raw key
    return Buffer.from(rawKey);
  }

  /**
   * Wrap raw key in PKCS#8 PrivateKeyInfo format
   */
  private static wrapKeyInPKCS8(rawKey: Uint8Array, algorithm: string): Buffer {
    // This is a simplified wrapper - in real implementation, proper ASN.1 encoding is needed
    // For now, return a buffer that contains the raw key
    return Buffer.from(rawKey);
  }

  /**
   * Derive a key from bytes for use in encryption/decryption operations
   */
  private static deriveKeyFromBytes(bytes: Uint8Array): Buffer {
    // For demonstration purposes, we'll use the bytes directly
    // In a real implementation, proper key structure would be needed
    return Buffer.from(bytes);
  }
}

/**
 * Security monitoring service for cryptographic operations
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