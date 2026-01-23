import { createHash, createSign, createVerify, randomBytes } from 'crypto';
import { logger } from '../logger';
import { getLedger } from '../ledger/immutable-ledger';

interface DPoPTokenPayload {
  jti: string;           // JWT ID
  htm: string;           // HTTP method
  htu: string;           // HTTP URL
  iat: number;           // Issued at
  exp: number;           // Expiration time
  nonce: string;         // Nonce for replay protection
  ath: string;           // Access token hash (for linking to access token)
}

interface AccessTokenPayload {
  sub: string;           // Subject (user ID)
  jti: string;           // JWT ID
  iat: number;           // Issued at
  exp: number;           // Expiration time
  scope: string;         // Permissions scope
  cnf: {                 // Confirmation claim for DPoP
    jkt: string;         // JWK thumbprint of public key
  };
}

export class DPoPSessionManager {
  private readonly privateKey: Buffer;
  private readonly publicKey: Buffer;
  private readonly algorithm = 'ES256';
  private readonly issuer = 'financial-core-session-manager';
  private readonly audience = 'financial-app';
  private readonly validTime = 3600; // 1 hour
  private readonly nonceStore = new Map<string, number>(); // Store with timestamps for cleanup
  private readonly keyRotationInterval = 24 * 60 * 60 * 1000; // 24 hours
  private lastKeyRotation: number;
  private rotatedPrivateKey: Buffer | null = null;
  private rotatedPublicKey: Buffer | null = null;
  
  constructor() {
    // In production, these keys should come from HSM or secure key vault
    // For now, we'll generate ephemeral keys (not suitable for production)
    try {
      const { privateKey, publicKey } = this.generateKeyPair();
      this.privateKey = privateKey;
      this.publicKey = publicKey;
      this.lastKeyRotation = Date.now();
      
      logger.info('DPoP Session Manager initialized', {
        component: 'session-security',
        algorithm: this.algorithm
      });
    } catch (error) {
      logger.error('Failed to initialize DPoP Session Manager', {
        component: 'session-security',
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  /**
   * Generate a secure access token with DPoP confirmation
   */
  async generateAccessToken(userId: string, scopes: string[]): Promise<{
    accessToken: string;
    dpopJwkThumbprint: string;
  }> {
    const jti = this.generateId();
    const now = Math.floor(Date.now() / 1000);
    const publicKeyJWK = await this.publicKeyToJWK(this.publicKey);
    const jwkThumbprint = await this.calculateJwkThumbprint(publicKeyJWK);

    const payload: AccessTokenPayload = {
      sub: userId,
      jti,
      iat: now,
      exp: now + this.validTime,
      scope: scopes.join(' '),
      cnf: {
        jkt: jwkThumbprint
      }
    };

    const header = {
      typ: 'JWT',
      alg: this.algorithm,
      kid: jwkThumbprint.substring(0, 16) // Short identifier
    };

    const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
    const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));

    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const signature = createSign(this.algorithm.toLowerCase())
      .update(signingInput)
      .end()
      .sign(this.privateKey);

    const encodedSignature = this.base64UrlEncode(signature);

    logger.audit('Access Token Generated', {
      component: 'session-security',
      userId,
      tokenId: jti,
      scopes
    });

    return {
      accessToken: `${signingInput}.${encodedSignature}`,
      dpopJwkThumbprint: jwkThumbprint
    };
  }

  /**
   * Generate a DPoP proof token for a specific HTTP request
   */
  async generateDPoPProof(
    accessToken: string,
    httpMethod: string,
    httpUrl: string,
    publicKeyJwk: any
  ): Promise<string> {
    const jti = this.generateId();
    const now = Math.floor(Date.now() / 1000);
    const ath = this.calculateAccessTokenHash(accessToken);

    const payload: DPoPTokenPayload = {
      jti,
      htm: httpMethod,
      htu: httpUrl,
      iat: now,
      exp: now + 300, // 5 minutes
      nonce: this.generateNonce(),
      ath
    };

    const header = {
      typ: 'dpop+jwt',
      alg: this.algorithm,
      jwk: publicKeyJwk
    };

    const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
    const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));

    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const signature = createSign(this.algorithm.toLowerCase())
      .update(signingInput)
      .end()
      .sign(this.privateKey);

    const encodedSignature = this.base64UrlEncode(signature);

    logger.debug('DPoP Proof Generated', {
      component: 'session-security',
      tokenId: jti,
      method: httpMethod,
      url: httpUrl
    });

    return `${signingInput}.${encodedSignature}`;
  }

  /**
   * Validate an access token
   */
  async validateAccessToken(token: string): Promise<{
    valid: boolean;
    payload?: AccessTokenPayload;
    error?: string;
  }> {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        return { valid: false, error: 'Invalid token format' };
      }

      const [encodedHeader, encodedPayload, encodedSignature] = parts;
      const header = JSON.parse(this.base64UrlDecode(encodedHeader));
      const payload: AccessTokenPayload = JSON.parse(this.base64UrlDecode(encodedPayload));
      const signature = this.base64UrlDecode(encodedSignature);

      // Verify algorithm
      if (header.alg !== this.algorithm) {
        return { valid: false, error: 'Invalid algorithm' };
      }

      // Check expiration
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp < now) {
        return { valid: false, error: 'Token expired' };
      }

      // Verify signature
      const signingInput = `${encodedHeader}.${encodedPayload}`;
      const verifier = createVerify(this.algorithm.toLowerCase());
      verifier.update(signingInput);
      
      const isValid = verifier.verify(this.publicKey, signature);
      if (!isValid) {
        return { valid: false, error: 'Invalid signature' };
      }

      // Log successful validation
      logger.debug('Access Token Validated', {
        component: 'session-security',
        userId: payload.sub,
        tokenId: payload.jti
      });

      return { valid: true, payload };
    } catch (error) {
      logger.warn('Access Token Validation Failed', {
        component: 'session-security',
        error: error instanceof Error ? error.message : String(error)
      });
      return { valid: false, error: 'Token validation failed' };
    }
  }

  /**
   * Validate a DPoP proof token
   */
  async validateDPoPProof(
    dpopProof: string,
    expectedHttpMethod: string,
    expectedHttpUrl: string,
    accessToken: string
  ): Promise<{
    valid: boolean;
    payload?: DPoPTokenPayload;
    error?: string;
  }> {
    try {
      const parts = dpopProof.split('.');
      if (parts.length !== 3) {
        return { valid: false, error: 'Invalid DPoP proof format' };
      }

      const [encodedHeader, encodedPayload, encodedSignature] = parts;
      const header: any = JSON.parse(this.base64UrlDecode(encodedHeader));
      const payload: DPoPTokenPayload = JSON.parse(this.base64UrlDecode(encodedPayload));
      const signature = this.base64UrlDecode(encodedSignature);

      // Verify algorithm
      if (header.alg !== this.algorithm) {
        return { valid: false, error: 'Invalid algorithm in DPoP proof' };
      }

      // Verify HTTP method and URL match
      if (payload.htm !== expectedHttpMethod || payload.htu !== expectedHttpUrl) {
        return { valid: false, error: 'HTTP method or URL mismatch' };
      }

      // Check expiration
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp < now) {
        return { valid: false, error: 'DPoP proof expired' };
      }

      // Verify nonce (replay protection)
      if (this.nonceStore.has(payload.nonce)) {
        return { valid: false, error: 'Replay attack detected' };
      }

      // Verify access token hash
      const expectedAth = this.calculateAccessTokenHash(accessToken);
      if (payload.ath !== expectedAth) {
        return { valid: false, error: 'Access token hash mismatch' };
      }

      // Verify signature using the public key from the header
      const signingInput = `${encodedHeader}.${encodedPayload}`;
      const publicKeyJwk = header.jwk;
      const publicKeyDer = await this.jwkToDer(publicKeyJwk);
      
      const verifier = createVerify(this.algorithm.toLowerCase());
      verifier.update(signingInput);
      
      let isValid = verifier.verify(publicKeyDer, signature);
      
      // If primary key fails, try rotated key as a fallback
      if (!isValid && this.rotatedPublicKey) {
        const rotatedVerifier = createVerify(this.algorithm.toLowerCase());
        rotatedVerifier.update(signingInput);
        isValid = rotatedVerifier.verify(this.rotatedPublicKey, signature);
      }
      if (!isValid) {
        return { valid: false, error: 'Invalid DPoP proof signature' };
      }

      // Store nonce to prevent replay attacks
      this.nonceStore.set(payload.nonce, Date.now());
      
      // Clean up old nonces periodically (based on their timestamp)
      this.cleanupExpiredNonces();

      logger.debug('DPoP Proof Validated', {
        component: 'session-security',
        tokenId: payload.jti,
        method: expectedHttpMethod,
        url: expectedHttpUrl
      });

      return { valid: true, payload };
    } catch (error) {
      logger.warn('DPoP Proof Validation Failed', {
        component: 'session-security',
        error: error instanceof Error ? error.message : String(error)
      });
      return { valid: false, error: 'DPoP proof validation failed' };
    }
  }

  /**
   * Clean up expired nonces from the store
   */
  private cleanupExpiredNonces(): void {
    const now = Date.now();
    const fiveMinutesAgo = now - (5 * 60 * 1000); // Nonces expire after 5 minutes
    
    for (const [nonce, timestamp] of this.nonceStore.entries()) {
      if (timestamp < fiveMinutesAgo) {
        this.nonceStore.delete(nonce);
      }
    }
  }

  /**
   * Revoke a session by invalidating tokens
   */
  async revokeSession(userId: string, tokenId: string): Promise<boolean> {
    // In production, this would involve blacklisting tokens in a distributed store
    logger.audit('Session Revoked', {
      component: 'session-security',
      userId,
      tokenId
    });

    // Add to revocation list in ledger
    const ledger = getLedger();
    await ledger.addEntry({
      transactionId: `revoke-${tokenId}`,
      userId,
      action: 'freeze',
      status: 'confirmed',
      metadata: {
        revokedToken: tokenId,
        reason: 'explicit_revocation'
      }
    });

    return true;
  }

  private generateId(): string {
    return randomBytes(16).toString('hex');
  }

  private generateNonce(): string {
    return randomBytes(16).toString('hex');
  }

  private base64UrlEncode(str: string | Buffer): string {
    return Buffer.from(str)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  private base64UrlDecode(str: string): string {
    // Add padding if needed
    str += '='.repeat((4 - (str.length % 4)) % 4);
    return Buffer.from(
      str.replace(/-/g, '+').replace(/_/g, '/'),
      'base64'
    ).toString();
  }

  private calculateAccessTokenHash(token: string): string {
    return createHash('sha256')
      .update(token)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  private generateKeyPair(): { privateKey: Buffer; publicKey: Buffer } {
    // In production, keys should come from HSM
    // This is for demonstration purposes only
    const { generateKeyPairSync } = require('crypto') as typeof import('crypto');
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: 'prime256v1'
    });
    
    return {
      privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }),
      publicKey: publicKey.export({ type: 'spki', format: 'der' })
    };
  }

  /**
   * Check if keys need rotation and rotate if necessary
   */
  private checkAndRotateKeys(): void {
    const now = Date.now();
    if (now - this.lastKeyRotation > this.keyRotationInterval) {
      // Rotate keys
      const { privateKey, publicKey } = this.generateKeyPair();
      this.rotatedPrivateKey = this.privateKey; // Old key becomes backup
      this.rotatedPublicKey = this.publicKey;
      this.privateKey = privateKey;
      this.publicKey = publicKey;
      this.lastKeyRotation = now;
      
      logger.info('DPoP Keys rotated', {
        component: 'session-security',
        timestamp: now
      });
    }
  }

  /**
   * Get the current or rotated public key for validation
   */
  private getPublicKeyForVerification(useRotatedKey: boolean = false): Buffer {
    if (useRotatedKey && this.rotatedPublicKey) {
      return this.rotatedPublicKey;
    }
    return this.publicKey;
  }

  /**
   * Verify if a token was signed with a rotated key
   */
  private isSignedWithRotatedKey(token: string, signingInput: string, signature: Buffer): boolean {
    if (!this.rotatedPublicKey) {
      return false;
    }

    const verifier = createVerify(this.algorithm.toLowerCase());
    verifier.update(signingInput);
    return verifier.verify(this.rotatedPublicKey, signature);
  }

  private async publicKeyToJWK(publicKey: Buffer): Promise<any> {
    // Convert DER to JWK (simplified implementation)
    // In production, use a proper library for this conversion
    const base64Key = publicKey.toString('base64');
    
    // This is a simplified representation - real implementation would parse DER
    return {
      kty: 'EC',
      crv: 'P-256',
      x: this.base64UrlEncode(base64Key.substring(0, 32)),
      y: this.base64UrlEncode(base64Key.substring(32, 64))
    };
  }

  private async calculateJwkThumbprint(jwk: any): Promise<string> {
    const json = JSON.stringify(jwk, Object.keys(jwk).sort());
    return createHash('sha256')
      .update(json)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  private async jwkToDer(jwk: any): Promise<Buffer> {
    // Simplified DER generation from JWK
    // In production, use a proper library for this conversion
    const x = this.base64UrlDecode(jwk.x);
    const y = this.base64UrlDecode(jwk.y);
    
    // Combine x and y coordinates for P-256 curve
    const uncompressedPoint = Buffer.concat([
      Buffer.from([0x04]), // Uncompressed point prefix
      Buffer.from(x, 'binary'),
      Buffer.from(y, 'binary')
    ]);
    
    // Return as DER format (this is a simplified representation)
    return uncompressedPoint;
  }
}

// Singleton instance
let sessionManager: DPoPSessionManager | null = null;

export function getSessionManager(): DPoPSessionManager {
  if (!sessionManager) {
    sessionManager = new DPoPSessionManager();
  }
  return sessionManager;
}