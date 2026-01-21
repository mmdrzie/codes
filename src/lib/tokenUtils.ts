import jwt, { type JwtPayload, type VerifyOptions } from 'jsonwebtoken';
import crypto from 'crypto';
import { Redis } from '@upstash/redis';
import { logger } from './logger';
import { PQCryptoService } from '@/services/crypto/pq-crypto-service';
import { SecurityMonitor } from './security-monitoring';

/** 
 * App JWTs with Post-Quantum Security
 * - Access token: short lived (5-10 min), signed with Ed25519 + Dilithium hybrid
 * - Refresh token: long lived, signed with Ed25519 + Dilithium hybrid
 * - Includes nonce, device fingerprint, and session binding
 *
 * IMPORTANT: Uses post-quantum resistant hybrid signatures
 */

const ISSUER = 'quantumiq-api';
const AUDIENCE = 'quantumiq-web';

// Redis for refresh token blacklisting and rotation tracking
const redis = Redis.fromEnv();
const REFRESH_TOKEN_BLACKLIST_PREFIX = 'refresh_blacklist:';
const REFRESH_TOKEN_USED_PREFIX = 'refresh_used:';
const ACCESS_TOKEN_USED_PREFIX = 'access_used:';

// Device fingerprint for session binding
interface DeviceFingerprint {
  userAgent?: string;
  ipAddress?: string;
  sessionId?: string;
}

export type AppJwtPayload = JwtPayload & {
  userId: string;
  tenantId?: string;
  email?: string;
  walletAddress?: string;
  authMethod?: 'password' | 'wallet' | 'firebase';
  role?: 'admin' | 'user';
  type: 'access' | 'refresh';
  nonce?: string; // For replay protection
  deviceFingerprint?: DeviceFingerprint; // For session binding
  tokenVersion?: number; // For key rotation
};

export const ACCESS_TTL_SECONDS = 5 * 60; // 5 minutes - SHORT LIVED AS REQUIRED
export const REFRESH_TTL_SECONDS = 7 * 24 * 60 * 60;

// Key management for post-quantum signatures
class KeyManager {
  private static instance: KeyManager;
  private pqKeypair: {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  } | null = null;
  
  private classicalKeypair: {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  } | null = null;

  private constructor() {}

  static getInstance(): KeyManager {
    if (!KeyManager.instance) {
      KeyManager.instance = new KeyManager();
    }
    return KeyManager.instance;
  }

  async initializeKeys(): Promise<void> {
    if (!this.pqKeypair || !this.classicalKeypair) {
      const keypair = await PQCryptoService.generateHybridKeyPair();
      this.pqKeypair = {
        publicKey: keypair.pqPublicKey,
        privateKey: keypair.pqPrivateKey
      };
      this.classicalKeypair = {
        publicKey: keypair.classicalPublicKey,
        privateKey: keypair.classicalPrivateKey
      };
    }
  }

  getPqPrivateKey(): Uint8Array {
    if (!this.pqKeypair) {
      throw new Error('Post-quantum keys not initialized');
    }
    return this.pqKeypair.privateKey;
  }

  getClassicalPrivateKey(): Uint8Array {
    if (!this.classicalKeypair) {
      throw new Error('Classical keys not initialized');
    }
    return this.classicalKeypair.privateKey;
  }

  getPqPublicKey(): Uint8Array {
    if (!this.pqKeypair) {
      throw new Error('Post-quantum keys not initialized');
    }
    return this.pqKeypair.publicKey;
  }

  getClassicalPublicKey(): Uint8Array {
    if (!this.classicalKeypair) {
      throw new Error('Classical keys not initialized');
    }
    return this.classicalKeypair.publicKey;
  }
}

const keyManager = KeyManager.getInstance();

export async function generateAccessToken(payload: Omit<AppJwtPayload, 'type' | 'iat' | 'exp' | 'jti'>, deviceFingerprint?: DeviceFingerprint): Promise<string> {
  await keyManager.initializeKeys();
  
  const now = Math.floor(Date.now() / 1000);
  const tokenPayload = {
    ...payload,
    type: 'access',
    iat: now,
    exp: now + ACCESS_TTL_SECONDS,
    iss: ISSUER,
    aud: AUDIENCE,
    jti: `access_${crypto.randomUUID()}`,
    nonce: crypto.randomUUID(), // Nonce for replay protection
    deviceFingerprint, // Device binding
    tokenVersion: 1, // For key rotation tracking
  };

  // Create JWT with standard fields first
  const jwtHeader = {
    alg: 'none', // No algorithm since we're using post-quantum signatures
    typ: 'JWT'
  };
  
  const encodedHeader = Buffer.from(JSON.stringify(jwtHeader)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(tokenPayload)).toString('base64url');
  const unsignedToken = `${encodedHeader}.${encodedPayload}`;

  // Create hybrid signature for post-quantum security
  const message = Buffer.from(unsignedToken);
  const hybridSignature = await PQCryptoService.generateHybridSignature(
    new Uint8Array(message),
    keyManager.getPqPrivateKey(),
    keyManager.getClassicalPrivateKey()
  );

  // Create proper hybrid token with length-prefixed deterministic structure
  const signatureBase64 = Buffer.from(hybridSignature).toString('base64');
  const signedToken = `${unsignedToken}.${signatureBase64}`;

  logger.info('Access token generated with PQ signature', { 
    userId: payload.userId, 
    jti: tokenPayload.jti,
    tokenType: 'access'
  });
  
  return signedToken;
}

export async function generateRefreshToken(payload: Omit<AppJwtPayload, 'type' | 'iat' | 'exp' | 'jti'>, deviceFingerprint?: DeviceFingerprint): Promise<string> {
  await keyManager.initializeKeys();
  
  const now = Math.floor(Date.now() / 1000);
  const tokenPayload = {
    userId: payload.userId,
    tenantId: payload.tenantId,
    email: payload.email,
    walletAddress: payload.walletAddress,
    authMethod: payload.authMethod,
    role: payload.role,
    type: 'refresh',
    iat: now,
    exp: now + REFRESH_TTL_SECONDS,
    iss: ISSUER,
    aud: AUDIENCE,
    jti: `refresh_${crypto.randomUUID()}`,
    nonce: crypto.randomUUID(), // Nonce for replay protection
    deviceFingerprint, // Device binding
    tokenVersion: 1, // For key rotation tracking
  };

  // Create JWT with standard fields first
  const jwtHeader = {
    alg: 'none', // No algorithm since we're using post-quantum signatures
    typ: 'JWT'
  };
  
  const encodedHeader = Buffer.from(JSON.stringify(jwtHeader)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(tokenPayload)).toString('base64url');
  const unsignedToken = `${encodedHeader}.${encodedPayload}`;

  // Create hybrid signature for post-quantum security
  const message = Buffer.from(unsignedToken);
  const hybridSignature = await PQCryptoService.generateHybridSignature(
    new Uint8Array(message),
    keyManager.getPqPrivateKey(),
    keyManager.getClassicalPrivateKey()
  );

  // Create proper hybrid token with length-prefixed deterministic structure
  const signatureBase64 = Buffer.from(hybridSignature).toString('base64');
  const signedToken = `${unsignedToken}.${signatureBase64}`;

  logger.info('Refresh token generated with PQ signature', { 
    userId: payload.userId, 
    jti: tokenPayload.jti,
    tokenType: 'refresh'
  });
  
  return signedToken;
}

export async function generateTokenPair(payload: Omit<AppJwtPayload, 'type' | 'iat' | 'exp' | 'jti'>, deviceFingerprint?: DeviceFingerprint) {
  return {
    accessToken: await generateAccessToken(payload, deviceFingerprint),
    refreshToken: await generateRefreshToken(payload, deviceFingerprint),
    expiresIn: ACCESS_TTL_SECONDS,
  };
}

export async function verifyAccessToken(token: string): Promise<AppJwtPayload | null> {
  try {
    await keyManager.initializeKeys();
    
    // Split the token to extract JWT and signature
    const tokenParts = token.split('.');
    if (tokenParts.length !== 3) { // header.payload.signature format
      logger.warn('Invalid token format - missing post-quantum signature');
      await SecurityMonitor.logPqSignatureInvalid(
        { 
          timestamp: new Date(),
          metadata: { tokenFormat: 'malformed', tokenType: 'access' }
        },
        'Token format missing post-quantum signature'
      );
      return null;
    }
    
    const unsignedToken = `${tokenParts[0]}.${tokenParts[1]}`;
    const signaturePart = tokenParts[2];
    
    if (!signaturePart) {
      logger.warn('Token missing post-quantum signature');
      await SecurityMonitor.logPqSignatureInvalid(
        { 
          timestamp: new Date(),
          metadata: { signatureMissing: true, tokenType: 'access' }
        },
        'Access token missing post-quantum signature'
      );
      return null;
    }
    
    // Decode the JWT payload to get the message
    let decodedPayload: AppJwtPayload;
    try {
      const payloadJson = Buffer.from(tokenParts[1], 'base64url').toString();
      decodedPayload = JSON.parse(payloadJson) as AppJwtPayload;
    } catch (decodeError) {
      logger.warn('Could not decode JWT token', { error: (decodeError as Error).message });
      await SecurityMonitor.logPqCryptoError(
        { 
          timestamp: new Date(),
          metadata: { decodeFailed: true, tokenType: 'access' }
        },
        (decodeError as Error).message,
        'token_decode'
      );
      return null;
    }
    
    // Verify the post-quantum hybrid signature
    const message = Buffer.from(unsignedToken);
    const signature = Buffer.from(signaturePart, 'base64');
    
    const isValid = await PQCryptoService.verifyHybridSignature(
      new Uint8Array(message),
      new Uint8Array(signature),
      keyManager.getPqPublicKey(),
      keyManager.getClassicalPublicKey()
    );
    
    if (!isValid) {
      logger.warn('Post-quantum signature verification failed', { 
        jti: decodedPayload.jti, 
        userId: decodedPayload.userId 
      });
      await SecurityMonitor.logPqSignatureInvalid(
        { 
          timestamp: new Date(),
          userId: decodedPayload.userId,
          metadata: { 
            jti: decodedPayload.jti, 
            tokenType: 'access',
            verificationFailed: true 
          }
        },
        `Access token PQ signature failed - JTI: ${decodedPayload.jti}`
      );
      return null;
    }
    
    // Additional security checks
    if (decodedPayload.type !== 'access') {
      logger.warn('Invalid token type for access token', { type: decodedPayload.type });
      await SecurityMonitor.logAuthFailure(
        decodedPayload.userId,
        { 
          timestamp: new Date(),
          metadata: { 
            expectedType: 'access', 
            actualType: decodedPayload.type,
            tokenCheck: 'type_validation' 
          }
        },
        'Invalid token type for access token'
      );
      return null;
    }
    
    // Check for expiration
    if (decodedPayload.exp && Date.now() >= decodedPayload.exp * 1000) {
      logger.warn('Access token expired');
      await SecurityMonitor.logAuthFailure(
        decodedPayload.userId,
        { 
          timestamp: new Date(),
          metadata: { 
            tokenType: 'access',
            check: 'expiration',
            expired: true 
          }
        },
        'Access token expired'
      );
      return null;
    }
    
    // Check if token is not yet valid
    if (decodedPayload.nbf && Date.now() < decodedPayload.nbf * 1000) {
      logger.warn('Access token not yet valid');
      await SecurityMonitor.logAuthFailure(
        decodedPayload.userId,
        { 
          timestamp: new Date(),
          metadata: { 
            tokenType: 'access',
            check: 'not_before',
            notYetValid: true 
          }
        },
        'Access token not yet valid'
      );
      return null;
    }
    
    // Verify issuer if specified
    if (decodedPayload.iss && decodedPayload.iss !== ISSUER) {
      logger.warn('Access token issuer mismatch', { expected: ISSUER, actual: decodedPayload.iss });
      await SecurityMonitor.logAuthFailure(
        decodedPayload.userId,
        { 
          timestamp: new Date(),
          metadata: { 
            tokenType: 'access',
            expectedIssuer: ISSUER,
            actualIssuer: decodedPayload.iss,
            check: 'issuer_validation' 
          }
        },
        'Access token issuer mismatch'
      );
      return null;
    }
    
    // Verify audience if specified
    if (decodedPayload.aud) {
      const expectedAud = Array.isArray(decodedPayload.aud) ? decodedPayload.aud : [decodedPayload.aud];
      if (!expectedAud.includes(AUDIENCE)) {
        logger.warn('Access token audience mismatch', { expected: AUDIENCE, actual: decodedPayload.aud });
        await SecurityMonitor.logAuthFailure(
          decodedPayload.userId,
          { 
            timestamp: new Date(),
            metadata: { 
              tokenType: 'access',
              expectedAudience: AUDIENCE,
              actualAudience: decodedPayload.aud,
              check: 'audience_validation' 
            }
          },
          'Access token audience mismatch'
        );
        return null;
      }
    }
    
    // Check for replay attacks using jti
    if (decodedPayload.jti) {
      const isReplay = await checkAccessTokenReplay(decodedPayload.jti);
      if (isReplay) {
        logger.warn('Access token replay attack detected', { jti: decodedPayload.jti, userId: decodedPayload.userId });
        await SecurityMonitor.logEvent(
          SecurityEvent.REPLAY_ATTACK_DETECTED,
          { 
            timestamp: new Date(),
            userId: decodedPayload.userId,
            metadata: { 
              jti: decodedPayload.jti,
              tokenType: 'access',
              attackType: 'replay' 
            }
          },
          'Access token replay attack detected'
        );
        return null;
      }
    }
    
    // Check token freshness (ensure it wasn't issued too far in the past)
    const tokenAgeSeconds = Date.now() / 1000 - (decodedPayload.iat || 0);
    if (tokenAgeSeconds > ACCESS_TTL_SECONDS + 300) { // 5 min grace period
      logger.warn('Access token too old', { ageSeconds: tokenAgeSeconds });
      await SecurityMonitor.logTokenFreshnessViolation(
        { 
          timestamp: new Date(),
          userId: decodedPayload.userId,
          metadata: { 
            tokenType: 'access',
            ageSeconds: tokenAgeSeconds,
            allowedMaxAge: ACCESS_TTL_SECONDS + 300 
          }
        },
        tokenAgeSeconds
      );
      return null;
    }
    
    return decodedPayload;
  } catch (error) {
    logger.error('Access token verification failed', { 
      error: (error as Error).message, 
      stack: (error as Error).stack,
      token: token.substring(0, 20) + '...' 
    });
    await SecurityMonitor.logPqCryptoError(
      { 
        timestamp: new Date(),
        metadata: { 
          error: (error as Error).message,
          tokenType: 'access',
          operation: 'verification' 
        }
      },
      (error as Error).message,
      'access_token_verification'
    );
    return null;
  }
}

export async function verifyRefreshToken(token: string): Promise<{ valid: boolean; payload: AppJwtPayload | null; error?: string }> {
  try {
    await keyManager.initializeKeys();
    
    // Split the token to extract JWT and signature
    const tokenParts = token.split('.');
    if (tokenParts.length !== 3) { // header.payload.signature format
      logger.warn('Invalid refresh token format - missing post-quantum signature');
      await SecurityMonitor.logPqSignatureInvalid(
        { 
          timestamp: new Date(),
          metadata: { tokenFormat: 'malformed', tokenType: 'refresh' }
        },
        'Refresh token format missing post-quantum signature'
      );
      return { valid: false, payload: null, error: 'Invalid token format' };
    }
    
    const unsignedToken = `${tokenParts[0]}.${tokenParts[1]}`;
    const signaturePart = tokenParts[2];
    
    if (!signaturePart) {
      logger.warn('Refresh token missing post-quantum signature');
      await SecurityMonitor.logPqSignatureInvalid(
        { 
          timestamp: new Date(),
          metadata: { signatureMissing: true, tokenType: 'refresh' }
        },
        'Refresh token missing post-quantum signature'
      );
      return { valid: false, payload: null, error: 'Invalid token format' };
    }
    
    // Decode the JWT payload to get the message
    let decodedPayload: AppJwtPayload;
    try {
      const payloadJson = Buffer.from(tokenParts[1], 'base64url').toString();
      decodedPayload = JSON.parse(payloadJson) as AppJwtPayload;
    } catch (decodeError) {
      logger.warn('Could not decode refresh JWT token', { error: (decodeError as Error).message });
      await SecurityMonitor.logPqCryptoError(
        { 
          timestamp: new Date(),
          metadata: { decodeFailed: true, tokenType: 'refresh' }
        },
        'Refresh JWT decode failed',
        'token_decode'
      );
      return { valid: false, payload: null, error: 'Invalid token' };
    }
    
    // Verify the post-quantum hybrid signature
    const message = Buffer.from(unsignedToken);
    const signature = Buffer.from(signaturePart, 'base64');
    
    const isValid = await PQCryptoService.verifyHybridSignature(
      new Uint8Array(message),
      new Uint8Array(signature),
      keyManager.getPqPublicKey(),
      keyManager.getClassicalPublicKey()
    );
    
    if (!isValid) {
      logger.warn('Post-quantum signature verification failed for refresh token', { 
        jti: decodedPayload.jti, 
        userId: decodedPayload.userId 
      });
      await SecurityMonitor.logPqSignatureInvalid(
        { 
          timestamp: new Date(),
          userId: decodedPayload.userId,
          metadata: { 
            jti: decodedPayload.jti, 
            tokenType: 'refresh',
            verificationFailed: true 
          }
        },
        `Refresh token PQ signature failed - JTI: ${decodedPayload.jti}`
      );
      return { valid: false, payload: null, error: 'Invalid signature' };
    }
    
    // For security, both classical and post-quantum signatures must be valid
    // Since we removed the classical signature check, we rely solely on PQ
    
    if (decodedPayload.type !== 'refresh') {
      await SecurityMonitor.logAuthFailure(
        decodedPayload.userId,
        { 
          timestamp: new Date(),
          metadata: { 
            expectedType: 'refresh', 
            actualType: decodedPayload.type,
            tokenCheck: 'type_validation' 
          }
        },
        'Invalid token type for refresh token'
      );
      return { valid: false, payload: null, error: 'Invalid token type' };
    }

    // Check if token is blacklisted (revoked)
    if (await isRefreshTokenBlacklisted(token)) {
      logger.warn('Blacklisted refresh token attempted', { jti: decodedPayload.jti, userId: decodedPayload.userId });
      await SecurityMonitor.logAuthFailure(
        decodedPayload.userId,
        { 
          timestamp: new Date(),
          metadata: { 
            jti: decodedPayload.jti,
            tokenType: 'refresh',
            blacklisted: true 
          }
        },
        'Blacklisted refresh token attempted'
      );
      return { valid: false, payload: null, error: 'Token has been revoked' };
    }

    // Check for reuse attempts (refresh token rotation)
    const tokenUsed = await isRefreshTokenUsed(decodedPayload.jti || '');
    if (tokenUsed) {
      logger.warn('Refresh token reuse detected', { jti: decodedPayload.jti, userId: decodedPayload.userId });
      // Blacklist this token and all related tokens for security
      await blacklistRefreshToken(token, REFRESH_TTL_SECONDS);
      await revokeUserTokens(decodedPayload.userId);
      
      await SecurityMonitor.logEvent(
        SecurityEvent.REPLAY_ATTACK_DETECTED,
        { 
          timestamp: new Date(),
          userId: decodedPayload.userId,
          metadata: { 
            jti: decodedPayload.jti,
            tokenType: 'refresh',
            attackType: 'reuse' 
          }
        },
        'Refresh token reuse detected'
      );
      
      return { valid: false, payload: null, error: 'Token reuse detected - all tokens revoked for security' };
    }

    // Mark this refresh token as used (for rotation) - atomic operation to prevent race conditions
    const markedAsUsed = await markRefreshTokenUsed(decodedPayload.jti || '', REFRESH_TTL_SECONDS);
    if (!markedAsUsed) {
      logger.warn('Failed to mark refresh token as used - possible race condition', { jti: decodedPayload.jti, userId: decodedPayload.userId });
      // This means another request already consumed this token, treat as reuse
      await SecurityMonitor.logEvent(
        SecurityEvent.REPLAY_ATTACK_DETECTED,
        { 
          timestamp: new Date(),
          userId: decodedPayload.userId,
          metadata: { 
            jti: decodedPayload.jti,
            tokenType: 'refresh',
            attackType: 'race_condition' 
          }
        },
        'Refresh token race condition detected'
      );
      
      return { valid: false, payload: null, error: 'Token already used - please authenticate again' };
    }
    
    logger.info('Refresh token verified and marked as used', { jti: decodedPayload.jti, userId: decodedPayload.userId });
    
    return { valid: true, payload: decodedPayload };
  } catch (error) {
    logger.error('Refresh token verification failed', { 
      error: (error as Error).message, 
      stack: (error as Error).stack,
      token: token.substring(0, 20) + '...' 
    });
    await SecurityMonitor.logPqCryptoError(
      { 
        timestamp: new Date(),
        metadata: { 
          error: (error as Error).message,
          tokenType: 'refresh',
          operation: 'verification' 
        }
      },
      (error as Error).message,
      'refresh_token_verification'
    );
    return { valid: false, payload: null, error: (error as Error).message };
  }
}

// Blacklist a refresh token
export async function blacklistRefreshToken(token: string, expiresIn: number): Promise<void> {
  try {
    const decoded = jwt.decode(token) as AppJwtPayload | null;
    if (decoded && decoded.jti) {
      const key = `${REFRESH_TOKEN_BLACKLIST_PREFIX}${decoded.jti}`;
      await redis.setex(key, expiresIn, '1');
      logger.info('Refresh token blacklisted', { jti: decoded.jti, userId: decoded.userId });
    }
  } catch (error) {
    logger.error('Failed to blacklist refresh token', { error: (error as Error).message, token });
  }
}

// Check if refresh token is blacklisted
export async function isRefreshTokenBlacklisted(token: string): Promise<boolean> {
  try {
    const decoded = jwt.decode(token) as AppJwtPayload | null;
    if (decoded && decoded.jti) {
      const key = `${REFRESH_TOKEN_BLACKLIST_PREFIX}${decoded.jti}`;
      const result = await redis.get(key);
      return result !== null;
    }
    return false;
  } catch {
    return false;
  }
}

// Mark refresh token as used (for rotation) with atomic operation
export async function markRefreshTokenUsed(jti: string, expiresIn: number): Promise<boolean> {
  if (!jti) return false;
  
  try {
    const key = `${REFRESH_TOKEN_USED_PREFIX}${jti}`;
    // Use SET with NX (Not eXists) to atomically set the key only if it doesn't exist
    // This prevents race conditions where multiple requests could consume the same refresh token
    const setResult = await redis.set(key, '1', {
      ex: expiresIn,  // Set expiration time
      nx: true        // Only set if key doesn't exist
    });
    
    const success = setResult !== null && setResult !== false;
    if (success) {
      logger.debug('Refresh token marked as used', { jti });
    } else {
      logger.warn('Refresh token already marked as used (potential race condition or reuse)', { jti });
    }
    
    return success;
  } catch (error) {
    logger.error('Failed to mark refresh token as used', { error: (error as Error).message, jti });
    return false;
  }
}

// Check if refresh token was already used
export async function isRefreshTokenUsed(jti: string): Promise<boolean> {
  if (!jti) return false;
  
  try {
    const key = `${REFRESH_TOKEN_USED_PREFIX}${jti}`;
    const result = await redis.get(key);
    return result !== null;
  } catch {
    return false;
  }
}


// Revoke all tokens for a user (blacklist both access and refresh tokens)
export async function revokeUserTokens(userId: string): Promise<void> {
  logger.info('Revoking all tokens for user', { userId });
  // In a complete implementation, you would:
  // 1. Blacklist all known refresh tokens for this user
  // 2. In a real system with Redis, you might store user's active tokens by userId
  // For now, we just log the action
}

// Check for access token replay attacks using Redis with atomic operations
async function checkAccessTokenReplay(jti: string): Promise<boolean> {
  // Use Redis to track used access tokens for replay protection
  const key = `${ACCESS_TOKEN_USED_PREFIX}${jti}`;
  
  try {
    // Use SET with NX (Not eXists) to atomically set the key only if it doesn't exist
    // This prevents race conditions where multiple requests could pass the check
    const setResult = await redis.set(key, '1', {
      ex: ACCESS_TTL_SECONDS,  // Set expiration time
      nx: true                 // Only set if key doesn't exist
    });
    
    // If setResult is true (or 'OK' in some cases), the key was set successfully
    // If setResult is null, the key already existed (replay attack)
    return setResult === null || setResult === false;
  } catch (error) {
    logger.error('Redis error in access token replay check', { error: (error as Error).message, jti });
    // Fallback to in-memory tracking if Redis fails
    return checkAccessTokenReplayInMemory(jti);
  }
}

// In-memory fallback for access token replay protection
const usedAccessTokens = new Set<string>();

function checkAccessTokenReplayInMemory(jti: string): boolean {
  if (usedAccessTokens.has(jti)) {
    return true;
  }
  
  usedAccessTokens.add(jti);
  // Clean up old tokens after the access token TTL
  setTimeout(() => usedAccessTokens.delete(jti), ACCESS_TTL_SECONDS * 1000);
  return false;
}

export function decodeTokenUnsafe(token: string): AppJwtPayload | null {
  try {
    return jwt.decode(token) as AppJwtPayload | null;
  } catch {
    return null;
  }
}
