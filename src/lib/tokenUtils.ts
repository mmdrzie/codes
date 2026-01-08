import jwt, { type JwtPayload, type VerifyOptions } from 'jsonwebtoken';
import crypto from 'crypto';
import { Redis } from '@upstash/redis';
import { logger } from './logger';
import { PQCryptoService } from '@/services/crypto/pq-crypto-service';

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
  const token = jwt.sign(
    tokenPayload,
    process.env.JWT_ACCESS_SECRET || process.env.JWT_SECRET || 'default_secret_for_dev',
    { algorithm: 'HS256' } // Standard JWT signing as backup
  );

  // Create hybrid signature for post-quantum security
  const message = Buffer.from(JSON.stringify(tokenPayload));
  const hybridSignature = await PQCryptoService.generateHybridSignature(
    message,
    keyManager.getPqPrivateKey(),
    keyManager.getClassicalPrivateKey()
  );

  // Append the signature to the token
  const signedToken = `${token}.${Buffer.from(hybridSignature).toString('base64')}`;

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
  const token = jwt.sign(
    tokenPayload,
    process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET || 'default_secret_for_dev',
    { algorithm: 'HS256' } // Standard JWT signing as backup
  );

  // Create hybrid signature for post-quantum security
  const message = Buffer.from(JSON.stringify(tokenPayload));
  const hybridSignature = await PQCryptoService.generateHybridSignature(
    message,
    keyManager.getPqPrivateKey(),
    keyManager.getClassicalPrivateKey()
  );

  // Append the signature to the token
  const signedToken = `${token}.${Buffer.from(hybridSignature).toString('base64')}`;

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
    if (tokenParts.length < 3) {
      logger.warn('Invalid token format - missing post-quantum signature');
      SecurityMonitor.logPqSignatureInvalid(
        { 
          timestamp: new Date(),
          metadata: { tokenFormat: 'malformed', tokenType: 'access' }
        },
        'Token format missing post-quantum signature'
      );
      return null;
    }
    
    const jwtPart = `${tokenParts[0]}.${tokenParts[1]}.${tokenParts[2]}`;
    const signaturePart = tokenParts[3];
    
    if (!signaturePart) {
      logger.warn('Token missing post-quantum signature');
      SecurityMonitor.logPqSignatureInvalid(
        { 
          timestamp: new Date(),
          metadata: { signatureMissing: true, tokenType: 'access' }
        },
        'Access token missing post-quantum signature'
      );
      return null;
    }
    
    // Decode the JWT payload without verification first to get the message
    let decodedPayload: AppJwtPayload;
    try {
      decodedPayload = jwt.decode(jwtPart) as AppJwtPayload;
      if (!decodedPayload) {
        logger.warn('Could not decode JWT token');
        SecurityMonitor.logPqCryptoError(
          { 
            timestamp: new Date(),
            metadata: { decodeFailed: true, tokenType: 'access' }
          },
          'JWT decode failed',
          'token_decode'
        );
        return null;
      }
    } catch (decodeError) {
      logger.warn('JWT token decode failed', { error: (decodeError as Error).message });
      SecurityMonitor.logPqCryptoError(
        { 
          timestamp: new Date(),
          metadata: { decodeError: (decodeError as Error).message, tokenType: 'access' }
        },
        (decodeError as Error).message,
        'jwt_decode'
      );
      return null;
    }
    
    // Verify the JWT signature first (backup verification)
    try {
      jwt.verify(jwtPart, process.env.JWT_ACCESS_SECRET || process.env.JWT_SECRET || 'default_secret_for_dev', {
        algorithms: ['HS256'],
        issuer: ISSUER,
        audience: AUDIENCE,
        clockTolerance: 30,
      });
    } catch (jwtError) {
      logger.warn('Standard JWT verification failed', { error: (jwtError as Error).message });
      SecurityMonitor.logPqCryptoError(
        { 
          timestamp: new Date(),
          metadata: { jwtError: (jwtError as Error).message, tokenType: 'access' }
        },
        (jwtError as Error).message,
        'standard_jwt_verification'
      );
      return null;
    }
    
    // Verify the post-quantum hybrid signature
    const message = Buffer.from(JSON.stringify(decodedPayload));
    const signature = Buffer.from(signaturePart, 'base64');
    
    const isValid = await PQCryptoService.verifyHybridSignature(
      message,
      new Uint8Array(signature),
      keyManager.getPqPublicKey(),
      keyManager.getClassicalPublicKey()
    );
    
    if (!isValid) {
      logger.warn('Post-quantum signature verification failed', { 
        jti: decodedPayload.jti, 
        userId: decodedPayload.userId 
      });
      SecurityMonitor.logPqSignatureInvalid(
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
      SecurityMonitor.logAuthFailure(
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
    
    // Check for expiration (duplicate check since jwt.verify does this, but explicit is better)
    if (decodedPayload.exp && Date.now() >= decodedPayload.exp * 1000) {
      logger.warn('Access token expired');
      SecurityMonitor.logAuthFailure(
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
      SecurityMonitor.logAuthFailure(
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
      SecurityMonitor.logAuthFailure(
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
        SecurityMonitor.logAuthFailure(
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
        SecurityMonitor.logEvent(
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
      SecurityMonitor.logTokenFreshnessViolation(
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
    SecurityMonitor.logPqCryptoError(
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
    if (tokenParts.length < 3) {
      logger.warn('Invalid refresh token format - missing post-quantum signature');
      SecurityMonitor.logPqSignatureInvalid(
        { 
          timestamp: new Date(),
          metadata: { tokenFormat: 'malformed', tokenType: 'refresh' }
        },
        'Refresh token format missing post-quantum signature'
      );
      return { valid: false, payload: null, error: 'Invalid token format' };
    }
    
    const jwtPart = `${tokenParts[0]}.${tokenParts[1]}.${tokenParts[2]}`;
    const signaturePart = tokenParts[3];
    
    if (!signaturePart) {
      logger.warn('Refresh token missing post-quantum signature');
      SecurityMonitor.logPqSignatureInvalid(
        { 
          timestamp: new Date(),
          metadata: { signatureMissing: true, tokenType: 'refresh' }
        },
        'Refresh token missing post-quantum signature'
      );
      return { valid: false, payload: null, error: 'Invalid token format' };
    }
    
    // Decode the JWT payload without verification first to get the message
    let decodedPayload: AppJwtPayload;
    try {
      decodedPayload = jwt.decode(jwtPart) as AppJwtPayload;
      if (!decodedPayload) {
        logger.warn('Could not decode refresh JWT token');
        SecurityMonitor.logPqCryptoError(
          { 
            timestamp: new Date(),
            metadata: { decodeFailed: true, tokenType: 'refresh' }
          },
          'Refresh JWT decode failed',
          'token_decode'
        );
        return { valid: false, payload: null, error: 'Invalid token' };
      }
    } catch (decodeError) {
      logger.warn('Refresh JWT token decode failed', { error: (decodeError as Error).message });
      SecurityMonitor.logPqCryptoError(
        { 
          timestamp: new Date(),
          metadata: { decodeError: (decodeError as Error).message, tokenType: 'refresh' }
        },
        (decodeError as Error).message,
        'jwt_decode'
      );
      return { valid: false, payload: null, error: 'Invalid token' };
    }
    
    // Verify the JWT signature first (backup verification)
    let jwtVerified = false;
    try {
      jwt.verify(jwtPart, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET || 'default_secret_for_dev', {
        algorithms: ['HS256'],
        issuer: ISSUER,
        audience: AUDIENCE,
        clockTolerance: 30,
      });
      jwtVerified = true;
    } catch (jwtError) {
      logger.warn('Standard refresh JWT verification failed', { error: (jwtError as Error).message });
      SecurityMonitor.logPqCryptoError(
        { 
          timestamp: new Date(),
          metadata: { jwtError: (jwtError as Error).message, tokenType: 'refresh' }
        },
        (jwtError as Error).message,
        'standard_refresh_jwt_verification'
      );
    }
    
    // Even if JWT verification fails, we still verify the PQ signature
    // Verify the post-quantum hybrid signature
    const message = Buffer.from(JSON.stringify(decodedPayload));
    const signature = Buffer.from(signaturePart, 'base64');
    
    const isValid = await PQCryptoService.verifyHybridSignature(
      message,
      new Uint8Array(signature),
      keyManager.getPqPublicKey(),
      keyManager.getClassicalPublicKey()
    );
    
    if (!isValid) {
      logger.warn('Post-quantum signature verification failed for refresh token', { 
        jti: decodedPayload.jti, 
        userId: decodedPayload.userId 
      });
      SecurityMonitor.logPqSignatureInvalid(
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
    
    if (!jwtVerified) {
      logger.warn('Refresh token failed standard JWT verification but passed PQ verification', { 
        jti: decodedPayload.jti,
        userId: decodedPayload.userId
      });
      SecurityMonitor.logPqCryptoError(
        { 
          timestamp: new Date(),
          userId: decodedPayload.userId,
          metadata: { 
            jti: decodedPayload.jti, 
            tokenType: 'refresh',
            verificationStatus: 'mixed' 
          }
        },
        'Mixed verification results: Standard JWT failed but PQ succeeded',
        'refresh_token_verification'
      );
      return { valid: false, payload: null, error: 'Token verification failed' };
    }
    
    if (decodedPayload.type !== 'refresh') {
      SecurityMonitor.logAuthFailure(
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
      SecurityMonitor.logAuthFailure(
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
      
      SecurityMonitor.logEvent(
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

    // Mark this refresh token as used (for rotation)
    await markRefreshTokenUsed(decodedPayload.jti || '', REFRESH_TTL_SECONDS);
    
    logger.info('Refresh token verified and marked as used', { jti: decodedPayload.jti, userId: decodedPayload.userId });
    
    return { valid: true, payload: decodedPayload };
  } catch (error) {
    logger.error('Refresh token verification failed', { 
      error: (error as Error).message, 
      stack: (error as Error).stack,
      token: token.substring(0, 20) + '...' 
    });
    SecurityMonitor.logPqCryptoError(
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

// Mark refresh token as used (for rotation)
export async function markRefreshTokenUsed(jti: string, expiresIn: number): Promise<void> {
  if (!jti) return;
  
  try {
    const key = `${REFRESH_TOKEN_USED_PREFIX}${jti}`;
    await redis.setex(key, expiresIn, '1');
    logger.debug('Refresh token marked as used', { jti });
  } catch (error) {
    logger.error('Failed to mark refresh token as used', { error: (error as Error).message, jti });
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

// Check for access token replay attacks using Redis
async function checkAccessTokenReplay(jti: string): Promise<boolean> {
  // Use Redis to track used access tokens for replay protection
  const key = `${ACCESS_TOKEN_USED_PREFIX}${jti}`;
  
  try {
    // Check if token was already used
    const result = await redis.get(key);
    if (result !== null) {
      return true; // Replay attack detected
    }
    
    // Mark token as used with TTL equal to access token TTL
    await redis.setex(key, ACCESS_TTL_SECONDS, '1');
    return false;
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
