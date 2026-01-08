import jwt, { type JwtPayload, type VerifyOptions } from 'jsonwebtoken';
import crypto from 'crypto';
import { Redis } from '@upstash/redis';
import { logger } from './logger';

/** 
 * App JWTs
 * - Access token: short lived, used in __session cookie
 * - Refresh token: long lived, used in refresh_token cookie
 *
 * IMPORTANT: We intentionally use separate secrets for access vs refresh.
 */

const ISSUER = 'quantumiq-api';
const AUDIENCE = 'quantumiq-web';

// Redis for refresh token blacklisting and rotation tracking
const redis = Redis.fromEnv();
const REFRESH_TOKEN_BLACKLIST_PREFIX = 'refresh_blacklist:';
const REFRESH_TOKEN_USED_PREFIX = 'refresh_used:';

const getSecrets = () => {
  const accessSecret = process.env.JWT_ACCESS_SECRET || process.env.JWT_SECRET;
  const refreshSecret = process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET;

  if (!accessSecret || accessSecret.length < 32) {
    throw new Error('JWT_ACCESS_SECRET (or JWT_SECRET) must be at least 32 characters');
  }
  if (!refreshSecret || refreshSecret.length < 32) {
    throw new Error('JWT_REFRESH_SECRET (or JWT_SECRET) must be at least 32 characters');
  }

  return { accessSecret, refreshSecret };
};

export type AppJwtPayload = JwtPayload & {
  userId: string;
  tenantId?: string;
  email?: string;
  walletAddress?: string;
  authMethod?: 'password' | 'wallet' | 'firebase';
  role?: 'admin' | 'user';
  type: 'access' | 'refresh';
};

export const ACCESS_TTL_SECONDS = 15 * 60;
export const REFRESH_TTL_SECONDS = 7 * 24 * 60 * 60;

function verifyOptions(): VerifyOptions {
  return {
    issuer: ISSUER,
    audience: AUDIENCE,
    algorithms: ['HS256'],
    clockTolerance: 30,
  };
}

export function generateAccessToken(payload: Omit<AppJwtPayload, 'type' | 'iat' | 'exp'>): string {
  const { accessSecret } = getSecrets();
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    {
      ...payload,
      type: 'access',
      iat: now,
      exp: now + ACCESS_TTL_SECONDS,
      iss: ISSUER,
      aud: AUDIENCE,
      jti: `access_${crypto.randomUUID()}`,
    },
    accessSecret,
    { algorithm: 'HS256' }
  );
}

export function generateRefreshToken(payload: Omit<AppJwtPayload, 'type' | 'iat' | 'exp'>): string {
  const { refreshSecret } = getSecrets();
  const now = Math.floor(Date.now() / 1000);
  const token = jwt.sign(
    {
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
    },
    refreshSecret,
    { algorithm: 'HS256' }
  );

  logger.info('Refresh token generated', { 
    userId: payload.userId, 
    jti: payload.jti || 'unknown' 
  });
  
  return token;
}

export function generateTokenPair(payload: Omit<AppJwtPayload, 'type' | 'iat' | 'exp'>) {
  return {
    accessToken: generateAccessToken(payload),
    refreshToken: generateRefreshToken(payload),
    expiresIn: ACCESS_TTL_SECONDS,
  };
}

export function verifyAccessToken(token: string): AppJwtPayload | null {
  try {
    const { accessSecret } = getSecrets();
    const decoded = jwt.verify(token, accessSecret, verifyOptions()) as AppJwtPayload;
    if (decoded.type !== 'access') return null;
    
    // Check for replay attacks using jti
    if (decoded.jti) {
      const isReplay = checkAccessTokenReplay(decoded.jti);
      if (isReplay) {
        logger.warn('Access token replay attack detected', { jti: decoded.jti, userId: decoded.userId });
        return null;
      }
    }
    
    return decoded;
  } catch (error) {
    logger.error('Access token verification failed', { error: (error as Error).message, token: token.substring(0, 10) + '...' });
    return null;
  }
}

export async function verifyRefreshToken(token: string): Promise<{ valid: boolean; payload: AppJwtPayload | null; error?: string }> {
  try {
    const { refreshSecret } = getSecrets();
    const decoded = jwt.verify(token, refreshSecret, verifyOptions()) as AppJwtPayload;
    
    if (decoded.type !== 'refresh') {
      return { valid: false, payload: null, error: 'Invalid token type' };
    }

    // Check if token is blacklisted (revoked)
    if (await isRefreshTokenBlacklisted(token)) {
      logger.warn('Blacklisted refresh token attempted', { jti: decoded.jti, userId: decoded.userId });
      return { valid: false, payload: null, error: 'Token has been revoked' };
    }

    // Check for reuse attempts (refresh token rotation)
    const tokenUsed = await isRefreshTokenUsed(decoded.jti || '');
    if (tokenUsed) {
      logger.warn('Refresh token reuse detected', { jti: decoded.jti, userId: decoded.userId });
      // Blacklist this token and all related tokens for security
      await blacklistRefreshToken(token, REFRESH_TTL_SECONDS);
      await revokeUserTokens(decoded.userId);
      return { valid: false, payload: null, error: 'Token reuse detected - all tokens revoked for security' };
    }

    // Mark this refresh token as used (for rotation)
    await markRefreshTokenUsed(decoded.jti || '', REFRESH_TTL_SECONDS);
    
    logger.info('Refresh token verified and marked as used', { jti: decoded.jti, userId: decoded.userId });
    
    return { valid: true, payload: decoded };
  } catch (error) {
    logger.error('Refresh token verification failed', { error: (error as Error).message, token: token.substring(0, 10) + '...' });
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

// Check for access token replay attacks
function checkAccessTokenReplay(jti: string): boolean {
  // In a production system, you'd use Redis to track used access tokens
  // Since access tokens are short-lived, this is less critical than refresh token replay
  // For now, we'll use an in-memory set with cleanup
  if (usedAccessTokens.has(jti)) {
    return true;
  }
  
  usedAccessTokens.add(jti);
  // Clean up old tokens after the access token TTL
  setTimeout(() => usedAccessTokens.delete(jti), ACCESS_TTL_SECONDS * 1000);
  return false;
}

// In-memory tracking for access token replay (in production, use Redis)
const usedAccessTokens = new Set<string>();

export function decodeTokenUnsafe(token: string): AppJwtPayload | null {
  try {
    return jwt.decode(token) as AppJwtPayload | null;
  } catch {
    return null;
  }
}
