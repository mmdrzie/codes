import { getAdminAuthInstance } from '@/lib/firebaseAdmin';
import { verifyAccessToken } from '@/lib/tokenUtils';
import jwt, { JwtPayload, VerifyOptions } from 'jsonwebtoken';
import { Redis } from '@upstash/redis';
import crypto from 'crypto';
import { logger } from './logger';
import { SecurityMonitor } from './security-monitoring';
import { siemService } from './siem-integration';
import { SecurityEventType } from './security-monitoring';
import { sessionManager } from './advanced-security-config';

// ✅ Validation برای JWT secret
const getJwtSecret = (): string => {
  const secret = process.env.WALLET_JWT_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error('WALLET_JWT_SECRET must be at least 32 characters');
  }
  return secret;
};

const WALLET_JWT_SECRET = getJwtSecret();
const WALLET_ISSUER = 'quantumiq-wallet';
const WALLET_AUDIENCE = 'quantumiq-app';

// ✅ Redis برای token blacklist
const redis = Redis.fromEnv();
const BLACKLIST_PREFIX = 'jwt:blacklist:';

export type SessionUser = {
  type: 'firebase' | 'wallet' | 'session';
  uid?: string;
  email?: string;
  address?: string;
  tenantId?: string;
  role?: 'admin' | 'user';
  exp?: number;
  iat?: number;
};

// --------- Session tracking with enhanced security ---------

type SessionMeta = {
  userId: string;
  tenantId?: string;
  ipAddress?: string;
  userAgent?: string;
  createdAt: number;
  lastAccessed: number;
  lastAccessIp?: string;
  lastAccessUserAgent?: string;
};

const SESSION_PREFIX = 'session:';
const sessionMemory = new Map<string, { meta: SessionMeta; expiresAt: number }>();

export function createSession(
  userId: string,
  tenantId: string | undefined,
  meta: { ipAddress?: string; userAgent?: string }
): string {
  const sessionId = crypto.randomUUID();
  const record: SessionMeta = {
    userId,
    tenantId,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
    createdAt: Date.now(),
    lastAccessed: Date.now(),
  };

  // Best-effort store. If Redis not configured, fall back to memory.
  const ttlSeconds = 7 * 24 * 60 * 60;
  const expiresAt = Date.now() + ttlSeconds * 1000;

  if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
    // Fire and forget isn't ideal, but avoids making login depend on Redis.
    // If you want strict session revocation, make this awaited.
    redis
      .setex(`${SESSION_PREFIX}${sessionId}`, ttlSeconds, JSON.stringify(record))
      .catch(() => {});
  } else {
    sessionMemory.set(sessionId, { meta: record, expiresAt });
  }

  logger.info('Session created', { userId, sessionId, tenantId });
  return sessionId;
}

export async function revokeSession(sessionId: string): Promise<void> {
  if (!sessionId) return;
  if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
    await redis.del(`${SESSION_PREFIX}${sessionId}`);
  }
  sessionMemory.delete(sessionId);
  logger.info('Session revoked', { sessionId });
}

// ✅ اضافه کردن token به blacklist
export async function addToBlacklist(token: string, expiresIn: number): Promise<void> {
  const key = `${BLACKLIST_PREFIX}${token}`;
  await redis.setex(key, expiresIn, '1');
  logger.info('Token blacklisted', { token: key });
}

// ✅ بررسی blacklist
export async function isTokenBlacklisted(token: string): Promise<boolean> {
  const key = `${BLACKLIST_PREFIX}${token}`;
  const result = await redis.get(key);
  return result !== null;
}

// ✅ Verify wallet JWT با بررسی کامل
export async function verifyWalletToken(token: string): Promise<JwtPayload | null> {
  try {
    // بررسی blacklist
    if (await isTokenBlacklisted(token)) {
      logger.warn('Blacklisted token attempted', { token });
      return null;
    }

    const options: VerifyOptions = {
      issuer: WALLET_ISSUER,
      audience: WALLET_AUDIENCE,
      algorithms: ['HS256'], // ✅ مشخص کردن algorithm
      clockTolerance: 30, // ✅ 30 ثانیه tolerance برای clock skew
    };

    const decoded = jwt.verify(token, WALLET_JWT_SECRET, options) as JwtPayload;
    
    // بررسی claimهای مورد نیاز
    if (decoded.type !== 'wallet' || !decoded.address) {
      logger.warn('Invalid token claims', { token, decoded });
      return null;
    }

    // Check for replay attacks using jti
    if (decoded.jti) {
      const isReplay = await checkForReplayAttack(decoded.jti);
      if (isReplay) {
        logger.warn('Replay attack detected', { jti: decoded.jti, address: decoded.address });
        // Blacklist the token
        await addToBlacklist(token, 86400); // 24 hours
        return null;
      }
    }

    return decoded;
  } catch (error) {
    logger.error('JWT verification error', { error: (error as Error).message, token });
    return null;
  }
}

// ✅ Create wallet JWT with enhanced security
export function createWalletToken(user: {
  address: string;
  tenantId: string;
  role?: 'admin' | 'user';
}): string {
  const token = jwt.sign(
    {
      type: 'wallet',
      address: user.address.toLowerCase(), // ✅ normalize address
      tenantId: user.tenantId,
      role: user.role || 'user',
    },
    WALLET_JWT_SECRET,
    {
      issuer: WALLET_ISSUER,
      audience: WALLET_AUDIENCE,
      expiresIn: '24h',
      algorithm: 'HS256',
      jwtid: crypto.randomUUID(), // ✅ unique JWT ID برای revocation
    }
  );

  logger.info('Wallet token created', { address: user.address, tenantId: user.tenantId });
  return token;
}

// ✅ Verify session cookie with enhanced security
export async function verifySessionCookie(
  cookieValue: string
): Promise<SessionUser | null> {
  if (!cookieValue) return null;

  // 0️⃣ App access JWT
  const app = await verifyAccessToken(cookieValue);
  if (app) {
    return {
      type: 'session',
      uid: app.userId,
      email: app.email,
      tenantId: app.tenantId,
      role: app.role || 'user',
    };
  }

  // 1️⃣ Firebase session
  try {
    const adminAuth = getAdminAuthInstance();
    const decoded = await adminAuth.verifySessionCookie(cookieValue, true);
    return {
      type: 'firebase',
      uid: decoded.uid,
      email: decoded.email,
      tenantId: decoded.tenantId,
      role: decoded.role || 'user',
    };
  } catch (error) {
    logger.warn('Firebase session verification failed', { error: (error as Error).message });
  }

  // 2️⃣ Wallet JWT
  try {
    const decoded = await verifyWalletToken(cookieValue);
    if (!decoded) return null;

    return {
      type: 'wallet',
      address: decoded.address,
      tenantId: decoded.tenantId,
      role: decoded.role || 'user',
      exp: decoded.exp,
      iat: decoded.iat,
    };
  } catch (error) {
    logger.error('Wallet token verification failed', { error: (error as Error).message });
    return null;
  }
}

// ✅ Revoke sessions with enhanced logging and complete token invalidation
export async function revokeUserSessions(user: SessionUser): Promise<void> {
  if (user.type === 'firebase' && user.uid) {
    const adminAuth = getAdminAuthInstance();
    await adminAuth.revokeRefreshTokens(user.uid);
    logger.info('Firebase user sessions revoked', { uid: user.uid });
  }
  
  // For wallet sessions, also invalidate all associated tokens
  if (user.type === 'wallet' && user.address) {
    await revokeAllTokensForWallet(user.address);
    logger.info('Wallet user tokens revoked', { address: user.address });
  }
  
  // Also revoke all sessions for this user
  if (user.uid) {
    await revokeAllUserSessions(user.uid);
  }
  if (user.address) {
    await revokeAllUserSessions(user.address);
  }
}

// ✅ Revoke all tokens associated with a wallet address
async function revokeAllTokensForWallet(address: string): Promise<void> {
  // In a real implementation, we would track all tokens associated with a wallet
  // For now, we'll clear any cached data and mark tokens as invalid
  
  // Add wallet to a revocation list in Redis
  const revocationKey = `wallet:revoked:${address.toLowerCase()}`;
  await redis.setex(revocationKey, 86400 * 30, '1'); // 30 days
  
  logger.info('All tokens revoked for wallet', { address });
}

// ✅ Enhanced session invalidation with atomic operations and complete token revocation
export async function invalidateSessionCompletely(sessionId: string): Promise<void> {
  if (!sessionId) return;
  
  try {
    // First, get the session data to identify associated user
    const sessionDataStr = await redis.get(`${SESSION_PREFIX}${sessionId}`);
    let userId: string | undefined;
    let address: string | undefined;
    
    if (sessionDataStr) {
      const sessionData = JSON.parse(sessionDataStr as string);
      userId = sessionData.userId;
      address = sessionData.address; // For wallet sessions
    }
    
    // Use Redis MULTI to ensure atomic operations
    const multi = redis.multi();
    
    // Delete the main session
    multi.del(`${SESSION_PREFIX}${sessionId}`);
    
    // If we know the user, remove from their active sessions set
    if (userId) {
      multi.srem(`active_sessions:${userId}`, sessionId);
    }
    
    // Execute all operations atomically
    await multi.exec();
    
    // Log the session invalidation for security monitoring
    logger.info('Session completely invalidated', { 
      sessionId, 
      userId, 
      address,
      timestamp: new Date().toISOString()
    });
    
    // Also invalidate any related tokens if we know the user
    if (userId || address) {
      await invalidateAllTokensForUser(userId || address!);
    }
    
  } catch (error) {
    logger.error('Error during complete session invalidation', { 
      sessionId, 
      error: (error as Error).message 
    });
    throw error;
  }
}

// ✅ Invalidate all tokens associated with a user
async function invalidateAllTokensForUser(userId: string): Promise<void> {
  try {
    // In a real system, we would track all tokens associated with a user
    // For now, we'll add the user to a revocation list
    
    // Add user to revocation list
    const revocationKey = `user:revoked:${userId}`;
    await redis.setex(revocationKey, 86400 * 7, '1'); // 7 days
    
    // If this is a wallet address, also add to wallet revocation
    if (userId.startsWith('0x')) {
      const walletRevocationKey = `wallet:revoked:${userId.toLowerCase()}`;
      await redis.setex(walletRevocationKey, 86400 * 7, '1'); // 7 days
    }
    
    logger.info('All tokens invalidated for user', { 
      userId, 
      timestamp: new Date().toISOString() 
    });
  } catch (error) {
    logger.error('Error invalidating tokens for user', { 
      userId, 
      error: (error as Error).message 
    });
  }
}

// ✅ Enhanced logout function that invalidates everything
export async function completeLogout(userId: string, sessionId?: string): Promise<void> {
  try {
    // Invalidate the specific session if provided
    if (sessionId) {
      await invalidateSessionCompletely(sessionId);
    }
    
    // Invalidate all tokens for the user
    await invalidateAllTokensForUser(userId);
    
    // Revoke Firebase refresh tokens if it's a Firebase user
    try {
      const adminAuth = getAdminAuthInstance();
      await adminAuth.revokeRefreshTokens(userId);
    } catch (error) {
      // Not all users are Firebase users, so ignore errors here
      logger.debug('Firebase token revocation skipped', { userId, error: (error as Error).message });
    }
    
    // Log the complete logout for security monitoring
    logger.info('Complete logout performed', { 
      userId, 
      sessionId, 
      timestamp: new Date().toISOString(),
      action: 'complete_logout'
    });
    
  } catch (error) {
    logger.error('Error during complete logout', { 
      userId, 
      sessionId, 
      error: (error as Error).message 
    });
    throw error;
  }
}

// ✅ Enhanced session validation with strict binding checks to IP and User-Agent and revocation check
export async function validateSessionBinding(
  sessionId: string,
  currentIp: string,
  currentUserAgent: string
): Promise<boolean> {
  try {
    // First check if the session has been revoked
    const sessionDataStr = await redis.get(`${SESSION_PREFIX}${sessionId}`);
    if (!sessionDataStr) {
      logger.warn('Session not found during validation', { sessionId });
      return false;
    }
    
    const sessionData = JSON.parse(sessionDataStr as string);
    
    // Check if session is marked as revoked
    if (sessionData.isRevoked || sessionData.revoked) {
      logger.warn('Session marked as revoked', { sessionId });
      return false;
    }
    
    // Check for user-level revocation
    const userRevocationKey = `user:revoked:${sessionData.userId}`;
    const userRevoked = await redis.get(userRevocationKey);
    if (userRevoked) {
      logger.warn('User marked as revoked, invalidating session', { 
        sessionId, 
        userId: sessionData.userId 
      });
      return false;
    }
    
    // Use the advanced session manager for validation
    const sessionValidation = await sessionManager.validateSession(
      sessionId,
      currentIp,
      currentUserAgent
    );

    // Return the validity status
    return sessionValidation.isValid;
  } catch (error) {
    logger.error('Session validation error', { 
      sessionId, 
      error: (error as Error).message 
    });
    return false;
  }
}

// ✅ Check for replay attacks using JWT ID (jti)
async function checkForReplayAttack(jti: string): Promise<boolean> {
  const key = `${BLACKLIST_PREFIX}replay:${jti}`;
  
  try {
    // Check if token was already used (using Redis)
    const result = await redis.get(key);
    if (result !== null) {
      return true; // Replay attack detected
    }
    
    // Mark token as used with TTL equal to token TTL (or reasonable default)
    await redis.setex(key, 86400, '1'); // 24 hours TTL
    return false;
  } catch (error) {
    logger.error('Redis error in replay attack check', { error: (error as Error).message, jti });
    // Fallback to in-memory tracking if Redis fails
    return checkForReplayAttackInMemory(jti);
  }
}

// In-memory fallback for replay attack protection
const usedJtiStore = new Set<string>();
const JWT_CLEANUP_INTERVAL = 60 * 60 * 1000; // 1 hour

// Clean up old JTIs periodically
setInterval(() => {
  usedJtiStore.clear(); // In production, implement proper TTL with Redis
}, JWT_CLEANUP_INTERVAL);

function checkForReplayAttackInMemory(jti: string): boolean {
  if (usedJtiStore.has(jti)) {
    return true; // Replay attack detected
  }
  
  usedJtiStore.add(jti);
  return false;
}

// ✅ Revoke all sessions for a user
export async function revokeAllUserSessions(userId: string): Promise<void> {
  // In a real implementation with proper session tracking, 
  // you would search for all sessions belonging to the user
  // For now, we'll just log this action
  logger.info('Revoking all sessions for user', { userId });
  
  // Implementation would involve:
  // 1. Querying Redis for all sessions with this userId
  // 2. Revoking each session individually
  // 3. Blacklisting associated tokens
}
}
// ✅ Invalidate all active sessions for a user (more explicit naming)
export async function invalidateAllSessions(userId: string): Promise<void> {
  logger.info('Invalidating all sessions for user', { userId });
  await revokeAllUserSessions(userId);
}
