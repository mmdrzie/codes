import { getAdminAuthInstance } from '@/lib/firebaseAdmin';
import { verifyAccessToken } from '@/lib/tokenUtils';
import jwt, { JwtPayload, VerifyOptions } from 'jsonwebtoken';
import { Redis } from '@upstash/redis';
import crypto from 'crypto';
import { logger } from './logger';

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
  const app = verifyAccessToken(cookieValue);
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

// ✅ Revoke sessions with enhanced logging
export async function revokeUserSessions(user: SessionUser): Promise<void> {
  if (user.type === 'firebase' && user.uid) {
    const adminAuth = getAdminAuthInstance();
    await adminAuth.revokeRefreshTokens(user.uid);
    logger.info('Firebase user sessions revoked', { uid: user.uid });
  }
  // برای wallet sessions، باید client-side cookie پاک شود
  // server-side revocation با blacklist مدیریت می‌شود
}

// ✅ Enhanced session validation with binding checks
export async function validateSessionBinding(
  sessionId: string,
  currentIp: string,
  currentUserAgent: string
): Promise<boolean> {
  try {
    let sessionData: SessionMeta | null = null;
    
    if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
      const redisData = await redis.get(`${SESSION_PREFIX}${sessionId}`);
      if (redisData) {
        sessionData = JSON.parse(redisData as string) as SessionMeta;
      }
    } else {
      const memData = sessionMemory.get(sessionId);
      if (memData && memData.expiresAt > Date.now()) {
        sessionData = memData.meta;
      }
    }

    if (!sessionData) {
      logger.warn('Session not found during binding validation', { sessionId });
      return false;
    }

    // Update last access info
    sessionData.lastAccessed = Date.now();
    sessionData.lastAccessIp = currentIp;
    sessionData.lastAccessUserAgent = currentUserAgent;

    // Store updated session data
    if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
      const ttl = Math.floor((sessionData.createdAt + 7 * 24 * 60 * 60 * 1000 - Date.now()) / 1000);
      if (ttl > 0) {
        await redis.setex(`${SESSION_PREFIX}${sessionId}`, ttl, JSON.stringify(sessionData));
      }
    } else {
      const expiresAt = sessionData.createdAt + 7 * 24 * 60 * 60 * 1000;
      sessionMemory.set(sessionId, { meta: sessionData, expiresAt });
    }

    // Validate IP and User-Agent consistency (soft check)
    const isIpConsistent = !sessionData.ipAddress || 
                          currentIp.startsWith(sessionData.ipAddress.split(':')[0]) || 
                          currentIp === sessionData.ipAddress;
    
    const isUserAgentConsistent = !sessionData.userAgent || 
                                 currentUserAgent.includes(sessionData.userAgent.split(' ')[0]);

    if (!isIpConsistent) {
      logger.warn('IP inconsistency detected', { 
        sessionId, 
        originalIp: sessionData.ipAddress, 
        currentIp,
        userId: sessionData.userId
      });
    }

    if (!isUserAgentConsistent) {
      logger.warn('User-Agent inconsistency detected', { 
        sessionId, 
        originalUserAgent: sessionData.userAgent, 
        currentUserAgent,
        userId: sessionData.userId
      });
    }

    return true; // Allow access even with inconsistencies, but log them
  } catch (error) {
    logger.error('Session binding validation error', { 
      error: (error as Error).message, 
      sessionId,
      currentIp,
      currentUserAgent
    });
    return false;
  }
}

// ✅ Check for replay attacks using JWT ID (jti)
const usedJtiStore = new Set<string>();
const JWT_CLEANUP_INTERVAL = 60 * 60 * 1000; // 1 hour

// Clean up old JTIs periodically
setInterval(() => {
  usedJtiStore.clear(); // In production, implement proper TTL with Redis
}, JWT_CLEANUP_INTERVAL);

async function checkForReplayAttack(jti: string): Promise<boolean> {
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