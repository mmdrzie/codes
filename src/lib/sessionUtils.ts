import { getAdminAuthInstance } from '@/lib/firebaseAdmin';
import { verifyAccessToken } from '@/lib/tokenUtils';
import jwt, { JwtPayload, VerifyOptions } from 'jsonwebtoken';
import { Redis } from '@upstash/redis';
import crypto from 'crypto';

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

// --------- Session tracking (optional) ---------

type SessionMeta = {
  userId: string;
  tenantId?: string;
  ipAddress?: string;
  userAgent?: string;
  createdAt: number;
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

  return sessionId;
}

export async function revokeSession(sessionId: string): Promise<void> {
  if (!sessionId) return;
  if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
    await redis.del(`${SESSION_PREFIX}${sessionId}`);
  }
  sessionMemory.delete(sessionId);
}

// ✅ اضافه کردن token به blacklist
export async function addToBlacklist(token: string, expiresIn: number): Promise<void> {
  const key = `${BLACKLIST_PREFIX}${token}`;
  await redis.setex(key, expiresIn, '1');
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
      return null;
    }

    return decoded;
  } catch (error) {
    console.error('JWT verification error:', error);
    return null;
  }
}

// ✅ Create wallet JWT
export function createWalletToken(user: {
  address: string;
  tenantId: string;
  role?: 'admin' | 'user';
}): string {
  return jwt.sign(
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
}

// ✅ Verify session cookie
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
  } catch {}

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
  } catch {
    return null;
  }
}

// ✅ Revoke sessions
export async function revokeUserSessions(user: SessionUser): Promise<void> {
  if (user.type === 'firebase' && user.uid) {
    const adminAuth = getAdminAuthInstance();
    await adminAuth.revokeRefreshTokens(user.uid);
  }
  // برای wallet sessions، باید client-side cookie پاک شود
  // server-side revocation با blacklist مدیریت می‌شود
}