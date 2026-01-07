import jwt, { type JwtPayload, type VerifyOptions } from 'jsonwebtoken';
import crypto from 'crypto';

/**
 * App JWTs
 * - Access token: short lived, used in __session cookie
 * - Refresh token: long lived, used in refresh_token cookie
 *
 * IMPORTANT: We intentionally use separate secrets for access vs refresh.
 */

const ISSUER = 'quantumiq-api';
const AUDIENCE = 'quantumiq-web';

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
  return jwt.sign(
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
    return decoded;
  } catch {
    return null;
  }
}

export function verifyRefreshToken(token: string): AppJwtPayload | null {
  try {
    const { refreshSecret } = getSecrets();
    const decoded = jwt.verify(token, refreshSecret, verifyOptions()) as AppJwtPayload;
    if (decoded.type !== 'refresh') return null;
    return decoded;
  } catch {
    return null;
  }
}

export function decodeTokenUnsafe(token: string): AppJwtPayload | null {
  try {
    return jwt.decode(token) as AppJwtPayload | null;
  } catch {
    return null;
  }
}
