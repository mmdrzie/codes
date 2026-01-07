import { jwtVerify } from 'jose';

export type AccessTokenPayload = {
  userId: string;
  tenantId?: string;
  email?: string;
  authMethod?: string;
  role?: string;
  iat?: number;
  exp?: number;
};

const ISSUER = 'quantumiq-app';
const AUDIENCE = 'quantumiq-app';

function getSecretKey(): Uint8Array {
  const secret = process.env.JWT_ACCESS_SECRET;
  if (!secret || secret.length < 32) {
    // In Edge runtime, fail closed.
    throw new Error('JWT_ACCESS_SECRET must be set (min 32 chars)');
  }
  return new TextEncoder().encode(secret);
}

/**
 * Edge-safe access-token verification (HS256).
 * Use only in middleware (Edge runtime).
 */
export async function verifyAccessTokenEdge(token: string): Promise<AccessTokenPayload | null> {
  try {
    const { payload } = await jwtVerify(token, getSecretKey(), {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ['HS256'],
    });

    const userId = typeof payload.userId === 'string' ? payload.userId : null;
    if (!userId) return null;

    return {
      userId,
      tenantId: typeof payload.tenantId === 'string' ? payload.tenantId : undefined,
      email: typeof payload.email === 'string' ? payload.email : undefined,
      authMethod: typeof payload.authMethod === 'string' ? payload.authMethod : undefined,
      role: typeof payload.role === 'string' ? payload.role : undefined,
      iat: typeof payload.iat === 'number' ? payload.iat : undefined,
      exp: typeof payload.exp === 'number' ? payload.exp : undefined,
    };
  } catch {
    return null;
  }
}
