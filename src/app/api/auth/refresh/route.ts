import { NextRequest, NextResponse } from 'next/server';
import { getEnterpriseRedisClient } from '@/infrastructure/redis/enterprise-redis-client';
import { EnterpriseRateLimiter } from '@/core/ratelimit/enterprise-rate-limiter';
import { getRefreshToken, setAuthCookies } from '@/lib/cookies';
import { generateTokenPair, verifyRefreshToken } from '@/lib/tokenUtils';
import { addToBlacklist, isTokenBlacklisted } from '@/lib/sessionUtils';
import { logger } from '@/lib/logger';
import { getClientIp } from '@/lib/helpers';

// Initialize enterprise components
const redisClient = getEnterpriseRedisClient();
const rateLimiter = new EnterpriseRateLimiter(redisClient);

export async function POST(request: NextRequest) {
  try {
    // CRITICAL: Apply rate limiting FIRST - FAILS CLOSED
    const identifier = getClientIp(request) || 'unknown';
    const rateLimitResult = await rateLimiter.checkRateLimit(
      `refresh:${identifier}`,
      'auth:session:create'
    );

    if (!rateLimitResult.allowed) {
      return NextResponse.json(
        { error: 'Rate limit exceeded', resetAt: rateLimitResult.resetAt },
        {
          status: 429,
          headers: {
            'X-RateLimit-Limit': String(rateLimitResult.policy?.maxRequests || 10),
            'X-RateLimit-Remaining': String(rateLimitResult.remaining),
            'X-RateLimit-Reset': String(rateLimitResult.resetAt),
          },
        }
      );
    }

    // Get refresh token from cookies
    const refreshToken = await getRefreshToken();
    if (!refreshToken) {
      return NextResponse.json({ error: 'Authentication required' }, { status: 401 });
    }

    // Check if token is blacklisted
    if (await isTokenBlacklisted(refreshToken)) {
      logger.warn('Blacklisted refresh token used', { tokenPrefix: refreshToken.substring(0, 8) });
      return NextResponse.json({ error: 'Token revoked', shouldLogout: true }, { status: 401 });
    }

    // Verify refresh token
    const verificationResult = await verifyRefreshToken(refreshToken);
    if (!verificationResult.valid || !verificationResult.payload) {
      // Blacklist invalid token to prevent replay
      await addToBlacklist(refreshToken, 24 * 60 * 60);
      return NextResponse.json({ error: 'Invalid refresh token', shouldLogout: true }, { status: 401 });
    }

    // Generate new token pair (rotation)
    const tokens = generateTokenPair({
      userId: verificationResult.payload.userId,
      tenantId: verificationResult.payload.tenantId,
      email: verificationResult.payload.email,
      walletAddress: verificationResult.payload.walletAddress,
      authMethod: verificationResult.payload.authMethod,
      role: verificationResult.payload.role,
    });

    // Revoke old refresh token (critical for security)
    await addToBlacklist(refreshToken, 7 * 24 * 60 * 60);

    // Create response
    const response = NextResponse.json({
      success: true,
      expiresIn: tokens.expiresIn,
    });

    // Set new cookies
    await setAuthCookies(tokens.accessToken, tokens.refreshToken, undefined, response);

    // Security headers
    response.headers.set('X-Content-Type-Options', 'nosniff');
    response.headers.set('X-Frame-Options', 'DENY');
    response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');

    if (process.env.NODE_ENV === 'production') {
      response.headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    }

    return response;
  } catch (error) {
    logger.error('Refresh token error', { error: (error as Error).message });
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
