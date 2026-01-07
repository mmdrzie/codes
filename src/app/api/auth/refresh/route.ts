import { NextRequest, NextResponse } from 'next/server';
import { checkRateLimit, getIdentifier } from '@/lib/rateLimit';
import { getRefreshToken, setAuthCookies } from '@/lib/cookies';
import { generateTokenPair, verifyRefreshToken } from '@/lib/tokenUtils';
import { addToBlacklist, isTokenBlacklisted } from '@/lib/sessionUtils';

export async function POST(request: NextRequest) {
  // Rate limit per IP
  const identifier = getIdentifier(request);
  const rl = checkRateLimit(identifier, 'api');

  if (!rl.allowed) {
    return NextResponse.json(
      { error: rl.message || 'Rate limit exceeded', resetAt: rl.resetAt },
      {
        status: 429,
        headers: {
          'X-RateLimit-Limit': String(100),
          'X-RateLimit-Remaining': String(rl.remaining),
          'X-RateLimit-Reset': String(rl.resetAt),
        },
      }
    );
  }

  const refreshToken = await getRefreshToken();
  if (!refreshToken) {
    return NextResponse.json({ error: 'Authentication required' }, { status: 401 });
  }

  // Token rotation + blacklist
  if (await isTokenBlacklisted(refreshToken)) {
    return NextResponse.json({ error: 'Token revoked', shouldLogout: true }, { status: 401 });
  }

  const payload = verifyRefreshToken(refreshToken);
  if (!payload) {
    // If refresh token is malformed/invalid, blacklist it briefly to mitigate replay
    await addToBlacklist(refreshToken, 24 * 60 * 60);
    return NextResponse.json({ error: 'Invalid refresh token', shouldLogout: true }, { status: 401 });
  }

  // Issue new pair
  const tokens = generateTokenPair({
    userId: payload.userId,
    tenantId: payload.tenantId,
    email: payload.email,
    walletAddress: payload.walletAddress,
    authMethod: payload.authMethod,
    role: payload.role,
  });

  // Revoke old refresh token (rotation)
  await addToBlacklist(refreshToken, 7 * 24 * 60 * 60);

  const response = NextResponse.json({
    success: true,
    expiresIn: tokens.expiresIn,
  });

  await setAuthCookies(tokens.accessToken, tokens.refreshToken, undefined, response);

  // Security headers
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');

  if (process.env.NODE_ENV === 'production') {
    response.headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  }

  return response;
}

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';