import { NextRequest, NextResponse } from 'next/server';
import { getAdminAuthInstance } from '@/lib/firebaseAdmin';
import { generateTokenPair } from '@/lib/tokenUtils';
import { setAuthCookies } from '@/lib/cookies';
import { createSession } from '@/lib/sessionUtils';
import { getClientIp, getUserAgent } from '@/lib/helpers';

export async function POST(request: NextRequest) {
  const authHeader = request.headers.get('authorization') || '';
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  const idToken = match?.[1];

  if (!idToken) {
    return NextResponse.json({ error: 'Missing Authorization header' }, { status: 401 });
  }

  try {
    const adminAuth = getAdminAuthInstance();

    // ✅ if project/env mismatch, this is where it fails
    const decoded = await adminAuth.verifyIdToken(idToken);

    const userId = decoded.uid;

    const tokens = generateTokenPair({
      userId,
      tenantId: (decoded as any).tenantId,
      email: decoded.email,
      authMethod: 'firebase',
      role: (decoded as any).role || 'user',
    });

    const sessionId = createSession(userId, (decoded as any).tenantId, {
      ipAddress: getClientIp(request),
      userAgent: getUserAgent(request),
    });

    const response = NextResponse.json({ success: true }, { status: 200 });
    await setAuthCookies(tokens.accessToken, tokens.refreshToken, sessionId, response);
    return response;
  } catch (err: any) {
    // ✅ helps you see root cause in server logs
    console.error('sync-firebase verifyIdToken failed:', err?.message || err);
    return NextResponse.json({ error: 'Invalid Firebase token' }, { status: 401 });
  }
}

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
