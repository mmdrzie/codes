import { NextResponse } from 'next/server';
import { clearAuthCookies, getRefreshToken, getSessionId } from '@/lib/cookies';
import { addToBlacklist } from '@/lib/sessionUtils';
import { revokeSession } from '@/lib/sessionUtils';

export async function POST() {
  const response = NextResponse.json({ success: true });

  // Best-effort: revoke session id (if you use it)
  try {
    const sessionId = await getSessionId();
    if (sessionId) {
      await revokeSession(sessionId);
    }
  } catch {}

  // Best-effort: blacklist refresh token (rotation / theft mitigation)
  try {
    const refresh = await getRefreshToken();
    if (refresh) {
      await addToBlacklist(refresh, 7 * 24 * 60 * 60);
    }
  } catch {}

  await clearAuthCookies(response);
  return response;
}

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
