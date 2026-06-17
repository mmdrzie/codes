import { NextResponse } from 'next/server';
import { clearAuthCookies, getRefreshToken, getSessionId } from '@/lib/cookies';
import { addToBlacklist, revokeSession } from '@/lib/sessionUtils';
import { getEnterpriseRedisClient } from '@/infrastructure/redis/enterprise-redis-client';
import { EnterpriseSessionManager } from '@/core/session/enterprise-session-manager';

// Initialize enterprise components
const redisClient = getEnterpriseRedisClient();
const sessionManager = new EnterpriseSessionManager(redisClient);

export async function POST() {
  const response = NextResponse.json({ success: true });

  try {
    // Get session ID and revoke using enterprise session manager
    const sessionId = await getSessionId();
    if (sessionId) {
      await sessionManager.revokeSession(sessionId);
    }
  } catch (error) {
    console.error('Error revoking session:', error);
  }

  // Blacklist refresh token
  try {
    const refresh = await getRefreshToken();
    if (refresh) {
      await addToBlacklist(refresh, 7 * 24 * 60 * 60);
    }
  } catch (error) {
    console.error('Error blacklisting refresh token:', error);
  }

  // Clear all auth cookies
  await clearAuthCookies(response);
  return response;
}

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
