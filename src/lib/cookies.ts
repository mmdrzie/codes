import type { NextResponse } from 'next/server';
import { cookies } from 'next/headers';

/**
 * Cookie strategy (server + middleware + API routes)
 * - __session: short-lived access token (JWT)
 * - refresh_token: long-lived refresh token (JWT)
 * - session_id: opaque session id (optional, for session tracking / revocation)
 */

export const ACCESS_COOKIE_NAME = '__session';
export const REFRESH_COOKIE_NAME = 'refresh_token';
export const SESSION_ID_COOKIE_NAME = 'session_id';

export const ACCESS_TOKEN_TTL_SECONDS = 15 * 60; // 15m
export const REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60; // 7d

const isProd = process.env.NODE_ENV === 'production';

/**
 * Read cookies in Server Components / Route Handlers
 */
export async function getAccessToken(): Promise<string | undefined> {
  const store = await cookies();
  return store.get(ACCESS_COOKIE_NAME)?.value;
}

export async function getRefreshToken(): Promise<string | undefined> {
  const store = await cookies();
  return store.get(REFRESH_COOKIE_NAME)?.value;
}

export async function getSessionId(): Promise<string | undefined> {
  const store = await cookies();
  return store.get(SESSION_ID_COOKIE_NAME)?.value;
}

/**
 * Set auth cookies on a NextResponse (Route Handlers)
 */
export async function setAuthCookies(
  accessToken: string,
  refreshToken: string,
  sessionId: string | undefined,
  response: NextResponse
) {
  response.cookies.set(ACCESS_COOKIE_NAME, accessToken, {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
    path: '/',
    maxAge: ACCESS_TOKEN_TTL_SECONDS,
  });

  // Keep refresh token scoped to refresh endpoint to reduce CSRF surface
  response.cookies.set(REFRESH_COOKIE_NAME, refreshToken, {
    httpOnly: true,
    secure: isProd,
    sameSite: 'strict',
    path: '/api/auth/refresh',
    maxAge: REFRESH_TOKEN_TTL_SECONDS,
  });

  if (sessionId) {
    response.cookies.set(SESSION_ID_COOKIE_NAME, sessionId, {
      httpOnly: true,
      secure: isProd,
      sameSite: 'lax',
      path: '/',
      maxAge: REFRESH_TOKEN_TTL_SECONDS,
    });
  }
}

export async function clearAuthCookies(response: NextResponse) {
  response.cookies.set(ACCESS_COOKIE_NAME, '', {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
    path: '/',
    maxAge: 0,
  });
  response.cookies.set(REFRESH_COOKIE_NAME, '', {
    httpOnly: true,
    secure: isProd,
    sameSite: 'strict',
    path: '/api/auth/refresh',
    maxAge: 0,
  });
  response.cookies.set(SESSION_ID_COOKIE_NAME, '', {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
    path: '/',
    maxAge: 0,
  });
}
