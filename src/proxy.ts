import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { verifyAccessTokenEdge } from '@/lib/tokenEdge';
import { logger } from '@/lib/logger';

const PUBLIC_PATHS = [
  '/',
  '/login',
  '/register',
  '/api/auth/login',
  '/api/auth/register',
  '/api/auth/wallet/nonce',
  '/api/auth/wallet',
  '/api/auth/refresh',
  '/api/auth/sync-firebase'
];

const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim()).filter(Boolean)
  : ['http://localhost:3000'];

const SECURITY_HEADERS: Record<string, string> = {
  'X-DNS-Prefetch-Control': 'on',

  ...(process.env.NODE_ENV === 'production'
    ? { 'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload' }
    : {}),

  'X-XSS-Protection': '0',
  'X-Frame-Options': 'SAMEORIGIN',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',

  // ✅ برای popup login بهتره اجازه popup بدیم (به جای شکست خوردن flow)
  // اگر جایی COOP سفت گذاشتی، اینجا هم کمک می‌کنه.
  'Cross-Origin-Opener-Policy': 'same-origin-allow-popups',

  'Content-Security-Policy': [
    "default-src 'self'",

    // scripts needed for Firebase/Google auth
    process.env.NODE_ENV === 'production'
      ? "script-src 'self' https://www.gstatic.com https://apis.google.com https://accounts.google.com"
      : "script-src 'self' 'unsafe-eval' 'unsafe-inline' https://www.gstatic.com https://apis.google.com https://accounts.google.com",

    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "font-src 'self' data:",

    // Firebase/Google endpoints
    "connect-src 'self' https:",

    // ✅ مهم: Firebase uses firebaseapp.com in some auth flows
    "frame-src 'self' https://accounts.google.com https://*.firebaseapp.com",

    "frame-ancestors 'self'",
    "base-uri 'self'",
    "object-src 'none'"
  ].join('; ')
};

function isPublicPath(pathname: string): boolean {
  return PUBLIC_PATHS.some(path => {
    if (path.endsWith('*')) return pathname.startsWith(path.slice(0, -1));
    return pathname === path || pathname.startsWith(path + '/');
  });
}

function getClientIp(request: NextRequest): string | null {
  const xff = request.headers.get('x-forwarded-for');
  if (xff) return xff.split(',')[0]?.trim() ?? null;
  const realIp = request.headers.get('x-real-ip');
  if (realIp) return realIp.trim();
  const cf = request.headers.get('cf-connecting-ip');
  if (cf) return cf.trim();
  return null;
}

function handleCORS(request: NextRequest, response: NextResponse): NextResponse {
  const origin = request.headers.get('origin');
  response.headers.set('Vary', 'Origin');

  if (origin) {
    const isAllowed =
      process.env.NODE_ENV === 'development' || ALLOWED_ORIGINS.includes(origin);

    if (isAllowed) {
      response.headers.set('Access-Control-Allow-Origin', origin);
      response.headers.set('Access-Control-Allow-Credentials', 'true');
    }
  }

  if (request.method === 'OPTIONS') {
    response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token, X-Requested-With');
    response.headers.set('Access-Control-Max-Age', '86400');
  }

  return response;
}

function addSecurityHeaders(response: NextResponse): NextResponse {
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) response.headers.set(k, v);
  return response;
}

function generateRequestId(): string {
  return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

export async function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const requestId = generateRequestId();
  const startTime = Date.now();

  let response = NextResponse.next();
  response.headers.set('X-Request-ID', requestId);

  try {
    response = addSecurityHeaders(response);
    response = handleCORS(request, response);

    if (request.method === 'OPTIONS') {
      return new NextResponse(null, { status: 200, headers: response.headers });
    }

    if (isPublicPath(pathname)) return response;

    const token = request.cookies.get('__session')?.value;

    if (!token) {
      logger.warn('Unauthorized access attempt', { pathname, requestId, ip: getClientIp(request) });

      if (!pathname.startsWith('/api/')) {
        return NextResponse.redirect(new URL('/login', request.url));
      }

      return NextResponse.json({ error: 'Unauthorized' }, { status: 401, headers: response.headers });
    }

    const payload = await verifyAccessTokenEdge(token);

    if (!payload) {
      logger.warn('Invalid token', { pathname, requestId });

      response.cookies.delete('__session');
      response.cookies.delete('refresh_token');
      response.cookies.delete('session_id');

      if (!pathname.startsWith('/api/')) {
        return NextResponse.redirect(new URL('/login', request.url));
      }

      return NextResponse.json({ error: 'Invalid token' }, { status: 401, headers: response.headers });
    }

    response.headers.set('X-User-ID', payload.userId);
    if (payload.tenantId) response.headers.set('X-Tenant-ID', payload.tenantId);

    logger.info('Request processed', {
      method: request.method,
      pathname,
      requestId,
      userId: payload.userId,
      duration: `${Date.now() - startTime}ms`
    });

    return response;
  } catch (error) {
    logger.error('Proxy error', { error, pathname, requestId });
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|public).*)'],
};
