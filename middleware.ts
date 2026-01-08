import { NextRequest, NextResponse } from 'next/server';
import { authenticateRequest, applyRateLimiting, validateSessionBinding, addSecurityHeaders } from './src/lib/middleware';
import { logger } from './src/lib/logger';

// Public routes that don't require authentication
const PUBLIC_ROUTES = [
  '/',
  '/login',
  '/register',
  '/api/auth/login',
  '/api/auth/register',
  '/api/auth/wallet/nonce',
  '/api/auth/wallet',
  '/api/auth/refresh',
  '/api/auth/sync-firebase',
  '/api/auth/logout',
  '/api/web3/nonce',
  '/api/web3/signin',
  '/api/auth/session'
];

// Public API routes that don't require authentication
const PUBLIC_API_ROUTES = [
  '/api/auth/login',
  '/api/auth/register',
  '/api/auth/wallet/nonce',
  '/api/auth/wallet',
  '/api/auth/refresh',
  '/api/auth/sync-firebase',
  '/api/web3/nonce',
  '/api/web3/signin',
  '/api/auth/session'
];

/**
 * Enhanced security middleware with authentication, rate limiting, and security headers
 */
export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  // Apply rate limiting to all requests
  const rateLimitResponse = await applyRateLimiting(req);
  if (rateLimitResponse) {
    return rateLimitResponse;
  }

  // Check if route is public (no authentication required)
  const isPublicRoute = PUBLIC_ROUTES.some(route => 
    pathname === route || 
    pathname.startsWith(route + '/') ||
    (route.endsWith('/') && pathname.startsWith(route))
  );

  if (!isPublicRoute) {
    // Authenticate protected routes
    const authResult = await authenticateRequest(req);

    if (!authResult.authenticated) {
      logger.warn('Unauthorized access attempt', {
        pathname,
        ip: getClientIp(req),
        userAgent: getUserAgent(req)
      });

      // Return appropriate response based on route type
      if (pathname.startsWith('/api/')) {
        return NextResponse.json(
          { error: 'Unauthorized', message: authResult.error },
          { status: 401 }
        );
      } else {
        // Redirect to login for non-API routes
        return NextResponse.redirect(new URL('/login', req.url));
      }
    }

    // Validate session binding (IP/User-Agent consistency)
    if (authResult.userId) {
      const isBindingValid = await validateSessionBinding(req, authResult.userId);
      if (!isBindingValid) {
        logger.warn('Session binding validation failed', {
          userId: authResult.userId,
          ip: getClientIp(req),
          userAgent: getUserAgent(req)
        });

        // Clear session cookies and redirect
        const response = NextResponse.redirect(new URL('/login', req.url));
        response.cookies.delete('__session');
        response.cookies.delete('refresh_token');
        response.cookies.delete('session_id');
        return response;
      }
    }
  }

  // Create response and add security headers
  const response = NextResponse.next();
  addSecurityHeaders(response);

  // Add request ID for tracking
  const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  response.headers.set('X-Request-ID', requestId);

  // Add user info to headers if authenticated
  const authResult = await authenticateRequest(req);
  if (authResult.authenticated && authResult.userId) {
    response.headers.set('X-User-ID', authResult.userId);
    if (authResult.tenantId) {
      response.headers.set('X-Tenant-ID', authResult.tenantId);
    }
    if (authResult.role) {
      response.headers.set('X-User-Role', authResult.role);
    }
  }

  // Log the request
  logger.info('Request processed', {
    method: req.method,
    path: pathname,
    requestId,
    userId: authResult.authenticated ? authResult.userId : undefined,
    ip: getClientIp(req),
    userAgent: getUserAgent(req)
  });

  return response;
}

// Apply middleware to all routes except static assets
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public/ (public directory files)
     */
    {
      source: '/((?!_next/static|_next/image|favicon.ico|public/|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico|css|js)$).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
};

/**
 * Helper function to extract client IP
 */
function getClientIp(request: NextRequest): string | null {
  const xff = request.headers.get('x-forwarded-for');
  if (xff) return xff.split(',')[0]?.trim() ?? null;
  
  const realIp = request.headers.get('x-real-ip');
  if (realIp) return realIp.trim();
  
  const cf = request.headers.get('cf-connecting-ip');
  if (cf) return cf.trim();
  
  return null;
}

/**
 * Helper function to extract user agent
 */
function getUserAgent(request: NextRequest): string | null {
  return request.headers.get('user-agent');
}