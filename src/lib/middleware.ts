import { NextRequest, NextResponse } from 'next/server';
import { verifyAccessToken } from './tokenUtils';
import { verifySessionCookie } from './sessionUtils';
import { logger } from './logger';
import { checkRateLimit, getIdentifier } from './rateLimit';

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
  '/api/web3/signin'
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
  '/api/web3/signin'
];

/**
 * Global authentication middleware
 */
export async function authenticateRequest(request: NextRequest): Promise<{
  authenticated: boolean;
  userId?: string;
  tenantId?: string;
  role?: string;
  error?: string;
}> {
  const { pathname } = request.nextUrl;

  // Allow public routes without authentication
  if (PUBLIC_ROUTES.some(route => 
    pathname === route || 
    pathname.startsWith(route + '/') ||
    (route.endsWith('/') && pathname.startsWith(route))
  )) {
    return { authenticated: true }; // Public routes are considered authenticated for this check
  }

  // Extract token from various sources
  let token: string | undefined;
  
  // Check Authorization header
  const authHeader = request.headers.get('authorization');
  if (authHeader?.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  }
  
  // Check session cookie if no Bearer token
  if (!token) {
    token = request.cookies.get('__session')?.value;
  }

  if (!token) {
    return { authenticated: false, error: 'No authentication token provided' };
  }

  try {
    // First try to verify as access token
    let payload = verifyAccessToken(token);
    
    if (!payload) {
      // If access token invalid, try session cookie verification
      const sessionUser = await verifySessionCookie(token);
      if (!sessionUser) {
        return { authenticated: false, error: 'Invalid or expired token' };
      }
      
      // Map session user to standard payload
      payload = {
        userId: sessionUser.uid || sessionUser.address || '',
        tenantId: sessionUser.tenantId,
        role: sessionUser.role || 'user',
        exp: sessionUser.exp,
        iat: sessionUser.iat
      };
    }

    // Validate required fields
    if (!payload.userId) {
      return { authenticated: false, error: 'Token missing user ID' };
    }

    // Check for token expiration (duplicate check but explicit)
    if (payload.exp && Date.now() >= payload.exp * 1000) {
      return { authenticated: false, error: 'Token expired' };
    }

    return {
      authenticated: true,
      userId: payload.userId,
      tenantId: payload.tenantId,
      role: payload.role || 'user'
    };
  } catch (error) {
    logger.error('Authentication error', { 
      error: (error as Error).message, 
      pathname,
      userId: token ? 'unknown' : undefined 
    });
    return { authenticated: false, error: 'Authentication failed' };
  }
}

/**
 * Enhanced rate limiting middleware
 */
export async function applyRateLimiting(request: NextRequest, userId?: string) {
  const identifier = getIdentifier(request, userId);
  const endpoint = request.nextUrl.pathname;
  
  // Determine rate limit type based on endpoint
  let rateLimitType: 'login' | 'register' | 'walletAuth' | 'api' | 'passwordReset' = 'api';
  
  if (endpoint.includes('/api/auth/login')) {
    rateLimitType = 'login';
  } else if (endpoint.includes('/api/auth/register')) {
    rateLimitType = 'register';
  } else if (endpoint.includes('/api/auth/wallet') || endpoint.includes('/api/web3')) {
    rateLimitType = 'walletAuth';
  } else if (endpoint.includes('/api/auth/password-reset')) {
    rateLimitType = 'passwordReset';
  }

  const rateLimitResult = checkRateLimit(identifier, rateLimitType);

  if (!rateLimitResult.allowed) {
    return NextResponse.json(
      {
        error: rateLimitResult.message,
        resetAt: rateLimitResult.resetAt,
        retryAfter: Math.ceil((rateLimitResult.resetAt - Date.now()) / 1000)
      },
      {
        status: 429,
        headers: {
          'X-RateLimit-Limit': '100',
          'X-RateLimit-Remaining': rateLimitResult.remaining.toString(),
          'X-RateLimit-Reset': rateLimitResult.resetAt.toString(),
          'Retry-After': Math.ceil((rateLimitResult.resetAt - Date.now()) / 1000).toString()
        }
      }
    );
  }

  return null; // Rate limit passed
}

/**
 * Session binding validation (IP and User-Agent consistency)
 */
export async function validateSessionBinding(request: NextRequest, userId: string) {
  try {
    const currentIp = getClientIp(request);
    const currentUserAgent = getUserAgent(request);
    
    // In a real implementation, you would check these values against stored session data
    // For now, we'll just log for monitoring
    
    logger.info('Session binding validation', {
      userId,
      currentIp,
      currentUserAgent,
      timestamp: new Date().toISOString()
    });

    // This would normally check against stored session data
    // Return true if binding is valid, false otherwise
    return true;
  } catch (error) {
    logger.error('Session binding validation error', { 
      error: (error as Error).message, 
      userId 
    });
    return false;
  }
}

/**
 * Security headers middleware
 */
export function addSecurityHeaders(response: NextResponse): NextResponse {
  const securityHeaders: Record<string, string> = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Content-Security-Policy': [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "font-src 'self' https:",
      "connect-src 'self' https:",
      "frame-ancestors 'none'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'"
    ].join('; ')
  };

  if (process.env.NODE_ENV === 'production') {
    securityHeaders['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload';
  }

  Object.entries(securityHeaders).forEach(([key, value]) => {
    response.headers.set(key, value);
  });

  return response;
}

/**
 * Extract client IP from request headers
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
 * Extract user agent from request headers
 */
function getUserAgent(request: NextRequest): string | null {
  return request.headers.get('user-agent');
}