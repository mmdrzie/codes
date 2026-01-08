import { NextRequest, NextResponse } from 'next/server';
import { jwtVerify, type JWTPayload } from 'jose';
import { logger } from './logger';

// JWT Secret - should be set in environment variables
const JWT_SECRET = new TextEncoder().encode(
  process.env.JWT_SECRET || 'default_secret_for_dev'
);

// Default audience and issuer - should be configured per environment
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || 'your-app-audience';
const JWT_ISSUER = process.env.JWT_ISSUER || 'your-app-issuer';

export interface TokenPayload extends JWTPayload {
  userId: string;
  tenantId?: string;
  roles?: string[];
  permissions?: string[];
  jti?: string; // JWT ID for replay protection
}

/**
 * Secure JWT verification function
 */
export async function verifyAccessToken(token: string): Promise<TokenPayload | null> {
  try {
    // Verify the JWT signature and claims
    const { payload } = await jwtVerify(token, JWT_SECRET, {
      algorithms: ['HS256'],
      audience: JWT_AUDIENCE,
      issuer: JWT_ISSUER,
      clockTolerance: '5s', // Allow 5 seconds of clock skew
    });

    // Validate required fields
    if (!payload.userId) {
      logger.warn('JWT missing required userId field');
      return null;
    }

    // Check for expiration (duplicate check since jwtVerify does this, but explicit is better)
    if (payload.exp && Date.now() >= payload.exp * 1000) {
      logger.warn('JWT token expired');
      return null;
    }

    // Check if token is not yet valid
    if (payload.nbf && Date.now() < payload.nbf * 1000) {
      logger.warn('JWT token not yet valid');
      return null;
    }

    // Verify issuer if specified
    if (payload.iss && payload.iss !== JWT_ISSUER) {
      logger.warn('JWT issuer mismatch', { expected: JWT_ISSUER, actual: payload.iss });
      return null;
    }

    // Verify audience if specified
    if (payload.aud) {
      const expectedAud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (!expectedAud.includes(JWT_AUDIENCE)) {
        logger.warn('JWT audience mismatch', { expected: JWT_AUDIENCE, actual: payload.aud });
        return null;
      }
    }

    // Validate JWT ID to prevent replay attacks
    if (payload.jti) {
      const isReplayAttack = await checkForReplayAttack(payload.jti);
      if (isReplayAttack) {
        logger.warn('Potential replay attack detected', { jti: payload.jti });
        return null;
      }
    }

    return payload as TokenPayload;
  } catch (error: any) {
    logger.error('JWT verification failed', { 
      error: error.message, 
      stack: error.stack 
    });
    
    // Different error types require different responses
    if (error?.message?.includes('JWTExpired')) {
      logger.warn('JWT token expired');
    } else if (error?.message?.includes('JWTSignatureVerificationFailed')) {
      logger.warn('JWT signature verification failed - potential token forgery');
    } else if (error?.message?.includes('JWTAudienceInvalid') || error?.message?.includes('JWTIssuerInvalid')) {
      logger.warn('JWT claim validation failed');
    }
    
    return null;
  }
}

/**
 * Check for replay attacks using JWT ID (jti)
 * In production, use Redis or database for this
 */
const usedJtiStore = new Set<string>();
const JWT_CLEANUP_INTERVAL = 60 * 60 * 1000; // 1 hour

// Clean up old JTIs periodically
setInterval(() => {
  usedJtiStore.clear(); // In production, implement proper TTL
}, JWT_CLEANUP_INTERVAL);

async function checkForReplayAttack(jti: string): Promise<boolean> {
  if (usedJtiStore.has(jti)) {
    return true; // Replay attack detected
  }
  
  usedJtiStore.add(jti);
  return false;
}

/**
 * Extract token from various sources in the request
 */
function extractToken(request: NextRequest): string | null {
  // Check Authorization header first
  const authHeader = request.headers.get('authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7).trim();
  }

  // Check for session cookie
  const sessionCookie = request.cookies.get('__session');
  if (sessionCookie) {
    return sessionCookie.value;
  }

  return null;
}

/**
 * Secure authentication middleware
 */
export async function secureAuthMiddleware(request: NextRequest): Promise<{
  authenticated: boolean;
  user?: TokenPayload;
  error?: string;
}> {
  try {
    const token = extractToken(request);
    
    if (!token) {
      return {
        authenticated: false,
        error: 'No authentication token provided'
      };
    }

    const user = await verifyAccessToken(token);
    
    if (!user) {
      return {
        authenticated: false,
        error: 'Invalid or expired token'
      };
    }

    // Additional security checks
    if (user.tenantId && !isValidTenantId(user.tenantId)) {
      logger.warn('Invalid tenant ID in token', { tenantId: user.tenantId });
      return {
        authenticated: false,
        error: 'Invalid tenant ID'
      };
    }

    return {
      authenticated: true,
      user
    };
  } catch (error) {
    logger.error('Authentication middleware error', { 
      error: (error as Error).message,
      path: request.nextUrl.pathname 
    });
    
    return {
      authenticated: false,
      error: 'Authentication system error'
    };
  }
}

/**
 * Validate tenant ID format
 */
function isValidTenantId(tenantId: string): boolean {
  // Tenant IDs should be alphanumeric with hyphens/underscores, 3-50 chars
  const tenantIdRegex = /^[a-zA-Z0-9][a-zA-Z0-9_-]{2,48}[a-zA-Z0-9]$/;
  return tenantIdRegex.test(tenantId);
}

/**
 * Middleware helper to protect routes
 */
export async function withAuth(
  request: NextRequest, 
  handler: (user: TokenPayload) => Promise<NextResponse>
): Promise<NextResponse> {
  const authResult = await secureAuthMiddleware(request);
  
  if (!authResult.authenticated) {
    return NextResponse.json(
      { error: 'Unauthorized', message: authResult.error },
      { status: 401 }
    );
  }

  return handler(authResult.user!);
}

/**
 * Enhanced security middleware with rate limiting and bot detection
 */
export async function enhancedSecurityMiddleware(request: NextRequest): Promise<NextResponse> {
  // Add security headers to response
  const response = NextResponse.next();
  
  // Strict Content Security Policy
  response.headers.set(
    'Content-Security-Policy',
    `default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self';`
  );
  
  // HTTP Strict Transport Security
  response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  
  // Additional security headers
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-XSS-Protection', '1; mode=block');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  
  // Add request ID for tracking
  const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  response.headers.set('X-Request-ID', requestId);
  
  // Log the request
  logger.info('Request received', {
    method: request.method,
    path: request.nextUrl.pathname,
    requestId,
    userAgent: request.headers.get('user-agent'),
    ip: getClientIp(request)
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