import { NextRequest, NextResponse } from 'next/server';
import { 
  getClientIp, 
  generateCspNonce, 
  createCspHeader, 
  validateSessionBinding, 
  applyEnhancedRateLimiting, 
  validateRequestForSuspiciousPatterns, 
  addSecurityHeaders,
  sanitizeErrorMessage,
  validateCryptoRequirements,
  validateSecretsConfiguration
} from './src/lib/security-middleware';
import { logger } from './src/lib/logger';
import { isPublicRoute, isProtectedRoute } from './src/config/routes';
import { HardenedAuthService } from './src/services/auth/hardened-auth-service';
import crypto from 'crypto';

// Security configuration
const SECURITY_CONFIG = {
  // Rate limiting
  GLOBAL_RATE_LIMIT: 100,
  
  // Request size limits
  MAX_REQUEST_SIZE: '1mb',
  
  // Trusted origins
  TRUSTED_ORIGINS: process.env.TRUSTED_ORIGINS?.split(',') || ['localhost', '127.0.0.1'],
};

// List of protected API routes that require authentication
const PROTECTED_ROUTES = [
  '/api/auth/session',
  '/api/user/profile',
  '/api/dashboard',
  '/api/settings',
];

// List of public API routes that don't require authentication
const PUBLIC_API_ROUTES = [
  '/api/auth/login',
  '/api/auth/register',
  '/api/auth/wallet',
  '/api/auth/wallet/hardened',
  '/api/auth/refresh',
  '/api/health',
];

/**
 * Auth Context interface for verified authentication state
 */
export interface AuthContext {
  authenticated: boolean;
  userId?: string;
  tenantId?: string;
  role?: string;
  error?: string;
  timestamp: number;
}

/**
 * Enhanced security middleware with authentication, rate limiting, and security headers
 */
export async function middleware(req: NextRequest) {
  const startTime = Date.now();
  const { pathname } = req.nextUrl;

  try {
    // Validate cryptographic requirements (fail closed if not met)
    validateCryptoRequirements();
    
    // Validate secrets configuration (fail closed if not met)
    validateSecretsConfiguration();

    // Block requests with suspicious patterns
    if (!validateRequestForSuspiciousPatterns(req)) {
      logger.warn('Suspicious request blocked', {
        pathname,
        method: req.method,
        ip: getClientIp(req),
        userAgent: req.headers.get('user-agent'),
      });

      return new NextResponse('Request blocked for security reasons', {
        status: 403,
      });
    }

    // Apply enhanced rate limiting
    const rateLimitResponse = await applyEnhancedRateLimiting(req);
    if (rateLimitResponse) {
      return rateLimitResponse;
    }

    // Check if route is public (no authentication required)
    const isPublic = isPublicRoute(pathname);

    // Initialize default auth context (fail closed)
    let authContext: AuthContext = {
      authenticated: false,
      error: 'No authentication provided',
      timestamp: Date.now()
    };

    // Check authentication for protected routes
    if (!isPublic && isProtectedRoute(pathname)) {
      const authResult = await checkAuthentication(req);
      
      if (!authResult.valid) {
        logger.warn('Unauthorized access attempt', {
          pathname,
          ip: getClientIp(req),
          userAgent: req.headers.get('user-agent'),
          error: authResult.error
        });

        // Return appropriate response based on route type
        if (pathname.startsWith('/api/')) {
          return NextResponse.json(
            { error: 'Unauthorized', message: sanitizeErrorMessage(authResult.error) },
            { status: 401 }
          );
        } else {
          // Redirect to login for non-API routes
          return NextResponse.redirect(new URL('/login', req.url));
        }
      }

      authContext = {
        authenticated: true,
        userId: authResult.payload?.userId,
        tenantId: authResult.payload?.tenantId,
        role: authResult.payload?.role,
        timestamp: Date.now()
      };

      // Apply account-specific rate limiting after authentication
      if (authContext.userId) {
        const accountRateLimitResponse = await applyEnhancedRateLimiting(req, authContext.userId);
        if (accountRateLimitResponse) {
          return accountRateLimitResponse;
        }
      }

      // Validate session binding (IP/User-Agent consistency) - ENFORCE strict validation
      if (authContext.userId) {
        // Extract session ID from request cookies or headers
        const sessionId = getSessionIdFromRequest(req);
        if (sessionId) {
          const currentIp = getClientIp(req);
          const currentUserAgent = req.headers.get('user-agent') || 'unknown';
          
          const isBindingValid = await validateSessionBinding(
            sessionId,
            currentIp,
            currentUserAgent
          );
          
          if (!isBindingValid) {
            logger.warn('Session binding validation failed', {
              userId: authContext.userId,
              ip: currentIp,
              userAgent: currentUserAgent,
              sessionId
            });

            // Clear session cookies and deny access
            const response = NextResponse.json(
              { error: 'Session validation failed', message: 'Invalid session binding' },
              { status: 401 }
            );
            response.cookies.delete('__session');
            response.cookies.delete('refresh_token');
            response.cookies.delete('session_id');
            return response;
          }
        }
      }
    } else if (isPublic) {
      // For public routes, set authenticated to true but with no user context
      authContext = {
        authenticated: true,
        timestamp: Date.now()
      };
    }

    // Create response and add security headers
    const response = NextResponse.next();
    
    // Add security headers with dynamic CSP nonce
    addSecurityHeaders(response);
    
    // Add request ID for tracking
    const requestId = `req_${Date.now()}_${crypto.randomUUID()}`;
    response.headers.set('X-Request-ID', requestId);

    // Add verified auth context to headers if authenticated
    if (authContext.authenticated && authContext.userId) {
      response.headers.set('X-User-ID', authContext.userId);
      if (authContext.tenantId) {
        response.headers.set('X-Tenant-ID', authContext.tenantId);
      }
      if (authContext.role) {
        response.headers.set('X-User-Role', authContext.role);
      }
    }

    // Log the request
    logger.info('Request processed', {
      method: req.method,
      path: pathname,
      requestId,
      userId: authContext.authenticated ? authContext.userId : undefined,
      ip: getClientIp(req),
      userAgent: req.headers.get('user-agent'),
      duration: Date.now() - startTime
    });

    // Log performance metrics
    const duration = Date.now() - startTime;
    if (duration > 1000) { // Log slow requests
      logger.warn('Slow request detected', {
        pathname: req.nextUrl.pathname,
        method: req.method,
        duration,
        ip: getClientIp(req),
      });
    }

    return response;
  } catch (error) {
    logger.error('Middleware error', { 
      error: (error as Error).message, 
      pathname,
      ip: getClientIp(req),
      userAgent: req.headers.get('user-agent')
    });
    
    // In production, don't reveal internal error details
    return NextResponse.json(
      { error: 'Internal server error', message: sanitizeErrorMessage(error) },
      { status: 500 }
    );
  }
}

/**
 * Check authentication for protected routes
 */
async function checkAuthentication(request: NextRequest): Promise<{ valid: boolean; payload?: any; error?: string }> {
  try {
    // Extract token from Authorization header
    const authHeader = request.headers.get('Authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7); // Remove 'Bearer ' prefix
      
      // Verify token using hardened auth service
      const verificationResult = await HardenedAuthService.verifyJWT(token);
      
      if (verificationResult.valid && verificationResult.payload) {
        return { valid: true, payload: verificationResult.payload };
      }
      
      return { valid: false, error: verificationResult.error || 'Invalid token' };
    }
    
    // For non-API routes, fall back to existing authentication
    const authResult = await authenticateRequest(request);
    if (authResult.authenticated) {
      return { 
        valid: true, 
        payload: { 
          userId: authResult.userId, 
          tenantId: authResult.tenantId, 
          role: authResult.role 
        } 
      };
    }
    
    return { valid: false, error: authResult.error || 'Authentication failed' };
  } catch (error) {
    logger.error('Authentication check failed', { error: (error as Error).message });
    return { valid: false, error: 'Authentication check failed' };
  }
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
      source: '/((?!_next/static|_next/image|favicon.ico|public/|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico|css|js)$|api/health).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
};

/**
 * Helper function to extract session ID from request
 */
function getSessionIdFromRequest(request: NextRequest): string | null {
  // Try to get session ID from cookies
  const sessionIdFromCookie = request.cookies.get('session_id')?.value;
  if (sessionIdFromCookie) {
    return sessionIdFromCookie;
  }
  
  // Try to get session ID from authorization header (if stored in JWT payload)
  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    try {
      // Decode JWT to extract session ID if present
      const base64Url = token.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      const payload = JSON.parse(atob(base64));
      if (payload.sessionId) {
        return payload.sessionId;
      }
    } catch (e) {
      // If decoding fails, continue with other methods
    }
  }
  
  // Try to get session ID from custom header
  const sessionIdFromHeader = request.headers.get('X-Session-ID');
  if (sessionIdFromHeader) {
    return sessionIdFromHeader;
  }
  
  return null;
}

/**
 * Authenticate request using the existing implementation
 */
async function authenticateRequest(request: NextRequest) {
  // This is a placeholder that should use the existing authentication logic
  // from the original middleware
  return {
    authenticated: false,
    error: 'Authentication not implemented'
  };
}