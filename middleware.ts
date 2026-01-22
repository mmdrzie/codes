import { NextRequest, NextResponse } from 'next/server';
import { authenticateRequest, applyRateLimiting, validateSessionBinding, addSecurityHeaders } from './src/lib/middleware';
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
  
  // Security headers
  SECURITY_HEADERS: {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
  },
  
  // CSP policy
  CSP_POLICY: "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' https://*.firebaseapis.com https://*.googleapis.com; frame-ancestors 'none';",
  
  // CSRF protection
  CSRF_HEADER_NAME: 'X-CSRF-Token',
  
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

  // Apply global rate limiting to all routes
  const rateLimitResponse = await applyRateLimiting(req);
  if (rateLimitResponse) {
    return rateLimitResponse;
  }

  // Block requests with suspicious patterns
  if (hasSuspiciousPattern(req)) {
    logger.warn('Suspicious request blocked', {
      pathname,
      method: req.method,
      ip: getClientIp(req),
      userAgent: req.headers.get('user-agent'),
      suspiciousElements: getSuspiciousElements(req),
    });

    return new NextResponse('Request blocked for security reasons', {
      status: 403,
    });
  }

  // Check if route is public (no authentication required)
  const isPublicRoute = isPublicRoute(pathname);

  // Initialize default auth context (fail closed)
  let authContext: AuthContext = {
    authenticated: false,
    error: 'No authentication provided',
    timestamp: Date.now()
  };

  // Check authentication for protected routes
  if (!isPublicRoute && isProtectedRoute(pathname)) {
    const authResult = await checkAuthentication(req);
    
    if (!authResult.valid) {
      logger.warn('Unauthorized access attempt', {
        pathname,
        ip: getClientIp(req),
        userAgent: getUserAgent(req),
        error: authResult.error
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

    authContext = {
      authenticated: true,
      userId: authResult.payload?.userId,
      tenantId: authResult.payload?.tenantId,
      role: authResult.payload?.role,
      timestamp: Date.now()
    };

    // Validate session binding (IP/User-Agent consistency)
    if (authContext.userId) {
      const isBindingValid = await validateSessionBinding(req, authContext.userId);
      if (!isBindingValid) {
        logger.warn('Session binding validation failed', {
          userId: authContext.userId,
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
  } else if (isPublicRoute(pathname)) {
    // For public routes, set authenticated to true but with no user context
    authContext = {
      authenticated: true,
      timestamp: Date.now()
    };
  }

  // Create response and add security headers
  const response = NextResponse.next();
  
  // Add security headers
  Object.entries(SECURITY_CONFIG.SECURITY_HEADERS).forEach(([header, value]) => {
    response.headers.set(header, value);
  });
  
  // Add CSP header
  response.headers.set('Content-Security-Policy', SECURITY_CONFIG.CSP_POLICY);
  
  // Add HSTS header
  response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  
  // Add cache control for sensitive endpoints
  if (pathname.startsWith('/api/')) {
    response.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  }

  // Add request ID for tracking
  const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
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
    userAgent: getUserAgent(req),
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
}

/**
 * Check if a request has suspicious patterns
 */
function hasSuspiciousPattern(request: NextRequest): boolean {
  const userAgent = request.headers.get('user-agent') || '';
  const url = request.nextUrl.toString();
  const body = ''; // Would need to get from request if needed
  
  // Check for common attack patterns
  const suspiciousPatterns = [
    /union\s+select/i,
    /drop\s+table/i,
    /exec\s*\(/i,
    /<script/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /eval\s*\(/i,
    /document\.cookie/i,
    /alert\s*\(/i,
  ];

  // Check user agent
  if (/sqlmap|nikto|nessus|acunetix|burp|owasp|nmap|masscan|gobuster|dirbuster|arachni|w3af|skipfish|zap/i.test(userAgent)) {
    return true;
  }

  // Check URL and body for patterns
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(url) || pattern.test(body)) {
      return true;
    }
  }

  return false;
}

/**
 * Get suspicious elements from request for logging
 */
function getSuspiciousElements(request: NextRequest): string[] {
  const elements: string[] = [];
  const userAgent = request.headers.get('user-agent') || '';
  const url = request.nextUrl.toString();
  
  if (/sqlmap|nikto|nessus|acunetix|burp|owasp|nmap|masscan|gobuster|dirbuster|arachni|w3af|skipfish|zap/i.test(userAgent)) {
    elements.push('suspicious_user_agent');
  }
  
  // Add other suspicious element checks here
  return elements;
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