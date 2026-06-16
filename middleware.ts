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
  validateSecretsConfiguration,
  verifyRecaptcha
} from './src/lib/security-middleware';
import { 
  securityEnhancementMiddleware,
  ensureSecurityInitialization 
} from './src/lib/security-enhancements';
import SecureLogger from './src/utils/logger';
import { isPublicRoute, isProtectedRoute } from './src/config/routes';
import { HardenedAuthService } from './src/services/auth/hardened-auth-service';
import crypto from 'crypto';
import { addAdvancedSecurityHeaders, sessionManager } from './src/lib/advanced-security-config';

// Security configuration
const SECURITY_CONFIG = {
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

// High-value routes that require MFA verification
const HIGH_VALUE_ROUTES = [
  '/api/wallet/transfer',
  '/api/withdraw',
  '/api/settings/security',
  '/api/account/delete',
  '/api/auth/change-password',
  '/api/auth/change-email',
  '/api/auth/setup-mfa',
  '/api/auth/disable-mfa'
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
    // Apply comprehensive security enhancements
    const securityResponse = await securityEnhancementMiddleware(req);
    if (securityResponse) {
      return securityResponse;
    }

    // Block requests with suspicious patterns
    if (!validateRequestForSuspiciousPatterns(req)) {
      SecureLogger.warn('Suspicious request blocked', {
        pathname,
        method: req.method,
        ip: getClientIp(req),
        userAgent: req.headers.get('user-agent'),
      });

      return new NextResponse('Request blocked for security reasons', {
        status: 403,
      });
    }

    // Check if route is public (no authentication required)
    const isPublic = isPublicRoute(pathname);

    // Apply rate limiting to public routes
    if (isPublic) {
      const rateLimitResponse = await applyEnhancedRateLimiting(req);
      if (rateLimitResponse) {
        // Rate limit exceeded - check for reCAPTCHA token
        const recaptchaToken = req.headers.get('x-recaptcha-token') || req.nextUrl.searchParams.get('recaptcha');
        
        if (recaptchaToken) {
          // Verify reCAPTCHA token
          const recaptchaResult = await verifyRecaptcha(recaptchaToken, getClientIp(req));
          
          if (recaptchaResult.success) {
            // ReCAPTCHA verified, allow request to proceed
            SecureLogger.info('Rate-limited request allowed via reCAPTCHA verification', {
              pathname,
              ip: getClientIp(req),
              recaptchaScore: recaptchaResult.score,
              recaptchaAction: recaptchaResult.action
            });
          } else {
            // ReCAPTCHA verification failed
            SecureLogger.warn('ReCAPTCHA verification failed for rate-limited request', {
              pathname,
              ip: getClientIp(req),
              error: recaptchaResult.error
            });
            
            return new NextResponse(JSON.stringify({
              error: 'Rate limit exceeded',
              message: 'Security verification failed. Please try again.',
              code: 'RATE_LIMIT_RECAPTCHA_FAILED'
            }), {
              status: 429,
              headers: {
                'Content-Type': 'application/json',
                'Retry-After': '60' // Retry after 60 seconds
              }
            });
          }
        } else {
          // No reCAPTCHA token provided, return challenge
          SecureLogger.warn('Rate limit exceeded for public route, reCAPTCHA challenge required', {
            pathname,
            ip: getClientIp(req),
          });
          
          return new NextResponse(JSON.stringify({
            error: 'Rate limit exceeded',
            message: 'Security verification required',
            code: 'RATE_LIMIT_CHALLENGE_REQUIRED',
            challenge: 'recaptcha_required'
          }), {
            status: 429,
            headers: {
              'Content-Type': 'application/json',
              'Retry-After': '60' // Retry after 60 seconds
            }
          });
        }
      }
    }

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
        SecureLogger.warn('Unauthorized access attempt', {
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

      // Check MFA for high-value routes
      if (isHighValueRoute(pathname)) {
        const mfaVerified = await checkMFAVerification(req, authResult.payload?.userId);
        
        if (!mfaVerified) {
          SecureLogger.warn('MFA required but not verified for high-value route', {
            pathname,
            userId: authResult.payload?.userId,
            ip: getClientIp(req),
          });

          return NextResponse.json(
            { 
              error: 'MFA Required', 
              message: 'Multi-factor authentication is required for this action' 
            },
            { status: 403 }
          );
        }
      }

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
          
          // Use advanced session manager for validation
          const sessionValidation = await sessionManager.validateSession(
            sessionId,
            currentIp,
            currentUserAgent
          );
          
          if (!sessionValidation.isValid) {
            SecureLogger.warn('Session binding validation failed', {
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
    
    // Generate nonce for CSP
    const nonce = crypto.randomBytes(16).toString('base64');
    
    // Add advanced security headers (without CSP - we'll add it separately)
    addAdvancedSecurityHeaders(response);
    
    // Add report-to header for CSP violations
    response.headers.set('Report-To', JSON.stringify({
      group: 'csp-endpoint',
      max_age: 10886400,
      endpoints: [{ url: '/api/csp-report' }]
    }));
    
    // Add Content Security Policy with dynamic nonce
    const isDev = process.env.NODE_ENV === 'development';
    const cspHeader = [
      "default-src 'self'",
      `script-src 'self' 'nonce-${nonce}'`,
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' https:",
      "font-src 'self' https:",
      "connect-src 'self' https: wss:",
      "frame-ancestors 'none'",
      "upgrade-insecure-requests",
      "block-all-mixed-content"
    ].join('; ');
    
    response.headers.set('Content-Security-Policy', cspHeader);
    
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
    SecureLogger.info('Request processed', {
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
      SecureLogger.warn('Slow request detected', {
        pathname: req.nextUrl.pathname,
        method: req.method,
        duration,
        ip: getClientIp(req),
      });
    }

    return response;
  } catch (error) {
    SecureLogger.error('Middleware error', { 
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
    SecureLogger.error('Authentication check failed', { error: (error as Error).message });
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
/** 
 * Check if a route requires MFA verification
 */
function isHighValueRoute(pathname: string): boolean {
  return HIGH_VALUE_ROUTES.some(route => pathname.startsWith(route));
}

/**
 * Check if user has MFA verified for high-value operations
 * SECURITY FIX: Never trust client-controlled headers
 * MFA status MUST be verified server-side via Redis-backed session store
 */
async function checkMFAVerification(request: NextRequest, userId: string | undefined): Promise<boolean> {
  if (!userId) {
    return false;
  }

  try {
    // CRITICAL SECURITY FIX: Never trust x-mfa-verified header from client
    // This was a critical vulnerability allowing MFA bypass

    // Extract session ID from request
    const sessionId = getSessionIdFromRequest(request);
    if (!sessionId) {
      logger.warn('MFA check failed: No session ID found', { userId });
      return false;
    }

    // Import enterprise session manager for server-side MFA verification
    const { getEnterpriseRedisClient } = await import('./src/infrastructure/redis/enterprise-redis-client');
    const { createEnterpriseSessionManager } = await import('./src/core/session/enterprise-session-manager');

    const redisClient = getEnterpriseRedisClient();
    const sessionManager = createEnterpriseSessionManager(redisClient);

    // Verify MFA status through Redis-backed session store
    const mfaVerified = await sessionManager.isMFAVerified(sessionId);

    if (mfaVerified) {
      logger.info('MFA verified via server-side session store', { userId, sessionId });
      return true;
    }

    // Fallback: Check JWT claims for mfa_verified (signed by server, cannot be tampered)
    const authHeader = request.headers.get('Authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const payload = JSON.parse(atob(base64));

        // Only trust mfa_verified if it's in the signed JWT payload
        // This claim can only be set by the server during authentication
        if (payload.mfa_verified === true && payload.sessionId === sessionId) {
          return true;
        }
      } catch (e) {
        // If decoding fails, MFA verification fails
      }
    }

    logger.warn('MFA required but not verified for high-value route', {
      userId,
      sessionId,
    });

    return false;
  } catch (error) {
    logger.error('Error checking MFA verification', { error: (error as Error).message, userId });
    // Fail closed: require MFA on error
    return false;
  }
}
