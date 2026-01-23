import { NextRequest, NextResponse } from 'next/server';
import { SessionBindingValidator } from './auth/session-binding';
import { logger } from './logger';

export async function sessionValidationMiddleware(
  request: NextRequest
): Promise<NextResponse> {
  try {
    // Create session validator instance
    const validator = new SessionBindingValidator();

    // Extract session information from request
    const sessionId = extractSessionId(request);
    const userId = extractUserId(request);
    const currentIp = getClientIp(request);
    const userAgent = request.headers.get('user-agent');

    if (!sessionId) {
      logger.warn('Session validation failed: No session ID found', {
        url: request.url,
        method: request.method,
        ip: currentIp,
        userAgent
      });

      return new NextResponse(
        JSON.stringify({ error: 'Session validation failed: No session ID found' }),
        { status: 401, headers: { 'Content-Type': 'application/json' } }
      );
    }

    if (!userId) {
      logger.warn('Session validation failed: No user ID found', {
        url: request.url,
        method: request.method,
        sessionId,
        ip: currentIp,
        userAgent
      });

      return new NextResponse(
        JSON.stringify({ error: 'Session validation failed: No user ID found' }),
        { status: 401, headers: { 'Content-Type': 'application/json' } }
      );
    }

    if (!currentIp) {
      logger.warn('Session validation failed: No IP address found', {
        url: request.url,
        method: request.method,
        sessionId,
        userId,
        userAgent
      });

      return new NextResponse(
        JSON.stringify({ error: 'Session validation failed: No IP address found' }),
        { status: 401, headers: { 'Content-Type': 'application/json' } }
      );
    }

    if (!userAgent) {
      logger.warn('Session validation failed: No User-Agent found', {
        url: request.url,
        method: request.method,
        sessionId,
        userId,
        ip: currentIp
      });

      return new NextResponse(
        JSON.stringify({ error: 'Session validation failed: No User-Agent found' }),
        { status: 401, headers: { 'Content-Type': 'application/json' } }
      );
    }

    // Validate session binding
    const validationResult = await validator.validateSessionBinding(
      sessionId,
      userId,
      currentIp,
      userAgent
    );

    if (!validationResult.isValid) {
      logger.warn('Session binding validation failed', {
        url: request.url,
        method: request.method,
        sessionId,
        userId,
        ip: currentIp,
        userAgent,
        reason: validationResult.reason
      });

      // Return 401 Unauthorized for binding violations
      return new NextResponse(
        JSON.stringify({
          error: 'Session validation failed',
          reason: validationResult.reason
        }),
        { status: 401, headers: { 'Content-Type': 'application/json' } }
      );
    }

    // Session is valid, continue with request
    // Add validated session info to request headers for downstream processing
    const response = NextResponse.next();
    response.headers.set('x-session-valid', 'true');
    response.headers.set('x-user-id', userId);
    response.headers.set('x-session-id', sessionId);

    return response;
  } catch (error) {
    logger.error('Session validation middleware error', {
      error: (error as Error).message,
      url: request.url,
      method: request.method
    });

    // On validation error, block the request (fail-closed)
    return new NextResponse(
      JSON.stringify({ error: 'Session validation error' }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}

/**
 * Extract session ID from request
 */
function extractSessionId(request: NextRequest): string | null {
  // Check authorization header first
  const authHeader = request.headers.get('authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    // Extract from JWT token if needed
    const token = authHeader.substring(7);
    try {
      // Decode JWT to extract session ID (simplified)
      const parts = token.split('.');
      if (parts.length === 3) {
        const payload = JSON.parse(atob(parts[1]));
        return payload.sessionId || payload.jti || null;
      }
    } catch (e) {
      // If JWT decoding fails, fall back to other methods
    }
  }

  // Check session cookie
  const sessionCookie = request.cookies.get('__session')?.value;
  if (sessionCookie) {
    return sessionCookie;
  }

  // Check custom header
  const sessionIdHeader = request.headers.get('x-session-id');
  if (sessionIdHeader) {
    return sessionIdHeader;
  }

  return null;
}

/**
 * Extract user ID from request
 */
function extractUserId(request: NextRequest): string | null {
  // Check authorization header for JWT payload
  const authHeader = request.headers.get('authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    try {
      const parts = token.split('.');
      if (parts.length === 3) {
        const payload = JSON.parse(atob(parts[1]));
        return payload.userId || payload.sub || null;
      }
    } catch (e) {
      // If JWT decoding fails, fall back to other methods
    }
  }

  // Check custom header
  const userIdHeader = request.headers.get('x-user-id');
  if (userIdHeader) {
    return userIdHeader;
  }

  return null;
}

/**
 * Extract client IP from request headers
 */
function getClientIp(request: NextRequest): string | null {
  // Check multiple headers that could contain the client IP
  const forwardedFor = request.headers.get('x-forwarded-for');
  if (forwardedFor) {
    // X-Forwarded-For can contain multiple IPs, take the first one
    return forwardedFor.split(',')[0].trim();
  }

  const realIp = request.headers.get('x-real-ip');
  if (realIp) {
    return realIp.trim();
  }

  const cfConnectingIp = request.headers.get('cf-connecting-ip');
  if (cfConnectingIp) {
    return cfConnectingIp.trim();
  }

  const trueClientIp = request.headers.get('true-client-ip');
  if (trueClientIp) {
    return trueClientIp.trim();
  }

  const xClusterClientIp = request.headers.get('x-cluster-client-ip');
  if (xClusterClientIp) {
    return xClusterClientIp.trim();
  }

  // If none of the headers are present, return null
  return null;
}

/**
 * Utility function to wrap middleware around route handlers
 */
export function withSessionValidation(
  handler: (request: NextRequest) => Promise<NextResponse>
): (request: NextRequest) => Promise<NextResponse> {
  return async (request: NextRequest) => {
    // Only validate for protected routes
    const protectedPaths = ['/api/', '/dashboard/', '/profile/', '/admin/'];
    const isProtected = protectedPaths.some(path => 
      request.nextUrl.pathname.startsWith(path)
    );

    if (!isProtected) {
      // For non-protected routes, just call the handler
      return handler(request);
    }

    // Validate session for protected routes
    const validationResponse = await sessionValidationMiddleware(request);
    
    // If validation passes (returns NextResponse.next()), continue with handler
    if (validationResponse.headers.get('x-session-valid') === 'true') {
      return handler(request);
    }

    // If validation fails, return the validation response
    return validationResponse;
  };
}

/**
 * Performance metrics for session validation
 */
export class SessionValidationMetrics {
  private static validationTimes: number[] = [];
  private static failureCount = 0;
  private static successCount = 0;

  static recordValidationTime(duration: number): void {
    this.validationTimes.push(duration);
    
    // Keep only the last 1000 measurements to prevent memory issues
    if (this.validationTimes.length > 1000) {
      this.validationTimes = this.validationTimes.slice(-1000);
    }
  }

  static recordFailure(): void {
    this.failureCount++;
  }

  static recordSuccess(): void {
    this.successCount++;
  }

  static getAverageValidationTime(): number {
    if (this.validationTimes.length === 0) {
      return 0;
    }
    
    const sum = this.validationTimes.reduce((acc, time) => acc + time, 0);
    return sum / this.validationTimes.length;
  }

  static getValidationRate(): number {
    const total = this.successCount + this.failureCount;
    return total > 0 ? this.successCount / total : 0;
  }

  static getMetrics(): {
    averageValidationTime: number;
    validationRate: number;
    totalValidations: number;
    failureCount: number;
    successCount: number;
  } {
    return {
      averageValidationTime: this.getAverageValidationTime(),
      validationRate: this.getValidationRate(),
      totalValidations: this.successCount + this.failureCount,
      failureCount: this.failureCount,
      successCount: this.successCount
    };
  }
}