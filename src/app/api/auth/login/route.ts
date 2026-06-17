import { NextRequest, NextResponse } from 'next/server';
import { loginSchema } from '@/lib/validation';
import { verifyPassword } from '@/lib/security';
import { generateTokenPair } from '@/lib/tokenUtils';
import { setAuthCookies } from '@/lib/cookies';
import { getEnterpriseRedisClient } from '@/infrastructure/redis/enterprise-redis-client';
import { EnterpriseRateLimiter } from '@/core/ratelimit/enterprise-rate-limiter';
import { EnterpriseSessionManager } from '@/core/session/enterprise-session-manager';
import { logger } from '@/lib/logger';
import { getClientIp, getUserAgent } from '@/lib/helpers';
import { getAdminDb } from '@/lib/firebase';

// Initialize enterprise components
const redisClient = getEnterpriseRedisClient();
const rateLimiter = new EnterpriseRateLimiter(redisClient);
const sessionManager = new EnterpriseSessionManager(redisClient);

export async function POST(request: NextRequest) {
  const startTime = Date.now();
  let userEmail: string | undefined;

  try {
    // CRITICAL: Apply rate limiting FIRST - FAILS CLOSED
    const identifier = getClientIp(request) || 'unknown';
    const rateLimitResult = await rateLimiter.checkRateLimit(
      `login:${identifier}`,
      'auth:login'
    );

    if (!rateLimitResult.allowed) {
      logger.warn('Login rate limit exceeded', {
        identifier,
        resetAt: new Date(rateLimitResult.resetAt).toISOString()
      });

      return NextResponse.json(
        {
          error: 'Too many login attempts. Please try again later.',
          resetAt: rateLimitResult.resetAt
        },
        {
          status: 429,
          headers: {
            'X-RateLimit-Limit': rateLimitResult.policy?.maxRequests.toString() || '5',
            'X-RateLimit-Remaining': rateLimitResult.remaining.toString(),
            'X-RateLimit-Reset': new Date(rateLimitResult.resetAt).toISOString(),
            'Retry-After': Math.ceil((rateLimitResult.resetAt - Date.now()) / 1000).toString()
          }
        }
      );
    }

    // Parse and validate request body
    const body = await request.json();
    const validation = loginSchema.safeParse(body);

    if (!validation.success) {
      return NextResponse.json(
        {
          error: 'Invalid input',
          details: validation.error.issues.map((e) => ({
            field: e.path.join('.'),
            message: e.message
          }))
        },
        { status: 400 }
      );
    }

    const { email, password } = validation.data;
    userEmail = email;

    // Look up user in database
    const db = getAdminDb();
    const user = await db.collection('users').where('email', '==', email).get();

    if (user.empty) {
      // Delay to prevent timing attack
      await new Promise(resolve => setTimeout(resolve, 1000));

      logger.warn('Login failed - user not found', {
        email,
        ip: getClientIp(request)
      });

      return NextResponse.json(
        { error: 'Invalid email or password' },
        { status: 401 }
      );
    }

    const firstDoc = user.docs[0];
    if (!firstDoc) {
      return NextResponse.json({ error: 'Invalid email or password' }, { status: 401 });
    }

    const userData = firstDoc.data();
    const userId = firstDoc.id;

    // Check account status
    if (userData.status === 'blocked') {
      logger.warn('Login attempt on blocked account', {
        userId,
        email,
        ip: getClientIp(request)
      });

      return NextResponse.json(
        { error: 'Account has been blocked. Please contact support.' },
        { status: 403 }
      );
    }

    // Verify password
    const isPasswordValid = await verifyPassword(password, userData.passwordHash);

    if (!isPasswordValid) {
      // Increment failed login attempts
      await db.collection('users').doc(userId).update({
        failedLoginAttempts: (userData.failedLoginAttempts || 0) + 1,
        lastFailedLogin: new Date()
      });

      logger.warn('Login failed - invalid password', {
        email,
        userId
      });

      // Delay to prevent timing attack
      await new Promise(resolve => setTimeout(resolve, 1000));

      return NextResponse.json(
        { error: 'Invalid email or password' },
        { status: 401 }
      );
    }

    // Reset failed login attempts
    if (userData.failedLoginAttempts > 0) {
      await db.collection('users').doc(userId).update({
        failedLoginAttempts: 0,
        lastFailedLogin: null
      });
    }

    // Generate tokens
    const tokens = generateTokenPair({
      userId,
      tenantId: userData.tenantId,
      email: userData.email
    });

    // Create session using enterprise session manager
    const sessionId = await sessionManager.createSession({
      userId,
      tenantId: userData.tenantId || 'default',
      deviceFingerprint: getUserAgent(request) || 'unknown',
      ipAddress: getClientIp(request) || 'unknown',
      userAgent: getUserAgent(request) || 'unknown',
      authMethod: 'password',
      roles: ['user'],
      permissions: []
    }).then(s => s.sessionId);

    // Update user info
    await db.collection('users').doc(userId).update({
      lastLogin: new Date(),
      lastLoginIp: getClientIp(request)
    });

    // Create response
    const response = NextResponse.json(
      {
        success: true,
        user: {
          id: userId,
          email: userData.email,
          name: userData.name,
          tenantId: userData.tenantId
        },
        expiresIn: tokens.expiresIn
      },
      { status: 200 }
    );

    // Set cookies
    await setAuthCookies(
      tokens.accessToken,
      tokens.refreshToken,
      sessionId,
      response
    );

    // Log successful login
    logger.info('Login successful', {
      userId,
      email,
      sessionId,
      duration: `${Date.now() - startTime}ms`
    });

    return response;

  } catch (error) {
    logger.error('Login error', {
      error,
      email: userEmail,
      duration: `${Date.now() - startTime}ms`
    });

    return NextResponse.json(
      { error: 'An error occurred during login' },
      { status: 500 }
    );
  }
}

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
