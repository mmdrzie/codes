import { NextRequest, NextResponse } from 'next/server';
import { registerSchema } from '@/lib/validation';
import { hashPassword } from '@/lib/security';
import { generateTokenPair } from '@/lib/tokenUtils';
import { setAuthCookies } from '@/lib/cookies';
import { getEnterpriseRedisClient } from '@/infrastructure/redis/enterprise-redis-client';
import { EnterpriseRateLimiter } from '@/core/ratelimit/enterprise-rate-limiter';
import { EnterpriseSessionManager } from '@/core/session/enterprise-session-manager';
import { getClientIp, getUserAgent } from '@/lib/helpers';
import { getAdminDb } from '@/lib/firebase';

// Initialize enterprise components
const redisClient = getEnterpriseRedisClient();
const rateLimiter = new EnterpriseRateLimiter(redisClient);
const sessionManager = new EnterpriseSessionManager(redisClient);

export async function POST(request: NextRequest) {
  try {
    // CRITICAL: Apply rate limiting FIRST - FAILS CLOSED
    const identifier = getClientIp(request) || 'unknown';
    const rateLimitResult = await rateLimiter.checkRateLimit(
      `register:${identifier}`,
      'auth:register'
    );

    if (!rateLimitResult.allowed) {
      return NextResponse.json(
        { 
          error: 'Too many registration attempts. Please try again later.',
          resetAt: rateLimitResult.resetAt 
        },
        { 
          status: 429,
          headers: {
            'Retry-After': Math.ceil((rateLimitResult.resetAt - Date.now()) / 1000).toString()
          }
        }
      );
    }

    // Parse and validate request body
    const body = await request.json();
    const validation = registerSchema.safeParse(body);

    if (!validation.success) {
      return NextResponse.json(
        {
          error: 'Invalid input',
          details: validation.error.issues.map((e) => ({ field: e.path.join('.'), message: e.message })),
        },
        { status: 400 }
      );
    }

    const { email, password } = validation.data;
    const db = getAdminDb();

    // Check for existing user
    const existing = await db.collection('users').where('email', '==', email).limit(1).get();
    if (!existing.empty) {
      return NextResponse.json({ error: 'Unable to create account' }, { status: 400 });
    }

    // Hash password
    const passwordHash = await hashPassword(password);

    // Create user document
    const userDoc = {
      email,
      passwordHash,
      status: 'active',
      authMethod: 'password',
      createdAt: new Date(),
      updatedAt: new Date(),
      lastLogin: new Date(),
      lastLoginIp: getClientIp(request),
      failedLoginAttempts: 0,
    };

    const ref = await db.collection('users').add(userDoc);
    const userId = ref.id;

    // Generate tokens
    const tokens = generateTokenPair({
      userId,
      tenantId: undefined,
      email,
      authMethod: 'password',
      role: 'user',
    });

    // Create session using enterprise session manager
    const sessionId = await sessionManager.createSession({
      userId,
      tenantId: 'default',
      deviceFingerprint: getUserAgent(request) || 'unknown',
      ipAddress: getClientIp(request) || 'unknown',
      userAgent: getUserAgent(request) || 'unknown',
      authMethod: 'password',
      roles: ['user'],
      permissions: []
    }).then(s => s.sessionId);

    // Create response
    const response = NextResponse.json(
      {
        success: true,
        user: { id: userId, email },
        expiresIn: tokens.expiresIn,
      },
      { status: 201 }
    );

    // Set cookies
    await setAuthCookies(tokens.accessToken, tokens.refreshToken, sessionId, response);
    return response;
  } catch (error) {
    console.error('Registration error:', error);
    return NextResponse.json({ error: 'An error occurred during registration' }, { status: 500 });
  }
}

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
