import { NextRequest, NextResponse } from 'next/server';
import { loginSchema } from '@/lib/validation';
import { verifyPassword } from '@/lib/security';
import { generateTokenPair } from '@/lib/tokenUtils';
import { createSession } from '@/lib/sessionUtils';
import { setAuthCookies } from '@/lib/cookies';
import { checkRateLimit, getIdentifier } from '@/lib/rateLimit';
import { logger, logAuthEvent, logSecurityEvent } from '@/lib/logger';
import { getClientIp, getUserAgent } from '@/lib/helpers';
import { getAdminDb } from '@/lib/firebase';

export async function POST(request: NextRequest) {
  const startTime = Date.now();
  let userEmail: string | undefined;

  try {
    // بررسی Rate Limit
    const identifier = getIdentifier(request);
    const db = getAdminDb();
    const rateLimitResult = checkRateLimit(identifier, 'login');

    if (!rateLimitResult.allowed) {
      logSecurityEvent('rate_limit_exceeded', 'medium', {
        identifier,
        endpoint: '/api/auth/login',
        remainingTime: new Date(rateLimitResult.resetAt).toISOString()
      });

      return NextResponse.json(
        {
          error: rateLimitResult.message,
          resetAt: rateLimitResult.resetAt
        },
        {
          status: 429,
          headers: {
            'X-RateLimit-Limit': '5',
            'X-RateLimit-Remaining': rateLimitResult.remaining.toString(),
            'X-RateLimit-Reset': rateLimitResult.resetAt.toString()
          }
        }
      );
    }

    // دریافت و Validation داده
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

    // جستجوی کاربر در Database
    const user = await db.collection('users').where('email', '==', email).get();

    if (user.empty) {
      // تاخیر برای جلوگیری از Timing Attack
      await new Promise(resolve => setTimeout(resolve, 1000));

      logSecurityEvent('login_failed', 'low', {
        email,
        reason: 'user_not_found',
        ip: getClientIp(request)
      });

      return NextResponse.json(
        { error: 'Invalid email or password' },
        { status: 401 }
      );
    }

    const firstDoc = user.docs[0];
    if (!firstDoc) {
      // This should be unreachable because we checked user.empty above,
      // but keeps TypeScript happy and protects against edge cases.
      return NextResponse.json({ error: 'Invalid email or password' }, { status: 401 });
    }

    const userData = firstDoc.data();
    const userId = firstDoc.id;

    // بررسی وضعیت حساب
    if (userData.status === 'blocked') {
      logSecurityEvent('login_attempt_blocked_user', 'high', {
        userId,
        email,
        ip: getClientIp(request)
      });

      return NextResponse.json(
        { error: 'Account has been blocked. Please contact support.' },
        { status: 403 }
      );
    }

    // تایید Password
    const isPasswordValid = await verifyPassword(password, userData.passwordHash);

    if (!isPasswordValid) {
      // ثبت تلاش ناموفق
      await db.collection('users').doc(userId).update({
        failedLoginAttempts: (userData.failedLoginAttempts || 0) + 1,
        lastFailedLogin: new Date()
      });

      logAuthEvent('login', userId, false, {
        email,
        reason: 'invalid_password'
      });

      // تاخیر برای جلوگیری از Timing Attack
      await new Promise(resolve => setTimeout(resolve, 1000));

      return NextResponse.json(
        { error: 'Invalid email or password' },
        { status: 401 }
      );
    }

    // ریست کردن تلاش‌های ناموفق
    if (userData.failedLoginAttempts > 0) {
      await db.collection('users').doc(userId).update({
        failedLoginAttempts: 0,
        lastFailedLogin: null
      });
    }

    // تولید Token ها
    const tokens = generateTokenPair({
      userId,
      tenantId: userData.tenantId,
      email: userData.email
    });

    // ایجاد Session
    const sessionId = createSession(userId, userData.tenantId, {
      ipAddress: getClientIp(request),
      userAgent: getUserAgent(request)
    });

    // بروزرسانی اطلاعات کاربر
    await db.collection('users').doc(userId).update({
      lastLogin: new Date(),
      lastLoginIp: getClientIp(request)
    });

    // ایجاد Response
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

    // تنظیم Cookie ها
    await setAuthCookies(
      tokens.accessToken,
      tokens.refreshToken,
      sessionId,
      response
    );

    // Log کردن ورود موفق
    logAuthEvent('login', userId, true, {
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

// تنظیمات Route
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';