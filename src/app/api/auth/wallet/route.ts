import { NextRequest, NextResponse } from 'next/server';
import { ethers } from 'ethers';
import { walletAuthSchema } from '@/lib/validation';
import { verifyAndConsumeNonce } from '@/lib/nonceStore';
import { validateWalletAddress } from '@/lib/security';
import { generateTokenPair } from '@/lib/tokenUtils';
import { createSession } from '@/lib/sessionUtils';
import { setAuthCookies } from '@/lib/cookies';
import { checkRateLimit, getIdentifier } from '@/lib/rateLimit';
import { logger, logAuthEvent, logSecurityEvent } from '@/lib/logger';
import { getClientIp, getUserAgent } from '@/lib/helpers';
import { getAdminDb } from '@/lib/firebase';

/**
 * تایید Signature با ethers.js
 */
async function verifySignature(
  address: string,
  message: string,
  signature: string
): Promise<boolean> {
  try {
    // بازیابی آدرس از Signature
    const recoveredAddress = ethers.verifyMessage(message, signature);

    // مقایسه آدرس‌ها (case-insensitive)
    return recoveredAddress.toLowerCase() === address.toLowerCase();
  } catch (error) {
    logger.error('Signature verification failed', { error, address });
    return false;
  }
}

export async function POST(request: NextRequest) {
  const startTime = Date.now();
  let walletAddress: string | undefined;

  try {
    // بررسی Rate Limit
    const identifier = getIdentifier(request);
    const db = getAdminDb();
    const rateLimitResult = checkRateLimit(identifier, 'walletAuth');

    if (!rateLimitResult.allowed) {
      logSecurityEvent('rate_limit_exceeded', 'medium', {
        identifier,
        endpoint: '/api/auth/wallet'
      });

      return NextResponse.json(
        {
          error: rateLimitResult.message,
          resetAt: rateLimitResult.resetAt
        },
        {
          status: 429,
          headers: {
            'X-RateLimit-Limit': '10',
            'X-RateLimit-Remaining': rateLimitResult.remaining.toString(),
            'X-RateLimit-Reset': rateLimitResult.resetAt.toString()
          }
        }
      );
    }

    // دریافت و Validation داده
    const body = await request.json();
    const validation = walletAuthSchema.safeParse(body);

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

    const { address, signature, nonce } = validation.data;
    walletAddress = address;

    // Validation اضافی آدرس
    if (!validateWalletAddress(address)) {
      logSecurityEvent('invalid_wallet_address_auth', 'medium', {
        address,
        ip: getClientIp(request)
      });

      return NextResponse.json(
        { error: 'Invalid wallet address format' },
        { status: 400 }
      );
    }

    // تایید Nonce
    const nonceOk = await verifyAndConsumeNonce(address, nonce);

    if (!nonceOk) {
      logSecurityEvent('invalid_nonce_wallet_auth', 'medium', {
        address: `${address.slice(0, 6)}...${address.slice(-4)}`,
        ip: getClientIp(request)
      });

      return NextResponse.json(
        { error: 'Invalid nonce' },
        { status: 401 }
      );
    }

    // تایید Signature
    const message = `Sign this message to authenticate: ${nonce}`;
    const isValidSignature = await verifySignature(address, message, signature);

    if (!isValidSignature) {
      logSecurityEvent('invalid_signature_wallet_auth', 'high', {
        address: `${address.slice(0, 6)}...${address.slice(-4)}`,
        ip: getClientIp(request)
      });

      // تاخیر برای جلوگیری از Brute Force
      await new Promise(resolve => setTimeout(resolve, 1000));

      return NextResponse.json(
        { error: 'Invalid signature' },
        { status: 401 }
      );
    }

    // جستجو یا ایجاد کاربر
    const userQuery = await db
      .collection('users')
      .where('walletAddress', '==', address.toLowerCase())
      .get();

    let userId: string;
    let userData: any;
    let isNewUser = false;

    if (userQuery.empty) {
      // ایجاد کاربر جدید
      const newUser = {
        walletAddress: address.toLowerCase(),
        authMethod: 'wallet',
        status: 'active',
        createdAt: new Date(),
        updatedAt: new Date(),
        lastLogin: new Date(),
        lastLoginIp: getClientIp(request)
      };

      const userRef = await db.collection('users').add(newUser);
      userId = userRef.id;
      userData = newUser;
      isNewUser = true;

      logger.info('New wallet user created', {
        userId,
        address: `${address.slice(0, 6)}...${address.slice(-4)}`
      });
    } else {
      // کاربر موجود
      const firstDoc = userQuery.docs[0];
      if (!firstDoc) {
        return NextResponse.json({ error: 'User lookup failed' }, { status: 500 });
      }

      userId = firstDoc.id;
      userData = firstDoc.data();

      // بررسی وضعیت حساب
      if (userData.status === 'blocked') {
        logSecurityEvent('blocked_user_login_attempt', 'high', {
          userId,
          address: `${address.slice(0, 6)}...${address.slice(-4)}`,
          ip: getClientIp(request)
        });

        return NextResponse.json(
          { error: 'Account has been blocked. Please contact support.' },
          { status: 403 }
        );
      }

      // بروزرسانی اطلاعات کاربر
      await db.collection('users').doc(userId).update({
        lastLogin: new Date(),
        lastLoginIp: getClientIp(request)
      });
    }

    // تولید Token ها
    const tokens = generateTokenPair({
      userId,
      tenantId: userData.tenantId,
      walletAddress: address.toLowerCase(),
      authMethod: 'wallet'
    });

    // ایجاد Session
    const sessionId = createSession(userId, userData.tenantId, {
      ipAddress: getClientIp(request),
      userAgent: getUserAgent(request)
    });

    // ایجاد Response
    const response = NextResponse.json(
      {
        success: true,
        isNewUser,
        user: {
          id: userId,
          walletAddress: address.toLowerCase(),
          tenantId: userData.tenantId || null
        },
        expiresIn: tokens.expiresIn
      },
      { status: isNewUser ? 201 : 200 }
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
      authMethod: 'wallet',
      address: `${address.slice(0, 6)}...${address.slice(-4)}`,
      isNewUser,
      sessionId,
      duration: `${Date.now() - startTime}ms`
    });

    return response;

  } catch (error) {
    logger.error('Wallet authentication error', {
      error,
      address: walletAddress ? `${walletAddress.slice(0, 6)}...${walletAddress.slice(-4)}` : 'unknown',
      duration: `${Date.now() - startTime}ms`
    });

    return NextResponse.json(
      { error: 'An error occurred during wallet authentication' },
      { status: 500 }
    );
  }
}

// تنظیمات Route
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';