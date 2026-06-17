import { NextRequest, NextResponse } from 'next/server';
import { ethers } from 'ethers';
import { walletAuthSchema } from '@/lib/validation';
import { validateWalletAddress } from '@/lib/security';
import { generateTokenPair } from '@/lib/tokenUtils';
import { setAuthCookies } from '@/lib/cookies';
import { getEnterpriseRedisClient } from '@/infrastructure/redis/enterprise-redis-client';
import { EnterpriseRateLimiter } from '@/core/ratelimit/enterprise-rate-limiter';
import { EnterpriseSessionManager } from '@/core/session/enterprise-session-manager';
import { EnterpriseSiweNonceStore } from '@/core/auth/enterprise-siwe-nonce-store';
import { logger } from '@/lib/logger';
import { getClientIp, getUserAgent } from '@/lib/helpers';
import { getAdminDb } from '@/lib/firebase';

// Initialize enterprise components
const redisClient = getEnterpriseRedisClient();
const rateLimiter = new EnterpriseRateLimiter(redisClient);
const sessionManager = new EnterpriseSessionManager(redisClient);
const nonceStore = new EnterpriseSiweNonceStore(redisClient);

/**
 * Verify signature with ethers.js
 */
async function verifySignature(
  address: string,
  message: string,
  signature: string
): Promise<boolean> {
  try {
    const recoveredAddress = ethers.verifyMessage(message, signature);
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
    // CRITICAL: Apply rate limiting FIRST - FAILS CLOSED
    const identifier = getClientIp(request) || 'unknown';
    const rateLimitResult = await rateLimiter.checkRateLimit(
      `wallet_auth:${identifier}`,
      'auth:wallet'
    );

    if (!rateLimitResult.allowed) {
      logger.warn('Wallet auth rate limit exceeded', {
        identifier,
        resetAt: new Date(rateLimitResult.resetAt).toISOString()
      });

      return NextResponse.json(
        {
          error: 'Rate limit exceeded. Please try again later.',
          resetAt: rateLimitResult.resetAt
        },
        {
          status: 429,
          headers: {
            'X-RateLimit-Limit': rateLimitResult.policy?.maxRequests.toString() || '10',
            'X-RateLimit-Remaining': rateLimitResult.remaining.toString(),
            'X-RateLimit-Reset': new Date(rateLimitResult.resetAt).toISOString(),
            'Retry-After': Math.ceil((rateLimitResult.resetAt - Date.now()) / 1000).toString()
          }
        }
      );
    }

    // Parse and validate request body
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

    // Additional address validation
    if (!validateWalletAddress(address)) {
      logger.warn('Invalid wallet address format', {
        address,
        ip: getClientIp(request)
      });

      return NextResponse.json(
        { error: 'Invalid wallet address format' },
        { status: 400 }
      );
    }

    // CRITICAL: Verify and consume nonce atomically using enterprise store
    const lowerAddress = address.toLowerCase();
    const nonceValid = await nonceStore.verifyAndConsumeNonce(lowerAddress, nonce);

    if (!nonceValid) {
      logger.warn('Invalid or replayed nonce in wallet auth', {
        address: `${address.slice(0, 6)}...${address.slice(-4)}`,
        ip: getClientIp(request)
      });

      return NextResponse.json(
        { error: 'Invalid or replayed nonce' },
        { status: 401 }
      );
    }

    // Verify signature
    const message = `Sign this message to authenticate: ${nonce}`;
    const isValidSignature = await verifySignature(address, message, signature);

    if (!isValidSignature) {
      logger.warn('Invalid signature in wallet auth', {
        address: `${address.slice(0, 6)}...${address.slice(-4)}`,
        ip: getClientIp(request)
      });

      // Delay to prevent brute force
      await new Promise(resolve => setTimeout(resolve, 1000));

      return NextResponse.json(
        { error: 'Invalid signature' },
        { status: 401 }
      );
    }

    // Look up or create user
    const db = getAdminDb();
    const userQuery = await db
      .collection('users')
      .where('walletAddress', '==', lowerAddress)
      .get();

    let userId: string;
    let userData: any;
    let isNewUser = false;

    if (userQuery.empty) {
      // Create new user
      const newUser = {
        walletAddress: lowerAddress,
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
      // Existing user
      const firstDoc = userQuery.docs[0];
      if (!firstDoc) {
        return NextResponse.json({ error: 'User lookup failed' }, { status: 500 });
      }

      userId = firstDoc.id;
      userData = firstDoc.data();

      // Check account status
      if (userData.status === 'blocked') {
        logger.warn('Blocked user login attempt', {
          userId,
          address: `${address.slice(0, 6)}...${address.slice(-4)}`,
          ip: getClientIp(request)
        });

        return NextResponse.json(
          { error: 'Account has been blocked. Please contact support.' },
          { status: 403 }
        );
      }

      // Update user info
      await db.collection('users').doc(userId).update({
        lastLogin: new Date(),
        lastLoginIp: getClientIp(request)
      });
    }

    // Generate tokens
    const tokens = generateTokenPair({
      userId,
      tenantId: userData.tenantId,
      walletAddress: lowerAddress,
      authMethod: 'wallet'
    });

    // Create session using enterprise session manager
    const sessionId = await sessionManager.createSession({
      userId,
      tenantId: userData.tenantId || 'default',
      deviceFingerprint: getUserAgent(request) || 'unknown',
      ipAddress: getClientIp(request) || 'unknown',
      userAgent: getUserAgent(request) || 'unknown',
      authMethod: 'wallet',
      walletAddress: lowerAddress,
      roles: ['user'],
      permissions: []
    }).then(s => s.sessionId);

    // Create response
    const response = NextResponse.json(
      {
        success: true,
        isNewUser,
        user: {
          id: userId,
          walletAddress: lowerAddress,
          tenantId: userData.tenantId || null
        },
        expiresIn: tokens.expiresIn
      },
      { status: isNewUser ? 201 : 200 }
    );

    // Set cookies
    await setAuthCookies(
      tokens.accessToken,
      tokens.refreshToken,
      sessionId,
      response
    );

    // Log successful login
    logger.info('Wallet authentication successful', {
      userId,
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

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
