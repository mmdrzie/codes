import { NextRequest, NextResponse } from 'next/server';
import { checkRateLimit, getIdentifier } from '@/lib/rateLimit';
import { getRefreshToken, setAuthCookies } from '@/lib/cookies';
import { generateTokenPair, verifyRefreshToken } from '@/lib/tokenUtils';
import { addToBlacklist, isTokenBlacklisted } from '@/lib/sessionUtils';
import { logger } from '@/lib/logger';
import { Redis } from '@upstash/redis';

// Initialize Redis for distributed locking
const redis = Redis.fromEnv();
const REFRESH_LOCK_PREFIX = 'refresh_lock:';
const REFRESH_LOCK_TTL = 30; // 30 seconds lock TTL

// Track ongoing refresh operations to prevent race conditions
const ongoingRefreshOperations = new Map<string, Promise<any>>();

export async function POST(request: NextRequest) {
  // Rate limit per IP
  const identifier = getIdentifier(request);
  const rl = checkRateLimit(identifier, 'refresh'); // Use specific refresh rate limit

  if (!rl.allowed) {
    return NextResponse.json(
      { error: rl.message || 'Rate limit exceeded', resetAt: rl.resetAt },
      {
        status: 429,
        headers: {
          'X-RateLimit-Limit': String(10),
          'X-RateLimit-Remaining': String(rl.remaining),
          'X-RateLimit-Reset': String(rl.resetAt),
        },
      }
    );
  }

  const refreshToken = await getRefreshToken();
  if (!refreshToken) {
    return NextResponse.json({ error: 'Authentication required' }, { status: 401 });
  }

  // Create a unique key for this refresh operation to prevent concurrent operations
  const operationKey = `refresh_${refreshToken.substring(0, 16)}`;
  
  // Implement distributed locking to handle race conditions across multiple instances
  const lockKey = `${REFRESH_LOCK_PREFIX}${refreshToken}`;
  
  // Try to acquire lock using Redis
  let acquiredLock = false;
  try {
    // Use SET command with NX (not exists) and EX (expire) options for atomic lock acquisition
    const lockResult = await redis.set(lockKey, 'locked', {
      nx: true,  // Only set if key doesn't exist
      ex: REFRESH_LOCK_TTL  // Expire after TTL seconds
    });
    
    acquiredLock = lockResult === 'OK';
  } catch (error) {
    logger.warn('Redis lock acquisition failed, falling back to memory lock', { error: (error as Error).message });
    // Fall back to memory-based locking
    if (ongoingRefreshOperations.has(operationKey)) {
      // Wait for the ongoing operation to complete
      try {
        await ongoingRefreshOperations.get(operationKey);
      } catch {
        // If the previous operation failed, continue with this one
      }
    }
  }

  if (!acquiredLock && !ongoingRefreshOperations.has(operationKey)) {
    // Double-check if another instance acquired the lock while we were checking
    // If not, use memory-based locking as a backup
    if (ongoingRefreshOperations.has(operationKey)) {
      try {
        await ongoingRefreshOperations.get(operationKey);
      } catch {
        // If the previous operation failed, continue with this one
      }
    }
  }

  // Create the operation promise
  const operationPromise = (async () => {
    try {
      // Token rotation + blacklist
      if (await isTokenBlacklisted(refreshToken)) {
        return NextResponse.json({ error: 'Token revoked', shouldLogout: true }, { status: 401 });
      }

      const verificationResult = await verifyRefreshToken(refreshToken);
      if (!verificationResult.valid || !verificationResult.payload) {
        // If refresh token is malformed/invalid, blacklist it briefly to mitigate replay
        await addToBlacklist(refreshToken, 24 * 60 * 60);
        return NextResponse.json({ error: 'Invalid refresh token', shouldLogout: true }, { status: 401 });
      }

      // Issue new pair
      const tokens = generateTokenPair({
        userId: verificationResult.payload.userId,
        tenantId: verificationResult.payload.tenantId,
        email: verificationResult.payload.email,
        walletAddress: verificationResult.payload.walletAddress,
        authMethod: verificationResult.payload.authMethod,
        role: verificationResult.payload.role,
      });

      // Revoke old refresh token (rotation) - this is critical for security
      await addToBlacklist(refreshToken, 7 * 24 * 60 * 60);

      const response = NextResponse.json({
        success: true,
        expiresIn: tokens.expiresIn,
      });

      await setAuthCookies(tokens.accessToken, tokens.refreshToken, undefined, response);

      // Security headers
      response.headers.set('X-Content-Type-Options', 'nosniff');
      response.headers.set('X-Frame-Options', 'DENY');
      response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');

      if (process.env.NODE_ENV === 'production') {
        response.headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
      }

      return response;
    } finally {
      // Release the distributed lock
      try {
        await redis.del(lockKey);
      } catch (error) {
        logger.error('Failed to release refresh lock', { error: (error as Error).message });
      }
    }
  })();

  // Store the operation promise if we're using memory-based locking
  if (!acquiredLock) {
    ongoingRefreshOperations.set(operationKey, operationPromise);
  }

  try {
    const response = await operationPromise;
    return response;
  } catch (error) {
    logger.error('Refresh token error', { error: (error as Error).message, operationKey });
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  } finally {
    // Clean up the operation after completion
    if (!acquiredLock) {
      ongoingRefreshOperations.delete(operationKey);
    }
  }
}

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';