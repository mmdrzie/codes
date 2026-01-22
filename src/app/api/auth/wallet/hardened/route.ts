import { NextRequest, NextResponse } from 'next/server';
import { HardenedAuthService } from '@/services/auth/hardened-auth-service';
import { walletAuthSchema } from '@/lib/validation';
import { validateAndParse } from '@/lib/validation';
import { logger, logAuthEvent, logSecurityEvent } from '@/lib/logger';
import { getClientIp, getUserAgent } from '@/lib/helpers';
import { setAuthCookies } from '@/lib/cookies';
import { checkRateLimit, getIdentifier } from '@/lib/rateLimit';

/**
 * Hardened Wallet Authentication API Route
 * Implements post-quantum security with hybrid cryptography
 */
export async function POST(request: NextRequest) {
  const startTime = Date.now();
  let walletAddress: string | undefined;

  try {
    // Check Rate Limit
    const identifier = getIdentifier(request);
    const rateLimitResult = await checkRateLimit(identifier, 'walletAuth');

    if (!rateLimitResult.allowed) {
      logSecurityEvent('rate_limit_exceeded', 'medium', {
        identifier,
        endpoint: '/api/auth/wallet/hardened'
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

    // Get and validate request data
    const body = await request.json();
    const validationResult = validateAndParse(walletAuthSchema, body);

    if (!validationResult.success) {
      return NextResponse.json(
        {
          error: 'Invalid input',
          details: validationResult.errors
        },
        { status: 400 }
      );
    }

    const { address, signature, nonce } = validationResult.data;
    walletAddress = address;

    // Validate wallet address format
    // (validation is already handled by the schema, but we'll add additional checks here)
    if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
      logSecurityEvent('invalid_wallet_address_auth', 'medium', {
        address,
        ip: getClientIp(request)
      });

      return NextResponse.json(
        { error: 'Invalid wallet address format' },
        { status: 400 }
      );
    }

    // Perform hardened wallet authentication
    const clientInfo = {
      ip: getClientIp(request),
      userAgent: getUserAgent(request)
    };

    const authResult = await HardenedAuthService.authenticateWallet(
      address,
      signature,
      nonce,
      clientInfo
    );

    if (!authResult.success) {
      logSecurityEvent('hardened_wallet_auth_failed', 'high', {
        address: `${address.slice(0, 6)}...${address.slice(-4)}`,
        ip: clientInfo.ip,
        error: authResult.error
      });

      // Add delay to prevent brute force attacks
      await new Promise(resolve => setTimeout(resolve, 1000));

      return NextResponse.json(
        { error: authResult.error || 'Authentication failed' },
        { status: 401 }
      );
    }

    // Authentication successful - prepare response
    const response = NextResponse.json(
      {
        success: true,
        user: {
          id: authResult.user!.id,
          walletAddress: authResult.user!.walletAddress,
          authMethod: authResult.user!.authMethod,
          tenantId: authResult.user!.tenantId || null,
          status: authResult.user!.status
        },
        expiresIn: 300 // 5 minutes (access token TTL)
      },
      { status: 200 }
    );

    // Set authentication cookies with enhanced security
    if (authResult.tokens) {
      await setAuthCookies(
        authResult.tokens.accessToken,
        authResult.tokens.refreshToken,
        authResult.user!.sessionIds[authResult.user!.sessionIds.length - 1], // latest session
        response
      );
    }

    // Log successful authentication
    logAuthEvent('login', authResult.user!.id, true, {
      authMethod: 'wallet_hardened',
      address: `${address.slice(0, 6)}...${address.slice(-4)}`,
      sessionId: authResult.user!.sessionIds[authResult.user!.sessionIds.length - 1],
      duration: `${Date.now() - startTime}ms`
    });

    return response;

  } catch (error) {
    logger.error('Hardened wallet authentication error', {
      error,
      address: walletAddress ? `${walletAddress.slice(0, 6)}...${walletAddress.slice(-4)}` : 'unknown',
      duration: `${Date.now() - startTime}ms`
    });

    return NextResponse.json(
      { error: 'An error occurred during hardened wallet authentication' },
      { status: 500 }
    );
  }
}

// Enhanced security headers for the route
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// Add security middleware configuration
export const config = {
  api: {
    bodyParser: {
      sizeLimit: '1mb' // Limit request size to prevent abuse
    }
  }
};