import { NextRequest, NextResponse } from 'next/server';
import { createEnterpriseRedisClient } from '@/infrastructure/redis/enterprise-redis-client';
import { EnterpriseSiweNonceStore } from '@/core/auth/enterprise-siwe-nonce-store';
import { EnterpriseRateLimiter } from '@/core/ratelimit/enterprise-rate-limiter';
import { SecurityMonitor, SecurityEvent } from '@/lib/security-monitoring';
import { z } from 'zod';

// Validation schema with proper types
const nonceRequestSchema = z.object({
  address: z.string()
    .regex(/^0x[a-fA-F0-9]{40}$/, 'Invalid Ethereum address')
    .transform((addr: string) => addr.toLowerCase()),
});

type ValidationIssue = {
  path: (string | number)[];
  message: string;
  code: string;
};

// Initialize enterprise components
const redisClient = createEnterpriseRedisClient();
const nonceStore = new EnterpriseSiweNonceStore(redisClient);
const rateLimiter = new EnterpriseRateLimiter(redisClient);

export async function POST(request: NextRequest) {
  const clientIp = request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown';
  
  try {
    // Parse and validate request body FIRST (before any side effects)
    let address: string;
    try {
      const body = await request.json();
      const validated = nonceRequestSchema.safeParse(body);

      if (!validated.success) {
        const issues = validated.error.issues as ValidationIssue[];
        
        await SecurityMonitor.logEvent(
          SecurityEvent.INPUT_VALIDATION_FAILED,
          {
            timestamp: new Date(),
            metadata: {
              endpoint: '/api/auth/wallet/nonce',
              ip: clientIp,
              issues: issues.map(i => i.message),
            },
          },
          'Wallet nonce request validation failed'
        );
        
        return NextResponse.json(
          { 
            error: 'Validation failed',
            code: 'VALIDATION_ERROR',
            details: issues.map(issue => ({
              field: issue.path.join('.'),
              message: issue.message,
              code: issue.code,
            }))
          },
          { status: 400 }
        );
      }
      
      address = validated.data.address;
    } catch (parseError) {
      return NextResponse.json(
        { error: 'Invalid JSON body', code: 'PARSE_ERROR' },
        { status: 400 }
      );
    }

    // CRITICAL: Apply rate limiting BEFORE generating nonce
    // This is a CRITICAL endpoint - must FAIL CLOSED
    const rateLimitResult = await rateLimiter.checkCriticalEndpoint(
      `wallet_nonce:${address}`,
      'wallet_auth_nonce'
    );

    if (!rateLimitResult.allowed) {
      await SecurityMonitor.logEvent(
        SecurityEvent.RATE_LIMIT_EXCEEDED,
        {
          timestamp: new Date(),
          metadata: {
            endpoint: '/api/auth/wallet/nonce',
            address,
            ip: clientIp,
            limitType: 'wallet_auth_nonce',
          },
        },
        'Wallet nonce rate limit exceeded'
      );
      
      return NextResponse.json(
        { 
          error: 'Rate limit exceeded',
          code: 'RATE_LIMIT_EXCEEDED',
          retryAfter: Math.ceil((rateLimitResult.resetAt - Date.now()) / 1000),
        },
        { 
          status: 429,
          headers: {
            'X-RateLimit-Limit': rateLimitResult.limit.toString(),
            'X-RateLimit-Remaining': rateLimitResult.remaining.toString(),
            'X-RateLimit-Reset': new Date(rateLimitResult.resetAt).toISOString(),
            'Retry-After': Math.ceil((rateLimitResult.resetAt - Date.now()) / 1000).toString(),
          }
        }
      );
    }

    // Generate nonce using enterprise store (FAILS CLOSED if Redis unavailable)
    const { nonce, message, expiresAt } = await nonceStore.generateAndStoreNonce(address);

    return NextResponse.json({
      success: true,
      nonce,
      message,
      expiresAt,
      expiresIn: Math.floor((expiresAt - Date.now()) / 1000),
    });

  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    