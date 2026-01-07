import { NextRequest, NextResponse } from 'next/server';
import { generateAndStoreNonce } from '@/lib/nonceStore';
import { checkRateLimit, getIdentifier } from '@/lib/rateLimit';
import { z } from 'zod';

// ✅ Validation schema with proper types
const nonceRequestSchema = z.object({
  address: z.string()
    .regex(/^0x[a-fA-F0-9]{40}$/, 'Invalid Ethereum address')
    .transform((addr: string) => addr.toLowerCase()),
});

// ✅ تعریف type برای issue
type ValidationIssue = {
  path: (string | number)[];
  message: string;
  code: string;
};

export async function POST(request: NextRequest) {
  try {
    // ✅ Rate limiting
    const identifier = getIdentifier(request);
    const rateLimitResult = checkRateLimit(identifier, 'walletAuth');

    if (!rateLimitResult.allowed) {
      return NextResponse.json(
        { 
          error: 'Rate limit exceeded',
          code: 'RATE_LIMIT_EXCEEDED',
          retryAfter: Math.ceil((rateLimitResult.resetAt - Date.now()) / 1000),
        },
        { 
          status: 429,
          headers: {
            'X-RateLimit-Limit': '10',
            'X-RateLimit-Remaining': rateLimitResult.remaining.toString(),
            'X-RateLimit-Reset': new Date(rateLimitResult.resetAt).toISOString(),
            'Retry-After': Math.ceil((rateLimitResult.resetAt - Date.now()) / 1000).toString(),
          }
        }
      );
    }

    // ✅ Parse و validate
    const body = await request.json();
    const validated = nonceRequestSchema.safeParse(body);

    if (!validated.success) {
      // ✅ استفاده از type cast
      const issues = validated.error.issues as ValidationIssue[];
      
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

    const { address } = validated.data;

    // ✅ Generate nonce
    const { nonce, message, expiresAt } = await generateAndStoreNonce(address);

    return NextResponse.json({
      success: true,
      nonce,
      message,
      expiresAt,
      expiresIn: Math.floor((expiresAt - Date.now()) / 1000), // seconds remaining
    });

  } catch (error: unknown) {
    console.error('Nonce generation error:', error);
    
    // ✅ Error handling مناسب
    const errorMessage = error instanceof Error ? error.message : 'Failed to generate nonce';
    const status = errorMessage.includes('Too many') ? 429 : 500;
    
    return NextResponse.json(
      { 
        error: errorMessage,
        code: 'INTERNAL_ERROR'
      },
      { status }
    );
  }
}

// ✅ CORS برای preflight requests
export async function OPTIONS(request: Request) {
  const allowedOrigins = [
    'http://localhost:3000',
    'https://quantumiq.vercel.app',
  ];
  
  const origin = request.headers.get('origin');
  const isAllowedOrigin = !!origin && allowedOrigins.includes(origin);
  const allowOrigin = isAllowedOrigin ? origin! : allowedOrigins[0]!;
  
  return new NextResponse(null, {
    status: 204,
    headers: new Headers({
      'Access-Control-Allow-Origin': allowOrigin,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Max-Age': '86400',
      'Vary': 'Origin',
    })
  });
}