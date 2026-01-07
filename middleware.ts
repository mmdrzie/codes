import { NextRequest, NextResponse } from 'next/server';
import arcjet, { detectBot, shield, tokenBucket } from '@arcjet/next';

// Initialize Arcjet for rate limiting and bot detection
const aj = arcjet({
  key: process.env.ARCJET_KEY!, // Get your key from: https://app.arcjet.com
  characteristics: ['ip.src', 'user.id'], // Track requests by IP and user ID
  rules: [
    // Rate limit requests to 100 per minute per IP
    tokenBucket({
      mode: 'LIVE', // Set to "LIVE" to block requests, "DRY_RUN" to log only
      refillRate: 100,
      capacity: 100,
    }),
    // Detect and block bots
    detectBot({
      mode: 'LIVE',
      allow: [], // Allow no bots
    }),
    // Apply Arcjet Shield for common attacks
    shield({
      mode: 'LIVE',
    }),
  ],
});

export async function middleware(req: NextRequest) {
  // Apply rate limiting and bot detection
  const decision = await aj.protect(req);
  
  if (decision.isDenied()) {
    if (decision.reason.isRateLimit()) {
      return NextResponse.json(
        { error: 'Rate limit exceeded', reason: 'Too many requests' },
        { status: 429 }
      );
    } else if (decision.reason.isBot()) {
      return NextResponse.json(
        { error: 'Bots not allowed', reason: decision.reason },
        { status: 403 }
      );
    } else {
      return NextResponse.json(
        { error: 'Forbidden', reason: decision.reason },
        { status: 403 }
      );
    }
  }

  // Add security headers to all responses
  const response = NextResponse.next();
  
  // Strict Content Security Policy
  response.headers.set(
    'Content-Security-Policy',
    `default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self';`
  );
  
  // HTTP Strict Transport Security
  response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  
  // Additional security headers
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-XSS-Protection', '1; mode=block');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  
  return response;
}

// Apply middleware to all routes except static assets
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    {
      source: '/((?!api|_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
};