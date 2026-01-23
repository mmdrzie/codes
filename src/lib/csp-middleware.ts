import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';

// Define allowed sources for various CSP directives
const CSP_CONFIG = {
  defaultSrc: ["'self'"],
  scriptSrc: [
    "'self'",
    // Add nonces for inline scripts
    // These will be populated dynamically with nonce values
  ],
  styleSrc: [
    "'self'",
    "'unsafe-inline'", // Needed for Next.js dynamic styles, consider using strict-dynamic
    'https://fonts.googleapis.com',
  ],
  imgSrc: [
    "'self'",
    'data:',
    'https:',
    'http:',
    'blob:',
  ],
  fontSrc: [
    "'self'",
    'https://fonts.gstatic.com',
    'data:',
  ],
  connectSrc: [
    "'self'",
    'https://*.sentry.io', // For Sentry error tracking
    'https://api.infura.io', // For Ethereum blockchain interactions
    'https://*.infura.io',
    'wss://*.infura.io',
    'https://rpc.ankr.com',
  ],
  frameAncestors: ["'none'"], // Prevent clickjacking by disallowing framing
  objectSrc: ["'none'"], // Disallow plugins like Flash
  baseUri: ["'self'"],
  formAction: ["'self'"],
  frameSrc: [
    "'self'",
    'https://www.google.com', // For reCAPTCHA if implemented
    'https://challenges.cloudflare.com', // For Cloudflare Turnstile
  ],
};

// Generate a random nonce for each request
export function generateNonce(): string {
  return crypto.randomBytes(16).toString('hex');
}

// Build CSP header string
function buildCSPHeader(nonce: string): string {
  // Clone the config to avoid modifying the original
  const config = { ...CSP_CONFIG };
  
  // Add the nonce to script-src directive
  config.scriptSrc = [...CSP_CONFIG.scriptSrc, `'nonce-${nonce}'`];
  
  const directives = Object.entries(config)
    .filter(([_, values]) => values.length > 0)
    .map(([directive, values]) => {
      // Convert kebab-case to camelCase for directive names
      const directiveName = directive.replace(/([A-Z])/g, '-$1').toLowerCase();
      return `${directiveName} ${values.join(' ')}`;
    })
    .join('; ');

  // Add report-uri for CSP violations (optional, for monitoring)
  return `${directives}; report-uri /api/csp-report`;
}

// CSP Middleware
export function cspMiddleware(request: NextRequest, response: NextResponse): NextResponse {
  // Generate a unique nonce for this request
  const nonce = generateNonce();
  
  // Build the CSP header
  const cspHeader = buildCSPHeader(nonce);
  
  // Add CSP header to response
  response.headers.set('Content-Security-Policy', cspHeader);
  
  // Also add related security headers
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-XSS-Protection', '1; mode=block');
  
  // Add the nonce to the response so it can be used in templates
  response.headers.set('X-Nonce', nonce);
  
  return response;
}

// Higher-order function to wrap route handlers with CSP
export function withCSP(handler: (request: NextRequest) => Promise<NextResponse>) {
  return async (request: NextRequest) => {
    const nonce = generateNonce();
    const response = await handler(request);
    
    // Build CSP header with the generated nonce
    const cspHeader = buildCSPHeader(nonce);
    
    // Add CSP header to response
    response.headers.set('Content-Security-Policy', cspHeader);
    
    // Also add related security headers
    response.headers.set('X-Content-Type-Options', 'nosniff');
    response.headers.set('X-Frame-Options', 'DENY');
    response.headers.set('X-XSS-Protection', '1; mode=block');
    
    // Add the nonce to the response so it can be used in templates
    response.headers.set('X-Nonce', nonce);
    
    return response;
  };
}

// Export the nonce for use in React components
export { generateNonce, buildCSPHeader };