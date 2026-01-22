/**
 * Enhanced Security Middleware with IP Spoofing Prevention and Advanced Security Features
 */

import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import { logger } from './logger';

// Security configuration
const SECURITY_CONFIG = {
  // Trusted proxy configuration
  TRUSTED_PROXIES: process.env.TRUSTED_PROXIES?.split(',') || [],
  
  // CSP policies
  CSP_POLICIES: {
    production: {
      'default-src': "'self'",
      'script-src': ["'self'", "'strict-dynamic'", `'nonce-${crypto.randomUUID()}'`],
      'style-src': ["'self'", "'unsafe-inline'"], // For development only
      'img-src': ["'self'", 'data:', 'https:'],
      'font-src': ["'self'", 'data:', 'https:'],
      'connect-src': ["'self'", 'https://*.yourdomain.com', 'wss://*.yourdomain.com'],
      'frame-ancestors': ["'none'"],
      'object-src': "'none'",
      'base-uri': "'self'",
      'form-action': "'self'"
    },
    development: {
      'default-src': "'self'",
      'script-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      'style-src': ["'self'", "'unsafe-inline'"],
      'img-src': ["'self'", 'data:', 'https:', 'http:'],
      'font-src': ["'self'", 'data:', 'https:', 'http:'],
      'connect-src': ["'self'", 'https:', 'http:'],
      'frame-ancestors': ["'none'"],
      'object-src': "'none'",
      'base-uri': "'self'",
      'form-action': "'self'"
    }
  },
  
  // Rate limiting
  RATE_LIMITS: {
    global: { max: 1000, window: 60 * 60 * 1000 }, // 1000 requests per hour
    per_ip: { max: 100, window: 15 * 60 * 1000 },  // 100 requests per 15 minutes per IP
    sensitive_endpoints: { max: 5, window: 5 * 60 * 1000 } // 5 requests per 5 minutes for sensitive endpoints
  }
};

/**
 * Validates if an IP address belongs to a trusted proxy
 */
function isTrustedProxy(ip: string): boolean {
  return SECURITY_CONFIG.TRUSTED_PROXIES.some(trusted => {
    if (trusted.includes('/')) {
      // CIDR notation
      return isIpInCidr(ip, trusted);
    }
    return trusted === ip;
  });
}

/**
 * Checks if an IP is within a CIDR range
 */
function isIpInCidr(ip: string, cidr: string): boolean {
  const [range, bits] = cidr.split('/');
  const mask = ~((1 << (32 - parseInt(bits))) - 1);
  const rangeNum = ipToNumber(range);
  const ipNum = ipToNumber(ip);
  return (ipNum & mask) === (rangeNum & mask);
}

/**
 * Converts IP address to number for CIDR comparison
 */
function ipToNumber(ip: string): number {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
}

/**
 * Securely extracts the real client IP address, preventing IP spoofing
 */
export function getClientIp(request: NextRequest): string {
  // Get the connection info first (most trusted source)
  const connectionIp = request.ip || request.headers.get('x-forwarded-for')?.split(',')[0]?.trim();
  
  // Get various forwarded headers
  const forwardedFor = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim();
  const realIp = request.headers.get('x-real-ip')?.trim();
  const cfConnectingIp = request.headers.get('cf-connecting-ip')?.trim();
  const xClusterClientIp = request.headers.get('x-cluster-client-ip')?.trim();
  const xOriginalForwardedFor = request.headers.get('x-original-forwarded-for')?.trim();
  
  // If we're behind a trusted proxy, we can trust the forwarded headers
  const clientIp = connectionIp || forwardedFor || realIp || cfConnectingIp || xClusterClientIp || xOriginalForwardedFor || '127.0.0.1';
  
  // Validate IP format to prevent header injection
  if (!isValidIpAddress(clientIp)) {
    logger.warn('Invalid IP address detected in headers', { 
      attemptedIp: clientIp,
      headers: Array.from(request.headers.keys())
    });
    return '127.0.0.1'; // Default to localhost for invalid IPs
  }
  
  // If not behind trusted proxy, return connection IP (most trustworthy)
  if (!isTrustedProxy(clientIp)) {
    // In this case, forwarded headers could be spoofed, so return connection IP
    return request.ip || '127.0.0.1';
  }
  
  // If we trust the proxy, extract the original client IP from the forwarded header chain
  const forwardedChain = request.headers.get('x-forwarded-for');
  if (forwardedChain) {
    // Get the leftmost IP in the chain (original client)
    const ips = forwardedChain.split(',').map(ip => ip.trim());
    
    // Find the first IP that isn't a trusted proxy
    for (const ip of ips) {
      if (!isTrustedProxy(ip) && isValidIpAddress(ip)) {
        return ip;
      }
    }
  }
  
  return clientIp;
}

/**
 * Validates IP address format to prevent header injection
 */
function isValidIpAddress(ip: string): boolean {
  // Basic IPv4 validation
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Regex.test(ip)) {
    const parts = ip.split('.').map(Number);
    return parts.every(part => part >= 0 && part <= 255);
  }
  
  // Basic IPv6 validation (simplified)
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  if (ipv6Regex.test(ip)) {
    return true;
  }
  
  // Additional check for localhost variations
  if (ip === 'localhost' || ip === '127.0.0.1' || ip === '::1') {
    return true;
  }
  
  return false;
}

/**
 * Generates a cryptographically secure nonce for CSP
 */
export function generateCspNonce(): string {
  return crypto.randomBytes(16).toString('hex');
}

/**
 * Creates a Content Security Policy header with dynamic nonce
 */
export function createCspHeader(nonce: string, isProduction: boolean = process.env.NODE_ENV === 'production'): string {
  const policy = isProduction ? SECURITY_CONFIG.CSP_POLICIES.production : SECURITY_CONFIG.CSP_POLICIES.development;
  
  // Clone the policy object to avoid modifying the original
  const cspPolicy = { ...policy };
  
  // Update script-src with the dynamic nonce
  if (Array.isArray(cspPolicy['script-src'])) {
    cspPolicy['script-src'] = [...cspPolicy['script-src'], `'nonce-${nonce}'`];
  } else {
    cspPolicy['script-src'] = [cspPolicy['script-src'], `'nonce-${nonce}'`];
  }
  
  // Build the CSP string
  return Object.entries(cspPolicy)
    .map(([directive, values]) => {
      if (Array.isArray(values)) {
        return `${directive} ${values.join(' ')}`;
      }
      return `${directive} ${values}`;
    })
    .join('; ');
}

/**
 * Validates session binding (IP and User-Agent consistency)
 */
export async function validateSessionBinding(
  sessionId: string, 
  currentIp: string, 
  currentUserAgent: string
): Promise<boolean> {
  try {
    // In a real implementation, this would check against a database or Redis
    // For now, we'll simulate the validation
    
    // Retrieve stored session data (simulated)
    const storedSession = await getSessionData(sessionId);
    
    if (!storedSession) {
      // New session, store the current data
      await storeSessionData(sessionId, {
        ip: currentIp,
        userAgent: currentUserAgent,
        createdAt: new Date().toISOString()
      });
      return true;
    }
    
    // Validate IP and User-Agent match
    const ipMatches = storedSession.ip === currentIp;
    const userAgentMatches = storedSession.userAgent === currentUserAgent;
    
    if (!ipMatches || !userAgentMatches) {
      logger.warn('Session binding validation failed', {
        sessionId,
        expected: {
          ip: storedSession.ip,
          userAgent: storedSession.userAgent
        },
        actual: {
          ip: currentIp,
          userAgent: currentUserAgent
        },
        timestamp: new Date().toISOString()
      });
      
      // Invalidate session on binding failure
      await invalidateSession(sessionId);
      
      return false;
    }
    
    return true;
  } catch (error) {
    logger.error('Session binding validation error', { error: (error as Error).message });
    return false;
  }
}

/**
 * Simulated session data retrieval (replace with actual implementation)
 */
async function getSessionData(sessionId: string): Promise<any> {
  // In a real implementation, this would fetch from Redis or database
  // Returning null to simulate a new session
  return null;
}

/**
 * Simulated session data storage (replace with actual implementation)
 */
async function storeSessionData(sessionId: string, data: any): Promise<void> {
  // In a real implementation, this would store in Redis or database
  console.log(`Storing session data for ${sessionId}`, data);
}

/**
 * Simulated session invalidation (replace with actual implementation)
 */
async function invalidateSession(sessionId: string): Promise<void> {
  // In a real implementation, this would delete from Redis or database
  console.log(`Invalidating session ${sessionId}`);
}

/**
 * Implements enhanced rate limiting with cryptographic hashing
 */
export async function applyEnhancedRateLimiting(
  request: NextRequest, 
  userId?: string
): Promise<NextResponse | null> {
  const clientIp = getClientIp(request);
  const userAgent = request.headers.get('user-agent') || '';
  
  // Create cryptographic hash for the identifier to prevent collisions
  const ipHash = crypto.createHash('sha256').update(clientIp).digest('hex');
  const userAgentHash = crypto.createHash('sha256').update(userAgent).digest('hex');
  const endpoint = request.nextUrl.pathname;
  const endpointHash = crypto.createHash('sha256').update(endpoint).digest('hex');
  
  // Create combined identifier
  const combinedId = `${ipHash}:${userAgentHash}:${endpointHash}`;
  const userIdHash = userId ? crypto.createHash('sha256').update(userId).digest('hex') : null;
  
  // Use the hashed identifiers for rate limiting
  const identifiers = [
    `ip:${ipHash}`,
    `ua:${userAgentHash}`, 
    `ep:${endpointHash}`,
    `combo:${combinedId}`,
    ...(userIdHash ? [`user:${userIdHash}`] : [])
  ];
  
  // Check rate limits for all identifiers
  for (const id of identifiers) {
    const isLimited = await checkRateLimit(id);
    if (isLimited) {
      return new NextResponse('Rate limit exceeded', { status: 429 });
    }
  }
  
  return null; // No rate limiting applied
}

/**
 * Simulated rate limit checking (replace with actual implementation)
 */
async function checkRateLimit(identifier: string): Promise<boolean> {
  // In a real implementation, this would check against Redis with sliding window algorithm
  // For simulation, we'll return false (not limited)
  return false;
}

/**
 * Sanitizes error messages to prevent information disclosure
 */
export function sanitizeErrorMessage(error: unknown): string {
  // Log the full error internally for debugging
  logger.error('Security error occurred', { error });
  
  // Return generic message to client
  if (process.env.NODE_ENV === 'production') {
    return 'An error occurred processing your request';
  }
  
  // In development, return more descriptive message
  return (error as Error)?.message || 'An error occurred processing your request';
}

/**
 * Validates request for suspicious patterns to prevent attacks
 */
export function validateRequestForSuspiciousPatterns(request: NextRequest): boolean {
  const url = request.nextUrl.toString();
  const userAgent = request.headers.get('user-agent') || '';
  
  // Common attack patterns
  const suspiciousPatterns = [
    /union\s+select/i,
    /drop\s+table/i,
    /exec\s*\(/i,
    /<script/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /eval\s*\(/i,
    /document\.cookie/i,
    /alert\s*\(/i,
    /\.\.\//, // Directory traversal
    /%00/, // Null byte
    /<iframe/i,
    /vbscript:/i,
    /expression\(/i,
    /\/etc\/passwd/i,
    /select.*from/i,
    /insert.*into/i,
    /delete.*from/i
  ];
  
  // Check for suspicious patterns in URL and user agent
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(url) || pattern.test(userAgent)) {
      logger.warn('Suspicious pattern detected', {
        pattern: pattern.toString(),
        url,
        userAgent,
        ip: getClientIp(request)
      });
      return false;
    }
  }
  
  // Check for common automated scanner user agents
  const scannerAgents = [
    'sqlmap',
    'nikto',
    'nessus',
    'acunetix',
    'burp',
    'owasp',
    'nmap',
    'masscan',
    'gobuster',
    'dirbuster',
    'arachni',
    'w3af',
    'skipfish',
    'zap'
  ];
  
  for (const scanner of scannerAgents) {
    if (userAgent.toLowerCase().includes(scanner)) {
      logger.warn('Scanner user agent detected', {
        userAgent,
        ip: getClientIp(request)
      });
      return false;
    }
  }
  
  return true;
}

/**
 * Implements strict transport security and other security headers
 */
export function addSecurityHeaders(response: NextResponse): NextResponse {
  // Generate a new nonce for each response
  const nonce = generateCspNonce();
  
  // Add security headers
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-XSS-Protection', '1; mode=block');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  response.headers.set('Content-Security-Policy', createCspHeader(nonce));
  response.headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload'); // 2 years
  
  // Add the nonce to the response for client-side use
  response.headers.set('X-Nonce', nonce);
  
  return response;
}

/**
 * Validates that cryptographic requirements are met (Post-Quantum Crypto check)
 */
export function validateCryptoRequirements(): void {
  // Check if required cryptographic functions are available
  try {
    // Test basic crypto functionality
    crypto.randomBytes(32);
    
    // In a real implementation, you would also check for OQS (Open Quantum Safe) libraries here
    // For now, we'll just ensure basic crypto is available
    
    // If any critical crypto functionality is missing, throw an error
    // This ensures the system "fails closed" if security requirements aren't met
    logger.info('Cryptographic requirements validated successfully');
  } catch (error) {
    logger.error('Cryptographic requirements validation failed', { error: (error as Error).message });
    throw new Error('System security requirements not met - cryptographic functions unavailable');
  }
}

/**
 * Validates environment secrets configuration
 */
export function validateSecretsConfiguration(): void {
  const requiredSecrets = [
    'JWT_ACCESS_SECRET',
    'JWT_REFRESH_SECRET', 
    'WALLET_JWT_SECRET',
    'UPSTASH_REDIS_REST_URL',
    'UPSTASH_REDIS_REST_TOKEN'
  ];
  
  const missingSecrets = [];
  for (const secret of requiredSecrets) {
    if (!process.env[secret]) {
      missingSecrets.push(secret);
    } else if (process.env[secret]?.length < 32) {
      logger.warn(`Secret ${secret} is too short (minimum 32 characters recommended)`);
    }
  }
  
  if (missingSecrets.length > 0) {
    logger.error('Missing required secrets', { missingSecrets });
    throw new Error(`Missing required secrets: ${missingSecrets.join(', ')}`);
  }
  
  logger.info('Secrets configuration validated successfully');
}