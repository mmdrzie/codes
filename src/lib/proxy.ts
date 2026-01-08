import { NextRequest, NextResponse } from 'next/server';
import { lookup } from 'dns/promises';
import { URL } from 'url';
import { logger } from './logger';

// Whitelist of allowed domains for proxy requests
const ALLOWED_DOMAINS = new Set([
  'api.example.com',
  'external-api.service.com',
  'analytics.google.com',
  'api.mixpanel.com',
  'sentry.io',
  'api.segment.io',
  'api.stripe.com',
  'graph.facebook.com',
  'api.twitter.com',
  'api.linkedin.com',
]);

// List of internal IPs and private networks to block
const BLOCKED_IP_RANGES = [
  '10.',           // Class A private network
  '172.16.',       // Class B private network (172.16.0.0 - 172.31.255.255)
  '172.17.',
  '172.18.',
  '172.19.',
  '172.20.',
  '172.21.',
  '172.22.',
  '172.23.',
  '172.24.',
  '172.25.',
  '172.26.',
  '172.27.',
  '172.28.',
  '172.29.',
  '172.30.',
  '172.31.',
  '192.168.',      // Class C private network
  '127.',          // Loopback
  '0.',            // Self reference
  '::1',           // IPv6 loopback
  'fc00::',        // IPv6 private network
  'fe80::',        // IPv6 link-local
];

// Blocked ports for security
const BLOCKED_PORTS = new Set([22, 25, 110, 143, 993, 995, 1433, 3306, 5432, 6379, 27017]);

/**
 * Secure proxy that prevents Server-Side Request Forgery (SSRF) attacks
 */
export async function secureProxy(request: NextRequest, targetUrl: string): Promise<NextResponse> {
  try {
    // Validate and sanitize the target URL
    const sanitizedTargetUrl = await validateAndSanitizeUrl(targetUrl);
    if (!sanitizedTargetUrl) {
      return NextResponse.json(
        { error: 'Invalid target URL - SSRF protection triggered' },
        { status: 400 }
      );
    }

    // Prepare fetch options based on original request
    const fetchOptions: RequestInit = {
      method: request.method,
      headers: prepareSecureHeaders(request.headers),
      body: request.method !== 'GET' && request.method !== 'HEAD' ? await request.text() : undefined,
    };

    // Make the proxied request
    const response = await fetch(sanitizedTargetUrl, fetchOptions);

    // Sanitize response headers
    const responseHeaders = sanitizeResponseHeaders(response.headers);

    // Return the response with sanitized headers
    return new NextResponse(response.body, {
      status: response.status,
      headers: responseHeaders,
    });
  } catch (error: any) {
    logger.error('Proxy error', {
      error: error.message,
      targetUrl,
      stack: error.stack,
    });

    // Don't leak internal error details to client
    return NextResponse.json(
      { error: 'Proxy request failed' },
      { status: 500 }
    );
  }
}

/**
 * Validate and sanitize the target URL to prevent SSRF
 */
async function validateAndSanitizeUrl(urlString: string): Promise<string | null> {
  try {
    // Basic URL validation
    const url = new URL(urlString);

    // Protocol must be HTTPS for security (unless specifically needed otherwise)
    if (url.protocol !== 'https:' && url.protocol !== 'http:') {
      logger.warn('Blocked request - unsupported protocol', { protocol: url.protocol, url: urlString });
      return null;
    }

    // Block localhost and loopback addresses
    if (isLocalhost(url.hostname) || isPrivateNetwork(url.hostname)) {
      logger.warn('Blocked request - local/private address', { hostname: url.hostname, url: urlString });
      return null;
    }

    // Block specific ports
    if (url.port && BLOCKED_PORTS.has(parseInt(url.port, 10))) {
      logger.warn('Blocked request - blocked port', { port: url.port, url: urlString });
      return null;
    }

    // Resolve hostname to IP to check for private networks
    let resolvedIp: string | null = null;
    try {
      const resolved = await lookup(url.hostname);
      resolvedIp = resolved.address;

      // Check if resolved IP is in blocked ranges
      if (isPrivateIpAddress(resolvedIp)) {
        logger.warn('Blocked request - resolved to private IP', { 
          hostname: url.hostname, 
          ip: resolvedIp, 
          url: urlString 
        });
        return null;
      }
    } catch (dnsError) {
      logger.warn('DNS lookup failed', { hostname: url.hostname, error: (dnsError as Error).message });
      return null; // Fail closed
    }

    // Check against allowed domains whitelist
    if (!ALLOWED_DOMAINS.has(url.hostname.toLowerCase())) {
      logger.warn('Blocked request - domain not in whitelist', { 
        hostname: url.hostname, 
        ip: resolvedIp,
        url: urlString 
      });
      return null;
    }

    // Ensure the URL doesn't contain suspicious patterns
    if (containsSuspiciousPatterns(urlString)) {
      logger.warn('Blocked request - suspicious patterns detected', { url: urlString });
      return null;
    }

    return url.toString();
  } catch (error) {
    logger.warn('Invalid URL format', { url: urlString, error: (error as Error).message });
    return null;
  }
}

/**
 * Check if hostname is localhost
 */
function isLocalhost(hostname: string): boolean {
  return hostname === 'localhost' || 
         hostname === 'localhost.localdomain' || 
         hostname === 'local' ||
         hostname.endsWith('.local');
}

/**
 * Check if hostname resolves to a private network
 */
function isPrivateNetwork(hostname: string): boolean {
  // Check for common private network indicators in hostname
  return hostname.startsWith('internal.') || 
         hostname.startsWith('private.') || 
         hostname.includes('intranet') ||
         hostname.includes('internal') ||
         hostname.includes('private');
}

/**
 * Check if IP address is in a private network range
 */
function isPrivateIpAddress(ip: string): boolean {
  return BLOCKED_IP_RANGES.some(range => ip.startsWith(range));
}

/**
 * Check for suspicious URL patterns that might indicate SSRF attempts
 */
function containsSuspiciousPatterns(url: string): boolean {
  const suspiciousPatterns = [
    /\.(git|svn|htpasswd|shadow)/i,  // Files that shouldn't be accessed externally
    /(@|%40)(127\.0\.0\.1|localhost|0\.0\.0\.0)/i,  // IP addresses in username part
    /\.\.\/|\.\.\\/g,  // Directory traversal
    /0x[0-9a-f]+/gi,  // Hexadecimal IP representations
  ];

  return suspiciousPatterns.some(pattern => pattern.test(url));
}

/**
 * Prepare secure headers for the outgoing request
 * Remove potentially dangerous headers and add security headers
 */
function prepareSecureHeaders(originalHeaders: Headers): Headers {
  const secureHeaders = new Headers();

  // Only forward safe headers
  const safeHeaders = [
    'accept',
    'accept-encoding',
    'accept-language',
    'content-type',
    'user-agent',
    'authorization',
    'x-requested-with',
    'x-forwarded-for',
    'x-real-ip',
    'x-client-ip',
    'x-forwarded-host',
    'x-forwarded-proto',
    'x-custom-*', // Allow custom headers with prefix
  ];

  for (const [key, value] of originalHeaders.entries()) {
    // Check if header is in safe list (case-insensitive)
    const isSafe = safeHeaders.some(safeHeader => {
      if (safeHeader.endsWith('*')) {
        const prefix = safeHeader.slice(0, -1);
        return key.toLowerCase().startsWith(prefix);
      }
      return key.toLowerCase() === safeHeader;
    });

    if (isSafe) {
      // Block any headers that could be used for authentication bypass
      if (!key.toLowerCase().startsWith('cookie') && 
          !key.toLowerCase().startsWith('x-forwarded-server') &&
          !key.toLowerCase().startsWith('x-forwarded-scheme')) {
        secureHeaders.append(key, value);
      }
    }
  }

  // Add security headers to outbound request
  secureHeaders.append('User-Agent', 'SecureProxy/1.0 (+https://your-domain.com/security)');
  secureHeaders.append('Accept', 'application/json');
  secureHeaders.append('Accept-Encoding', 'gzip, deflate');

  return secureHeaders;
}

/**
 * Sanitize response headers to remove sensitive information
 */
function sanitizeResponseHeaders(responseHeaders: Headers): Headers {
  const sanitizedHeaders = new Headers();

  for (const [key, value] of responseHeaders.entries()) {
    // Block potentially dangerous response headers
    if (![
      'set-cookie',
      'location', 
      'access-control-allow-origin',
      'access-control-allow-credentials',
      'access-control-expose-headers',
      'www-authenticate',
      'proxy-authenticate',
      'proxy-authorization',
      'x-frame-options',
      'content-security-policy',
      'x-content-security-policy',
      'x-webkit-csp',
      'x-xss-protection',
      'x-content-type-options',
      'strict-transport-security',
      'public-key-pins',
      'x-permitted-cross-domain-policies',
      'referrer-policy',
      'permissions-policy'
    ].includes(key.toLowerCase())) {
      sanitizedHeaders.append(key, value);
    }
  }

  return sanitizedHeaders;
}

/**
 * Middleware wrapper for SSRF-safe proxy
 */
export async function withSecureProxy(
  request: NextRequest,
  targetUrl: string,
  options?: { timeout?: number }
): Promise<NextResponse> {
  // Log the proxy request for monitoring
  logger.info('Proxy request initiated', {
    method: request.method,
    originalUrl: request.url,
    targetUrl,
    userAgent: request.headers.get('user-agent'),
    ip: getClientIp(request),
  });

  const response = await secureProxy(request, targetUrl);

  logger.info('Proxy request completed', {
    status: response.status,
    targetUrl,
    duration: 'N/A', // Would need to track timing separately
  });

  return response;
}

/**
 * Extract client IP from request headers
 */
function getClientIp(request: NextRequest): string | null {
  const xff = request.headers.get('x-forwarded-for');
  if (xff) return xff.split(',')[0]?.trim() ?? null;
  
  const realIp = request.headers.get('x-real-ip');
  if (realIp) return realIp.trim();
  
  const cf = request.headers.get('cf-connecting-ip');
  if (cf) return cf.trim();
  
  return null;
}

/**
 * Add a domain to the allowed list (for dynamic configuration)
 */
export function addToAllowedDomains(domain: string): void {
  ALLOWED_DOMAINS.add(domain.toLowerCase());
}

/**
 * Remove a domain from the allowed list
 */
export function removeFromAllowedDomains(domain: string): void {
  ALLOWED_DOMAINS.delete(domain.toLowerCase());
}

/**
 * Get current allowed domains list
 */
export function getAllowedDomains(): Set<string> {
  return new Set(ALLOWED_DOMAINS);
}