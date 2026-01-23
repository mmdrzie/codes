import { NextApiHandler, NextApiRequest, NextApiResponse } from 'next';
import { RedisRateLimiter } from './redis-rate-limiter';
import { LimitsConfig } from './limits-config';
import { VelocityChecker } from './velocity-checker';

export interface RateLimitMiddlewareOptions {
  redisUrl?: string;
  trustProxy?: boolean;
}

export class RateLimitMiddleware {
  private rateLimiter: RedisRateLimiter;
  private velocityChecker: VelocityChecker;
  private options: RateLimitMiddlewareOptions;

  constructor(options: RateLimitMiddlewareOptions = {}) {
    this.options = {
      trustProxy: process.env.TRUST_PROXY === 'true',
      ...options
    };
    
    this.rateLimiter = new RedisRateLimiter(this.options.redisUrl);
    this.velocityChecker = new VelocityChecker(this.options.redisUrl);
  }

  /**
   * Creates a rate limiting middleware function
   */
  handler(): (req: NextApiRequest, res: NextApiResponse, next: () => void) => Promise<void> {
    return async (req: NextApiRequest, res: NextApiResponse, next: () => void) => {
      try {
        // Get the client IP
        const clientIp = this.getClientIp(req);
        
        // Get the request endpoint/path
        const endpoint = req.url || '/';
        
        // Get account ID if user is authenticated
        const accountId = this.getAccountId(req);
        
        // Record the request for velocity analysis
        await this.velocityChecker.recordRequest({
          ip: clientIp,
          accountId,
          endpoint,
          userAgent: req.headers['user-agent'],
          timestamp: Date.now()
        });
        
        // Perform velocity check
        const velocityAssessment = await this.velocityChecker.analyzeVelocity(clientIp, accountId);
        const graduatedResponse = await this.velocityChecker.applyGraduatedResponse(velocityAssessment);
        
        if (graduatedResponse === 'block') {
          this.sendRateLimitResponse(res, {
            allowed: false,
            remaining: 0,
            resetTime: Date.now() + 300000, // 5 minutes
            retryAfter: 300000
          }, 'Blocked due to high velocity');
          return;
        }
        
        // Get applicable rate limits
        const endpointLimits = LimitsConfig.getEndpointLimit(endpoint);
        const defaultLimits = LimitsConfig.getDefaultLimits();
        const combinedLimits = endpointLimits.length > 0 ? endpointLimits : defaultLimits;
        
        // Check if user is authenticated for enhanced limits
        const isAuthenticated = !!accountId;
        if (isAuthenticated) {
          const enhancedLimits = LimitsConfig.getAuthenticatedEnhancedLimits(endpoint);
          if (enhancedLimits.length > 0) {
            // Use enhanced limits for authenticated users
            combinedLimits.push(...enhancedLimits);
          }
        }
        
        // Get global limits
        const globalLimits = LimitsConfig.getGlobalLimits();
        
        // Prepare all rate limit keys to check
        const allLimitKeys = [];
        
        // Add endpoint-specific limits
        for (const rule of combinedLimits) {
          // Per-IP limits
          allLimitKeys.push({
            key: `${rule.keyPrefix}:${clientIp}`,
            rule
          });
          
          // Per-account limits (if authenticated)
          if (accountId) {
            allLimitKeys.push({
              key: `${rule.keyPrefix}:account:${accountId}`,
              rule
            });
          }
        }
        
        // Add global per-IP limits
        for (const rule of globalLimits.ip) {
          allLimitKeys.push({
            key: `${rule.keyPrefix}:${clientIp}`,
            rule
          });
        }
        
        // Add global per-account limits (if authenticated)
        if (accountId) {
          for (const rule of globalLimits.account) {
            allLimitKeys.push({
              key: `${rule.keyPrefix}:${accountId}`,
              rule
            });
          }
        }
        
        // Add global limits
        for (const rule of globalLimits.global) {
          allLimitKeys.push({
            key: rule.keyPrefix,
            rule
          });
        }
        
        // Check all applicable rate limits
        const rateLimitResult = await this.rateLimiter.consumeMultiple(allLimitKeys);
        
        if (!rateLimitResult.allowed) {
          this.sendRateLimitResponse(res, rateLimitResult);
          return;
        }
        
        // Set rate limit headers for the client
        this.setRateLimitHeaders(res, rateLimitResult);
        
        // Continue to next middleware/route handler
        next();
      } catch (error) {
        console.error('[RATE_LIMIT_MIDDLEWARE] Error applying rate limit:', error);
        // Continue without rate limiting in case of error to avoid blocking legitimate requests
        next();
      }
    };
  }

  /**
   * Alternative method to wrap Next.js API routes directly
   */
  wrap(handler: NextApiHandler): NextApiHandler {
    return async (req: NextApiRequest, res: NextApiResponse) => {
      // Create a simple next function to continue to the original handler
      const next = () => handler(req, res);
      
      // Apply the rate limiting middleware
      await this.handler()(req, res, next);
    };
  }

  /**
   * Gets the client IP address, considering proxy headers if configured
   */
  private getClientIp(req: NextApiRequest): string {
    if (this.options.trustProxy && req.headers['x-forwarded-for']) {
      const forwarded = req.headers['x-forwarded-for'];
      return Array.isArray(forwarded) ? forwarded[0] : forwarded.split(',')[0].trim();
    }
    
    return req.connection.remoteAddress || 
           req.socket.remoteAddress || 
           (req as any).connection.remoteAddress || 
           (req as any).headers['x-real-ip'] || 
           'unknown';
  }

  /**
   * Extracts account ID from request (implementation depends on your auth system)
   */
  private getAccountId(req: NextApiRequest): string | undefined {
    // This would depend on how you store user session information
    // Common approaches:
    // 1. From JWT token in Authorization header
    // 2. From session cookie
    // 3. From custom header after authentication middleware
    
    // For example, if using JWT:
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      try {
        const token = authHeader.substring(7);
        // In a real implementation, you would decode the JWT and extract the user ID
        // const decoded = jwt.verify(token, process.env.JWT_SECRET);
        // return decoded.userId;
      } catch (err) {
        // Invalid token
      }
    }
    
    // For now, returning undefined - implement according to your auth system
    return undefined;
  }

  /**
   * Sends rate limit response to client
   */
  private sendRateLimitResponse(
    res: NextApiResponse, 
    rateLimitResult: { remaining: number; resetTime: number; retryAfter?: number }, 
    message?: string
  ): void {
    const retryAfterSeconds = Math.ceil((rateLimitResult.retryAfter || 0) / 1000);
    
    res.status(429).json({
      error: 'Too Many Requests',
      message: message || 'Rate limit exceeded',
      retryAfter: retryAfterSeconds,
      resetTime: new Date(rateLimitResult.resetTime).toISOString()
    });
  }

  /**
   * Sets rate limit headers on the response
   */
  private setRateLimitHeaders(res: NextApiResponse, rateLimitResult: { remaining: number; resetTime: number }): void {
    const resetTimeUnixSec = Math.ceil(rateLimitResult.resetTime / 1000);
    const timeUntilResetSec = Math.ceil((rateLimitResult.resetTime - Date.now()) / 1000);
    
    res.setHeader('X-RateLimit-Limit', 'Application-specific limit');
    res.setHeader('X-RateLimit-Remaining', Math.max(0, rateLimitResult.remaining).toString());
    res.setHeader('X-RateLimit-Reset', resetTimeUnixSec.toString());
    
    if (timeUntilResetSec > 0) {
      res.setHeader('Retry-After', timeUntilResetSec.toString());
    }
  }
}

// Export a default instance for easy usage
export const rateLimitMiddleware = new RateLimitMiddleware();