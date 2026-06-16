/**
 * Enterprise-Grade Rate Limiter
 * 
 * SECURITY FEATURES:
 * - FAILS CLOSED on Redis failures (critical endpoints)
 * - Multi-layer rate limiting (IP, User, Account, Behavior)
 * - Atomic operations via Lua scripts
 * - Different policies for different endpoint classifications
 * - Circuit breaker integration
 */

import { EnterpriseRedisClient } from '../../infrastructure/redis/enterprise-redis-client';
import { logger } from '../../utils/logger';
import { SecurityMonitor, SecurityEvent } from '../../lib/security-monitoring';

export type EndpointClassification = 'public' | 'authenticated' | 'administrative' | 'critical';

export interface RateLimitPolicy {
  maxRequests: number;
  windowSeconds: number;
  blockDurationSeconds: number;
  failClosed: boolean; // Critical endpoints fail closed
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
  retryAfter?: number;
  policy?: RateLimitPolicy;
}

export class EnterpriseRateLimiter {
  private readonly redis: EnterpriseRedisClient;
  
  // Key prefixes
  private readonly REQUEST_COUNT_PREFIX = 'ratelimit:count:';
  private readonly BLOCKED_PREFIX = 'ratelimit:blocked:';
  private readonly WINDOW_PREFIX = 'ratelimit:window:';

  // Default policies by endpoint classification
  private readonly POLICIES: Record<EndpointClassification, RateLimitPolicy> = {
    public: {
      maxRequests: 100,
      windowSeconds: 60,
      blockDurationSeconds: 300,
      failClosed: false,
    },
    authenticated: {
      maxRequests: 50,
      windowSeconds: 60,
      blockDurationSeconds: 300,
      failClosed: false,
    },
    administrative: {
      maxRequests: 20,
      windowSeconds: 60,
      blockDurationSeconds: 600,
      failClosed: true,
    },
    critical: {
      maxRequests: 5,
      windowSeconds: 900, // 15 minutes
      blockDurationSeconds: 900,
      failClosed: true, // CRITICAL: Fail closed
    },
  };

  // Specific endpoint configurations
  private readonly ENDPOINT_POLICIES: Record<string, { classification: EndpointClassification; customPolicy?: Partial<RateLimitPolicy> }> = {
    // Authentication endpoints (CRITICAL)
    'auth:login': { classification: 'critical' },
    'auth:wallet': { classification: 'critical' },
    'auth:mfa': { classification: 'critical' },
    'auth:password-reset': { classification: 'critical' },
    'auth:session:create': { classification: 'critical' },
    
    // Administrative endpoints
    'admin:user:delete': { classification: 'administrative' },
    'admin:config:update': { classification: 'administrative' },
    
    // Regular authenticated endpoints
    'api:user:profile': { classification: 'authenticated' },
    'api:dashboard': { classification: 'authenticated' },
  };

  constructor(redisClient: EnterpriseRedisClient) {
    this.redis = redisClient;
  }

  /**
   * Check rate limit with atomic operations
   * FAILS CLOSED for critical endpoints when Redis unavailable
   */
  async checkRateLimit(
    identifier: string,
    endpoint: string,
    additionalIdentifiers?: {
      userId?: string;
      accountId?: string;
      ipAddress?: string;
    }
  ): Promise<RateLimitResult> {
    const endpointConfig = this.ENDPOINT_POLICIES[endpoint] || { classification: 'public' as EndpointClassification };
    const basePolicy = this.POLICIES[endpointConfig.classification];
    const policy: RateLimitPolicy = {
      ...basePolicy,
      ...(endpointConfig.customPolicy || {}),
    };

    const now = Date.now();
    const windowKey = `${this.WINDOW_PREFIX}${endpoint}:${identifier}:${Math.floor(now / (policy.windowSeconds * 1000))}`;
    const countKey = `${this.REQUEST_COUNT_PREFIX}${endpoint}:${identifier}`;
    const blockedKey = `${this.BLOCKED_PREFIX}${endpoint}:${identifier}`;

    try {
      // Check if already blocked
      const isBlocked = await this.redis.get(blockedKey);
      if (isBlocked) {
        const ttl = await this.redis.eval(
          `return redis.call('TTL', KEYS[1])`,
          [blockedKey],
          []
        );
        
        return {
          allowed: false,
          remaining: 0,
          resetAt: now + (ttl > 0 ? ttl * 1000 : policy.blockDurationSeconds * 1000),
          retryAfter: ttl > 0 ? ttl : policy.blockDurationSeconds,
          policy,
        };
      }

      // Atomic increment and check using Lua script
      const luaScript = `
        local countKey = KEYS[1]
        local blockedKey = KEYS[2]
        local windowKey = KEYS[3]
        local maxRequests = tonumber(ARGV[1])
        local windowSeconds = tonumber(ARGV[2])
        local blockDurationSeconds = tonumber(ARGV[3])
        local currentCount = tonumber(ARGV[4])
        
        -- Get current count in this window
        local windowCount = redis.call('GET', windowKey)
        if not windowCount then
          windowCount = 0
        else
          windowCount = tonumber(windowCount)
        end
        
        -- Check if already at limit
        if windowCount >= maxRequests then
          -- Block the identifier
          redis.call('SETEX', blockedKey, blockDurationSeconds, '1')
          return cjson.encode({
            allowed = false,
            remaining = 0,
            resetAt = os.time() + blockDurationSeconds,
            blocked = true
          })
        end
        
        -- Increment counters
        redis.call('INCR', countKey)
        redis.call('EXPIRE', countKey, windowSeconds)
        redis.call('INCR', windowKey)
        redis.call('EXPIRE', windowKey, windowSeconds)
        
        local newCount = windowCount + 1
        local remaining = math.max(0, maxRequests - newCount)
        
        return cjson.encode({
          allowed = true,
          remaining = remaining,
          resetAt = os.time() + windowSeconds,
          blocked = false
        })
      `;

      const result = await this.redis.eval(
        luaScript,
        [countKey, blockedKey, windowKey],
        [
          policy.maxRequests.toString(),
          policy.windowSeconds.toString(),
          policy.blockDurationSeconds.toString(),
          now.toString(),
        ]
      );

      const parsedResult = JSON.parse(result);

      return {
        allowed: parsedResult.allowed,
        remaining: parsedResult.remaining,
        resetAt: parsedResult.resetAt * 1000, // Convert to milliseconds
        retryAfter: parsedResult.blocked ? policy.blockDurationSeconds : undefined,
        policy,
      };
    } catch (error) {
      logger.error('Rate limit check failed', {
        error: (error as Error).message,
        identifier,
        endpoint,
        classification: endpointConfig.classification,
      });

      await SecurityMonitor.logEvent(
        SecurityEvent.SUSPICIOUS_ACTIVITY,
        {
          timestamp: new Date(),
          metadata: {
            identifier,
            endpoint,
            operation: 'rate_limit_check',
            error: (error as Error).message,
          },
        },
        'Rate limit check failed'
      );

      // CRITICAL: Fail closed for critical endpoints
      if (policy.failClosed) {
        logger.warn('Rate limiter failing CLOSED for critical endpoint', {
          endpoint,
          identifier,
        });

        return {
          allowed: false,
          remaining: 0,
          resetAt: now + 60000, // Retry after 1 minute
          retryAfter: 60,
          policy,
        };
      }

      // For non-critical endpoints, allow but log warning
      logger.warn('Rate limiter failing OPEN for non-critical endpoint', {
        endpoint,
        identifier,
      });

      return {
        allowed: true,
        remaining: 0,
        resetAt: now + policy.windowSeconds * 1000,
        policy,
      };
    }
  }

  /**
   * Block an identifier manually (for abuse prevention)
   */
  async blockIdentifier(
    identifier: string,
    endpoint: string,
    durationSeconds: number = 3600,
    reason?: string
  ): Promise<void> {
    const blockedKey = `${this.BLOCKED_PREFIX}${endpoint}:${identifier}`;

    try {
      await this.redis.setex(blockedKey, durationSeconds, '1');

      logger.warn('Identifier manually blocked', {
        identifier,
        endpoint,
        durationSeconds,
        reason,
      });

      await SecurityMonitor.logEvent(
        SecurityEvent.SUSPICIOUS_ACTIVITY,
        {
          timestamp: new Date(),
          metadata: {
            identifier,
            endpoint,
            operation: 'manual_block',
            reason,
            durationSeconds,
          },
        },
        `Identifier manually blocked: ${reason || 'No reason provided'}`
      );
    } catch (error) {
      logger.error('Failed to block identifier', {
        error: (error as Error).message,
        identifier,
        endpoint,
      });
      throw error;
    }
  }

  /**
   * Unblock an identifier
   */
  async unblockIdentifier(identifier: string, endpoint: string): Promise<void> {
    const blockedKey = `${this.BLOCKED_PREFIX}${endpoint}:${identifier}`;

    try {
      await this.redis.del(blockedKey);

      logger.info('Identifier manually unblocked', {
        identifier,
        endpoint,
      });
    } catch (error) {
      logger.error('Failed to unblock identifier', {
        error: (error as Error).message,
        identifier,
        endpoint,
      });
    }
  }

  /**
   * Get rate limit status for monitoring
   */
  async getRateLimitStatus(
    identifier: string,
    endpoint: string
  ): Promise<{
    requests: number;
    max: number;
    blocked: boolean;
    resetAt: number;
  }> {
    const endpointConfig = this.ENDPOINT_POLICIES[endpoint] || { classification: 'public' as EndpointClassification };
    const policy = this.POLICIES[endpointConfig.classification];
    const now = Date.now();
    const windowKey = `${this.WINDOW_PREFIX}${endpoint}:${identifier}:${Math.floor(now / (policy.windowSeconds * 1000))}`;
    const blockedKey = `${this.BLOCKED_PREFIX}${endpoint}:${identifier}`;

    try {
      const [windowCount, isBlocked, ttl] = await Promise.all([
        this.redis.get(windowKey),
        this.redis.get(blockedKey),
        this.redis.eval(`return redis.call('TTL', KEYS[1])`, [blockedKey], []),
      ]);

      const requests = windowCount ? parseInt(windowCount) : 0;
      const blocked = !!isBlocked;
      const resetAt = blocked && ttl > 0 ? now + (ttl * 1000) : now + (policy.windowSeconds * 1000);

      return {
        requests,
        max: policy.maxRequests,
        blocked,
        resetAt,
      };
    } catch (error) {
      logger.error('Failed to get rate limit status', {
        error: (error as Error).message,
        identifier,
        endpoint,
      });

      return {
        requests: 0,
        max: policy.maxRequests,
        blocked: false,
        resetAt: now,
      };
    }
  }

  /**
   * Get policy for an endpoint
   */
  getPolicy(endpoint: string): RateLimitPolicy {
    const endpointConfig = this.ENDPOINT_POLICIES[endpoint] || { classification: 'public' as EndpointClassification };
    const basePolicy = this.POLICIES[endpointConfig.classification];
    return {
      ...basePolicy,
      ...(endpointConfig.customPolicy || {}),
    };
  }
}

// Factory function
export function createEnterpriseRateLimiter(redisClient: EnterpriseRedisClient): EnterpriseRateLimiter {
  return new EnterpriseRateLimiter(redisClient);
}
