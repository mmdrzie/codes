import { Redis } from 'ioredis';
import { RateLimitRule } from './limits-config';

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetTime: number; // Unix timestamp in milliseconds
  retryAfter?: number; // Milliseconds to wait before retry
}

export class RedisRateLimiter {
  private redis: Redis;

  constructor(redisUrl?: string) {
    this.redis = new Redis(redisUrl || process.env.REDIS_URL || 'redis://localhost:6379');
  }

  /**
   * Consumes a request against the rate limit
   */
  async consume(
    key: string,
    rule: RateLimitRule
  ): Promise<RateLimitResult> {
    const currentTimestamp = Date.now();
    const windowStart = currentTimestamp - rule.windowMs;
    
    // Lua script for atomic rate limit check and increment
    const luaScript = `
      local key = KEYS[1]
      local window_ms = tonumber(ARGV[1])
      local max_requests = tonumber(ARGV[2])
      local current_timestamp = tonumber(ARGV[3])
      local window_start = current_timestamp - window_ms
      
      -- Remove expired entries
      redis.call('ZREMRANGEBYSCORE', key, 0, window_start)
      
      -- Get current count
      local current_count = redis.call('ZCARD', key)
      
      -- Check if limit is exceeded
      if current_count >= max_requests then
        -- Return current count and reset time
        local ttl = redis.call('TTL', key)
        local reset_time = current_timestamp + (ttl > 0 and ttl * 1000 or window_ms)
        return {0, current_count, reset_time}
      end
      
      -- Add current request timestamp
      redis.call('ZADD', key, current_timestamp, current_timestamp .. ':' .. math.random())
      
      -- Set expiration to clean up automatically
      redis.call('EXPIRE', key, math.ceil(window_ms / 1000))
      
      -- Calculate remaining requests
      local remaining = max_requests - current_count - 1
      local reset_time = current_timestamp + window_ms
      
      return {1, remaining, reset_time}
    `;
    
    try {
      const result = await this.redis.eval(
        luaScript,
        1,
        key,
        rule.windowMs.toString(),
        rule.maxRequests.toString(),
        currentTimestamp.toString()
      ) as [number, number, number]; // [allowed, remaining, reset_time]
      
      const [allowedFlag, remaining, resetTime] = result;
      
      const allowed = allowedFlag === 1;
      
      if (!allowed) {
        return {
          allowed: false,
          remaining: 0,
          resetTime,
          retryAfter: resetTime - currentTimestamp
        };
      }
      
      return {
        allowed: true,
        remaining,
        resetTime
      };
    } catch (error) {
      console.error(`[RATE_LIMIT] Error consuming rate limit for key ${key}:`, error);
      // Fail open in case of Redis error to avoid blocking legitimate requests
      return {
        allowed: true,
        remaining: rule.maxRequests,
        resetTime: currentTimestamp + rule.windowMs
      };
    }
  }

  /**
   * Checks rate limit without consuming a request
   */
  async checkOnly(
    key: string,
    rule: RateLimitRule
  ): Promise<RateLimitResult> {
    const currentTimestamp = Date.now();
    const windowStart = currentTimestamp - rule.windowMs;
    
    // Lua script to check rate limit without incrementing
    const luaScript = `
      local key = KEYS[1]
      local window_ms = tonumber(ARGV[1])
      local max_requests = tonumber(ARGV[2])
      local current_timestamp = tonumber(ARGV[3])
      local window_start = current_timestamp - window_ms
      
      -- Remove expired entries
      redis.call('ZREMRANGEBYSCORE', key, 0, window_start)
      
      -- Get current count
      local current_count = redis.call('ZCARD', key)
      
      -- Check if limit is exceeded
      if current_count >= max_requests then
        -- Return current count and reset time
        local ttl = redis.call('TTL', key)
        local reset_time = current_timestamp + (ttl > 0 and ttl * 1000 or window_ms)
        return {0, current_count, reset_time}
      end
      
      -- Calculate remaining requests
      local remaining = max_requests - current_count
      local reset_time = current_timestamp + window_ms
      
      return {1, remaining, reset_time}
    `;
    
    try {
      const result = await this.redis.eval(
        luaScript,
        1,
        key,
        rule.windowMs.toString(),
        rule.maxRequests.toString(),
        currentTimestamp.toString()
      ) as [number, number, number]; // [allowed, remaining, reset_time]
      
      const [allowedFlag, remaining, resetTime] = result;
      
      const allowed = allowedFlag === 1;
      
      if (!allowed) {
        return {
          allowed: false,
          remaining: 0,
          resetTime,
          retryAfter: resetTime - currentTimestamp
        };
      }
      
      return {
        allowed: true,
        remaining,
        resetTime
      };
    } catch (error) {
      console.error(`[RATE_LIMIT] Error checking rate limit for key ${key}:`, error);
      // Fail open in case of Redis error
      return {
        allowed: true,
        remaining: rule.maxRequests,
        resetTime: currentTimestamp + rule.windowMs
      };
    }
  }

  /**
   * Applies multiple rate limits and returns the most restrictive result
   */
  async consumeMultiple(
    keys: { key: string; rule: RateLimitRule }[]
  ): Promise<RateLimitResult> {
    if (keys.length === 0) {
      return {
        allowed: true,
        remaining: Infinity,
        resetTime: Date.now() + 60000 // 1 minute from now
      };
    }

    const results = await Promise.all(
      keys.map(({ key, rule }) => this.consume(key, rule))
    );

    // Find the most restrictive result (the one that would block the request)
    let mostRestrictive: RateLimitResult = results[0];

    for (const result of results) {
      if (!result.allowed) {
        // If any limit is exceeded, the overall result is not allowed
        // Choose the result with the longest retry time
        if (!mostRestrictive.allowed) {
          if ((result.retryAfter || 0) > (mostRestrictive.retryAfter || 0)) {
            mostRestrictive = result;
          }
        } else {
          mostRestrictive = result;
        }
      } else if (result.remaining < mostRestrictive.remaining) {
        // If all are allowed, choose the one with fewer remaining requests
        mostRestrictive = result;
      }
    }

    return mostRestrictive;
  }

  /**
   * Resets rate limit for a specific key
   */
  async reset(key: string): Promise<boolean> {
    try {
      await this.redis.del(key);
      return true;
    } catch (error) {
      console.error(`[RATE_LIMIT] Error resetting rate limit for key ${key}:`, error);
      return false;
    }
  }

  /**
   * Gets the current count for a rate limit key
   */
  async getCurrentCount(key: string, windowMs: number): Promise<number> {
    const currentTimestamp = Date.now();
    const windowStart = currentTimestamp - windowMs;
    
    try {
      // Clean up expired entries and get count atomically
      const luaScript = `
        local key = KEYS[1]
        local window_start = tonumber(ARGV[1])
        
        -- Remove expired entries
        redis.call('ZREMRANGEBYSCORE', key, 0, window_start)
        
        -- Get current count
        return redis.call('ZCARD', key)
      `;
      
      const count = await this.redis.eval(
        luaScript,
        1,
        key,
        windowStart.toString()
      ) as number;
      
      return count;
    } catch (error) {
      console.error(`[RATE_LIMIT] Error getting current count for key ${key}:`, error);
      return 0;
    }
  }
}