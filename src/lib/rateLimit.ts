import { NextRequest } from 'next/server';
import { Redis } from '@upstash/redis';
import { logger } from './logger';
import { SecurityMonitor } from './security-monitoring';

// تنظیمات Rate Limit برای endpoint های مختلف
export const RATE_LIMITS = {
  login: {
    max: 5,
    window: 15 * 60 * 1000, // 15 دقیقه
    message: 'Too many login attempts. Please try again in 15 minutes.'
  },
  register: {
    max: 3,
    window: 60 * 60 * 1000, // 1 ساعت
    message: 'Too many registration attempts. Please try again in 1 hour.'
  },
  walletAuth: {
    max: 10,
    window: 15 * 60 * 1000, // 15 دقیقه
    message: 'Too many wallet authentication attempts. Please try again later.'
  },
  api: {
    max: 100,
    window: 60 * 60 * 1000, // 1 ساعت
    message: 'Rate limit exceeded. Please try again later.'
  },
  passwordReset: {
    max: 3,
    window: 60 * 60 * 1000, // 1 ساعت
    message: 'Too many password reset attempts. Please try again in 1 hour.'
  },
  nonce: {
    max: 5,
    window: 5 * 60 * 1000, // 5 minutes
    message: 'Too many nonce requests. Please try again later.'
  },
  refresh: {
    max: 10,
    window: 5 * 60 * 1000, // 5 minutes
    message: 'Too many token refresh attempts. Please try again later.'
  }
} as const;

type RateLimitType = keyof typeof RATE_LIMITS;

interface RateLimitRecord {
  timestamps: number[];
  blocked: boolean;
  blockedUntil?: number;
}

// Redis for rate limiting (production ready)
const redis = Redis.fromEnv();
const RATE_LIMIT_PREFIX = 'rate_limit:';
const BLOCKED_PREFIX = 'rate_limit:blocked:';

// ذخیره‌سازی request ها (در production از Redis استفاده کنید)
const requestStore = new Map<string, RateLimitRecord>();

// پاکسازی خودکار record های قدیمی
const CLEANUP_INTERVAL = 5 * 60 * 1000; // هر 5 دقیقه

function startCleanup() {
  setInterval(() => {
    const now = Date.now();
    const keysToDelete: string[] = [];

    for (const [key, record] of requestStore.entries()) {
      // حذف record های خیلی قدیمی
      const oldestTimestamp = Math.min(...record.timestamps);
      const maxWindow = Math.max(...Object.values(RATE_LIMITS).map(r => r.window));

      if (now - oldestTimestamp > maxWindow * 2) {
        keysToDelete.push(key);
      }
    }

    keysToDelete.forEach(key => requestStore.delete(key));

    if (keysToDelete.length > 0) {
      logger.info(`Cleaned up ${keysToDelete.length} old rate limit records`);
    }
  }, CLEANUP_INTERVAL);
}

if (typeof window === 'undefined') {
  startCleanup();
}

/**
 * استخراج identifier از request (IP یا User ID)
 */
export function getIdentifier(request: NextRequest, userId?: string): string {
  if (userId) {
    return `user:${userId}`;
  }

  // IP address with additional security measures
  const forwarded = request.headers.get('x-forwarded-for');
  const realIp = request.headers.get('x-real-ip');
  const cloudflareIp = request.headers.get('cf-connecting-ip');
  
  const ip = forwarded ? forwarded.split(',')[0]?.trim() : 
             realIp ? realIp.trim() :
             cloudflareIp ? cloudflareIp.trim() :
             'unknown';

  // Sanitize IP to prevent injection
  const sanitizedIp = ip.replace(/[^0-9a-fA-F:.]/g, '');
  
  return `ip:${sanitizedIp}`;
}

/**
 * Multi-layered rate limiting with IP-based, account-based, and behavior-based protection
 */
export async function checkRateLimit(
  identifier: string,
  type: RateLimitType,
  additionalIdentifiers?: { userId?: string; accountId?: string; behaviorPattern?: string }
): Promise<{
  allowed: boolean;
  remaining: number;
  resetAt: number;
  message?: string;
}> {
  const config = RATE_LIMITS[type];
  const now = Date.now();
  
  // Multiple rate limit checks to prevent bypass
  const checks = [];
  
  // Original identifier check
  const baseKey = `${RATE_LIMIT_PREFIX}${type}:${identifier}`;
  const baseBlockedKey = `${BLOCKED_PREFIX}${type}:${identifier}`;
  checks.push({ key: baseKey, blockedKey: baseBlockedKey, identifier });

  // Account-based rate limiting if available
  if (additionalIdentifiers?.userId) {
    const userKey = `${RATE_LIMIT_PREFIX}${type}:user:${additionalIdentifiers.userId}`;
    const userBlockedKey = `${BLOCKED_PREFIX}${type}:user:${additionalIdentifiers.userId}`;
    checks.push({ key: userKey, blockedKey: userBlockedKey, identifier: `user:${additionalIdentifiers.userId}` });
  }
  
  // Account-based rate limiting if available
  if (additionalIdentifiers?.accountId) {
    const accountKey = `${RATE_LIMIT_PREFIX}${type}:account:${additionalIdentifiers.accountId}`;
    const accountBlockedKey = `${BLOCKED_PREFIX}${type}:account:${additionalIdentifiers.accountId}`;
    checks.push({ key: accountKey, blockedKey: accountBlockedKey, identifier: `account:${additionalIdentifiers.accountId}` });
  }
  
  // Behavior pattern-based rate limiting
  if (additionalIdentifiers?.behaviorPattern) {
    const behaviorKey = `${RATE_LIMIT_PREFIX}${type}:behavior:${additionalIdentifiers.behaviorPattern}`;
    const behaviorBlockedKey = `${BLOCKED_PREFIX}${type}:behavior:${additionalIdentifiers.behaviorPattern}`;
    checks.push({ key: behaviorKey, blockedKey: behaviorBlockedKey, identifier: `behavior:${additionalIdentifiers.behaviorPattern}` });
  }
  
  // Check if any identifier is blocked
  for (const check of checks) {
    if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
      try {
        const isBlocked = await redis.get(check.blockedKey);
        if (isBlocked) {
          const blockUntil = await redis.ttl(check.blockedKey);
          const resetAt = now + (blockUntil * 1000);
          
          logger.warn('Rate limit blocked request', { 
            identifier: check.identifier, 
            type, 
            resetAt: new Date(resetAt).toISOString() 
          });
          
          return {
            allowed: false,
            remaining: 0,
            resetAt,
            message: config.message
          };
        }
      } catch (error) {
        logger.critical('Redis error in rate limit check', { 
          error: (error as Error).message,
          identifier: check.identifier,
          type
        });
        
        // Fail closed - return 503 error
        throw new Error('Service temporarily unavailable due to Redis connectivity issues');
      }
    }
  }

  // Perform all rate limit checks
  let lowestRemaining = config.max;
  let earliestResetAt = now + config.window;
  
  for (const check of checks) {
    // Get or create record
    let record: RateLimitRecord | null = null;

    if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
      try {
        const redisData = await redis.get(check.key);
        if (redisData) {
          record = redisData as RateLimitRecord;
        }
      } catch (error) {
        logger.critical('Redis get error', { error: (error as Error).message });
        // Fail closed - throw error
        throw new Error('Service temporarily unavailable due to Redis connectivity issues');
      }
    }

    if (!record) {
      record = {
        timestamps: [],
        blocked: false
      };
    }

    // Filter timestamps within window
    const validTimestamps = record.timestamps.filter(
      timestamp => now - timestamp < config.window
    );

    // Check if this specific identifier has exceeded limits
    if (validTimestamps.length >= config.max) {
      // Block this specific identifier
      const blockDuration = config.window;
      record.blocked = true;
      
      if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
        try {
          // Store block status in Redis
          await redis.setex(check.blockedKey, Math.floor(blockDuration / 1000), '1');
          // Clean up the request count
          await redis.del(check.key);
        } catch (error) {
          logger.error('Redis set error in rate limiting', { error: (error as Error).message });
        }
      } else {
        // Fallback to in-memory storage
        record.blockedUntil = now + blockDuration;
        requestStore.set(check.key, record);
      }

      const resetAt = now + blockDuration;
      
      logger.warn('Rate limit exceeded', { 
        identifier: check.identifier, 
        type, 
        attempts: validTimestamps.length,
        resetAt: new Date(resetAt).toISOString() 
      });

      return {
        allowed: false,
        remaining: 0,
        resetAt,
        message: config.message
      };
    }
    
    // Track lowest remaining count across all checks
    const remaining = Math.max(0, config.max - validTimestamps.length);
    if (remaining < lowestRemaining) {
      lowestRemaining = remaining;
    }
  }

  // If we get here, all checks passed - update all relevant counters
  for (const check of checks) {
    // Get or create record again to make sure we have fresh data
    let record: RateLimitRecord | null = null;

    if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
      try {
        const redisData = await redis.get(check.key);
        if (redisData) {
          record = redisData as RateLimitRecord;
        }
      } catch (error) {
        logger.critical('Redis get error', { error: (error as Error).message });
        // Fail closed - throw error
        throw new Error('Service temporarily unavailable due to Redis connectivity issues');
      }
    }

    if (!record) {
      record = {
        timestamps: [],
        blocked: false
      };
    }

    // Add current timestamp to all relevant counters
    const validTimestamps = record.timestamps.filter(
      timestamp => now - timestamp < config.window
    );
    validTimestamps.push(now);
    record.timestamps = validTimestamps;

    // Store in Redis or memory
    if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
      try {
        await redis.setex(check.key, Math.floor(config.window / 1000), record);
      } catch (error) {
        logger.critical('Redis set error', { error: (error as Error).message });
        // Fail closed - throw error
        throw new Error('Service temporarily unavailable due to Redis connectivity issues');
      }
    } else {
      requestStore.set(check.key, record);
    }
  }

  const resetAt = now + config.window;

  logger.debug('Rate limit check passed', { 
    identifier, 
    type, 
    remaining: lowestRemaining,
    attempts: checks.map(check => {
      let record: RateLimitRecord | null = null;
      if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
        // This is just for logging, we won't actually fetch again
        return 'N/A';
      } else {
        const stored = requestStore.get(baseKey);
        return stored ? stored.timestamps.length : 0;
      }
    }),
    max: config.max
  });

  return {
    allowed: true,
    remaining: lowestRemaining,
    resetAt
  };
}

/**
 * Middleware برای Rate Limiting
 */
export function rateLimitMiddleware(type: RateLimitType) {
  return async (request: NextRequest, userId?: string) => {
    const identifier = getIdentifier(request, userId);
    const result = await checkRateLimit(identifier, type);

    return result;
  };
}

/**
 * ریست کردن Rate Limit برای یک identifier
 */
export async function resetRateLimit(identifier: string, type: RateLimitType): Promise<void> {
  const key = `${RATE_LIMIT_PREFIX}${type}:${identifier}`;
  const blockedKey = `${BLOCKED_PREFIX}${type}:${identifier}`;
  
  if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
    try {
      await redis.del(key);
      await redis.del(blockedKey);
      logger.info('Rate limit reset', { identifier, type });
    } catch (error) {
      logger.error('Redis delete error in rate limit reset', { error: (error as Error).message });
      requestStore.delete(key);
    }
  } else {
    requestStore.delete(key);
    logger.info('Rate limit reset', { identifier, type });
  }
}

/**
 * Block کردن دستی یک identifier
 */
export async function blockIdentifier(
  identifier: string,
  type: RateLimitType,
  durationMs?: number
): Promise<void> {
  const config = RATE_LIMITS[type];
  const blockedKey = `${BLOCKED_PREFIX}${type}:${identifier}`;
  const duration = durationMs || config.window;

  if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
    try {
      await redis.setex(blockedKey, Math.floor(duration / 1000), '1');
      logger.warn('Identifier manually blocked', { 
        identifier, 
        type, 
        duration: `${duration}ms`,
        until: new Date(Date.now() + duration).toISOString() 
      });
    } catch (error) {
      logger.error('Redis set error in manual block', { error: (error as Error).message });
    }
  } else {
    const key = `${RATE_LIMIT_PREFIX}${type}:${identifier}`;
    const record: RateLimitRecord = {
      timestamps: [],
      blocked: true,
      blockedUntil: Date.now() + duration
    };
    requestStore.set(key, record);
    logger.warn('Identifier manually blocked (in-memory)', { 
      identifier, 
      type,
      duration: `${duration}ms` 
    });
  }
}

/**
 * Unblock کردن یک identifier
 */
export async function unblockIdentifier(identifier: string, type: RateLimitType): Promise<void> {
  const blockedKey = `${BLOCKED_PREFIX}${type}:${identifier}`;
  
  if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
    try {
      await redis.del(blockedKey);
      logger.info('Identifier manually unblocked', { identifier, type });
    } catch (error) {
      logger.error('Redis delete error in manual unblock', { error: (error as Error).message });
    }
  } else {
    const key = `${RATE_LIMIT_PREFIX}${type}:${identifier}`;
    const record = requestStore.get(key);
    if (record) {
      record.blocked = false;
      record.blockedUntil = undefined;
    }
    logger.info('Identifier manually unblocked', { identifier, type });
  }
}

/**
 * دریافت وضعیت Rate Limit
 */
export async function getRateLimitStatus(identifier: string, type: RateLimitType) {
  const key = `${RATE_LIMIT_PREFIX}${type}:${identifier}`;
  const blockedKey = `${BLOCKED_PREFIX}${type}:${identifier}`;
  const config = RATE_LIMITS[type];
  const now = Date.now();

  let record: RateLimitRecord | null = null;

  if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
    try {
      const redisData = await redis.get(key);
      if (redisData) {
        record = redisData as RateLimitRecord;
      }
    } catch (error) {
      logger.error('Redis get error in status check', { error: (error as Error).message });
    }
  }

  if (!record) {
    record = requestStore.get(key) || {
      timestamps: [],
      blocked: false
    };
  }

  // Check if blocked
  let isBlocked = record.blocked;
  if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
    try {
      const blocked = await redis.get(blockedKey);
      isBlocked = !!blocked;
    } catch (error) {
      logger.error('Redis get error in blocked check', { error: (error as Error).message });
    }
  }

  const validTimestamps = record.timestamps.filter(
    timestamp => now - timestamp < config.window
  );

  const oldestTimestamp = validTimestamps[0];
  let calculatedResetAt = oldestTimestamp ? oldestTimestamp + config.window : null;

  if (isBlocked) {
    if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
      try {
        const ttl = await redis.ttl(blockedKey);
        calculatedResetAt = now + (ttl * 1000);
      } catch (error) {
        logger.error('Redis TTL error', { error: (error as Error).message });
      }
    } else if (record.blockedUntil) {
      calculatedResetAt = record.blockedUntil;
    }
  }

  return {
    requests: validTimestamps.length,
    max: config.max,
    blocked: isBlocked,
    resetAt: calculatedResetAt
  };
}

/**
 * آمار کلی Rate Limit
 */
export async function getRateLimitStats() {
  const stats: Record<string, { total: number; blocked: number; active: number }> = {};

  // This would require scanning Redis keys in production
  // For now, we'll just return in-memory stats
  for (const [key, record] of requestStore.entries()) {
    const parts = key.split(':');
    const type = parts[1] as RateLimitType;
    
    if (!type || !RATE_LIMITS[type]) continue;
    
    if (!stats[type]) {
      stats[type] = {
        total: 0,
        blocked: 0,
        active: 0
      };
    }

    stats[type].total++;
    
    if (record.blocked) {
      stats[type].blocked++;
    } else if (record.timestamps.length > 0) {
      stats[type].active++;
    }
  }

  logger.info('Rate limit stats', { stats });
  return stats;
}