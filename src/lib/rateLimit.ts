import { NextRequest } from 'next/server';

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
  }
} as const;

type RateLimitType = keyof typeof RATE_LIMITS;

interface RateLimitRecord {
  timestamps: number[];
  blocked: boolean;
  blockedUntil?: number;
}

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
      console.log(`Cleaned up ${keysToDelete.length} old rate limit records`);
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

  // IP address
  const forwarded = request.headers.get('x-forwarded-for');
  const ip = forwarded ? forwarded.split(',')[0] : 
             request.headers.get('x-real-ip') || 
             'unknown';

  return `ip:${ip}`;
}

/**
 * بررسی Rate Limit
 */
export function checkRateLimit(
  identifier: string,
  type: RateLimitType
): {
  allowed: boolean;
  remaining: number;
  resetAt: number;
  message?: string;
} {
  const config = RATE_LIMITS[type];
  const now = Date.now();
  const key = `${type}:${identifier}`;

  // دریافت یا ایجاد record
  let record = requestStore.get(key);

  if (!record) {
    record = {
      timestamps: [],
      blocked: false
    };
  }

  // بررسی block
  if (record.blocked && record.blockedUntil) {
    if (now < record.blockedUntil) {
      return {
        allowed: false,
        remaining: 0,
        resetAt: record.blockedUntil,
        message: config.message
      };
    } else {
      // رفع block
      record.blocked = false;
      record.blockedUntil = undefined;
      record.timestamps = [];
    }
  }

  // فیلتر کردن timestamp های داخل window
  const validTimestamps = record.timestamps.filter(
    timestamp => now - timestamp < config.window
  );

  // بررسی محدودیت
  if (validTimestamps.length >= config.max) {
    // مسدود کردن identifier
    record.blocked = true;
    record.blockedUntil = now + config.window;
    requestStore.set(key, record);

    return {
      allowed: false,
      remaining: 0,
      resetAt: record.blockedUntil,
      message: config.message
    };
  }

  // اضافه کردن timestamp جدید
  validTimestamps.push(now);
  record.timestamps = validTimestamps;
  requestStore.set(key, record);

  const oldestTimestamp = validTimestamps[0];
  const resetAt = oldestTimestamp ? oldestTimestamp + config.window : now + config.window;

  return {
    allowed: true,
    remaining: config.max - validTimestamps.length,
    resetAt
  };
}

/**
 * Middleware برای Rate Limiting
 */
export function rateLimitMiddleware(type: RateLimitType) {
  return async (request: NextRequest, userId?: string) => {
    const identifier = getIdentifier(request, userId);
    const result = checkRateLimit(identifier, type);

    return result;
  };
}

/**
 * ریست کردن Rate Limit برای یک identifier
 */
export function resetRateLimit(identifier: string, type: RateLimitType): void {
  const key = `${type}:${identifier}`;
  requestStore.delete(key);
  console.log(`Rate limit reset for ${key}`);
}

/**
 * Block کردن دستی یک identifier
 */
export function blockIdentifier(
  identifier: string,
  type: RateLimitType,
  durationMs?: number
): void {
  const config = RATE_LIMITS[type];
  const key = `${type}:${identifier}`;
  const now = Date.now();

  const record: RateLimitRecord = {
    timestamps: [],
    blocked: true,
    blockedUntil: now + (durationMs || config.window)
  };

  requestStore.set(key, record);
  
  const blockedUntil = record.blockedUntil;
  if (blockedUntil) {
    console.log(`Identifier blocked: ${key} until ${new Date(blockedUntil).toISOString()}`);
  }
}

/**
 * Unblock کردن یک identifier
 */
export function unblockIdentifier(identifier: string, type: RateLimitType): void {
  const key = `${type}:${identifier}`;
  requestStore.delete(key);
  console.log(`Identifier unblocked: ${key}`);
}

/**
 * دریافت وضعیت Rate Limit
 */
export function getRateLimitStatus(identifier: string, type: RateLimitType) {
  const key = `${type}:${identifier}`;
  const record = requestStore.get(key);
  const config = RATE_LIMITS[type];
  const now = Date.now();

  if (!record) {
    return {
      requests: 0,
      max: config.max,
      blocked: false,
      resetAt: null
    };
  }

  const validTimestamps = record.timestamps.filter(
    timestamp => now - timestamp < config.window
  );

  const oldestTimestamp = validTimestamps[0];
  const calculatedResetAt = oldestTimestamp ? oldestTimestamp + config.window : null;

  return {
    requests: validTimestamps.length,
    max: config.max,
    blocked: record.blocked,
    resetAt: record.blockedUntil || calculatedResetAt
  };
}

/**
 * آمار کلی Rate Limit
 */
export function getRateLimitStats() {
  const stats: Record<string, { total: number; blocked: number; active: number }> = {};

  for (const [key, record] of requestStore.entries()) {
    const parts = key.split(':');
    const type = parts[0];
    
    if (!type) continue;
    
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

  return stats;
}