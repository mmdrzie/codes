import { LRUCache } from 'lru-cache';
import crypto from 'crypto';

// ✅ بررسی اینکه آیا Redis available است
function isRedisAvailable(): boolean {
  return !!process.env.UPSTASH_REDIS_REST_URL && !!process.env.UPSTASH_REDIS_REST_TOKEN;
}

// ✅ Memory cache (فقط وقتی Redis نیست)
const memoryCache = new LRUCache<string, any>({
  max: 1000,
  ttl: 5 * 60 * 1000, // 5 minutes TTL
});

const NONCE_EXPIRY_SECONDS = 5 * 60; // 5 minutes
const MAX_NONCE_REQUESTS_PER_MINUTE = 10;

export type NonceResponse = {
  nonce: string;
  message: string;
  expiresAt: number;
};

// ✅ **Redis-based nonce storage**
async function generateAndStoreNonceWithRedis(address: string): Promise<NonceResponse> {
  try {
    const { Redis } = await import('@upstash/redis');
    
    const redis = new Redis({
      url: process.env.UPSTASH_REDIS_REST_URL!,
      token: process.env.UPSTASH_REDIS_REST_TOKEN!,
    });
    
    const lowerAddress = address.toLowerCase();
    
    // ✅ Rate limiting با Redis
    const rateLimitKey = `nonce:rate:${lowerAddress}`;
    const currentMinute = Math.floor(Date.now() / 60000);
    const windowKey = `${rateLimitKey}:${currentMinute}`;
    
    const requestCount = await redis.incr(windowKey);
    await redis.expire(windowKey, 60);
    
    if (requestCount > MAX_NONCE_REQUESTS_PER_MINUTE) {
      throw new Error('Too many nonce requests. Please try again later.');
    }
    
    // ✅ Generate nonce
    const nonce = crypto.randomBytes(32).toString('hex');
    const message = `QuantumIQ Login\nNonce: ${nonce}\nTimestamp: ${Date.now()}`;
    const expiresAt = Date.now() + (NONCE_EXPIRY_SECONDS * 1000);
    
    // ✅ Store in Redis با TTL
    const nonceKey = `nonce:${lowerAddress}`;
    await redis.setex(
      nonceKey,
      NONCE_EXPIRY_SECONDS,
      JSON.stringify({
        nonce,
        address: lowerAddress,
        createdAt: Date.now(),
        expiresAt,
      })
    );
    
    return { nonce, message, expiresAt };
    
  } catch (error) {
    console.error('Redis nonce storage failed, falling back to memory:', error);
    return generateAndStoreNonceWithMemory(address);
  }
}

// ✅ **Memory-based nonce storage** (fallback)
function generateAndStoreNonceWithMemory(address: string): NonceResponse {
  const lowerAddress = address.toLowerCase();
  
  // ✅ Rate limiting ساده با memory
  const rateLimitKey = `nonce:rate:${lowerAddress}`;
  const now = Date.now();
  const minute = Math.floor(now / 60000);
  const windowKey = `${rateLimitKey}:${minute}`;
  
  // Type-safe rate limit check
  let currentRate = memoryCache.get(windowKey);
  if (!currentRate) {
    currentRate = { count: 1 };
    memoryCache.set(windowKey, currentRate, { ttl: 60 * 1000 });
  } else {
    // Type assertion برای count
    const rateData = currentRate as { count: number };
    rateData.count++;
    memoryCache.set(windowKey, rateData, { ttl: 60 * 1000 });
  }
  
  // Type checking برای count
  const rateData = currentRate as { count: number };
  if (rateData.count > MAX_NONCE_REQUESTS_PER_MINUTE) {
    throw new Error('Too many nonce requests. Please try again later.');
  }
  
  // ✅ Generate nonce
  const nonce = crypto.randomBytes(32).toString('hex');
  const message = `QuantumIQ Login\nNonce: ${nonce}\nTimestamp: ${now}`;
  const expiresAt = now + (NONCE_EXPIRY_SECONDS * 1000);
  
  // ✅ Store in memory
  const nonceKey = `nonce:${lowerAddress}`;
  memoryCache.set(nonceKey, {
    nonce,
    createdAt: now,
  }, { ttl: NONCE_EXPIRY_SECONDS * 1000 });
  
  return { nonce, message, expiresAt };
}

// ✅ **تابع اصلی generateAndStoreNonce**
export async function generateAndStoreNonce(address: string): Promise<NonceResponse> {
  if (!address || typeof address !== 'string') {
    throw new Error('Address is required');
  }
  
  const lowerAddress = address.toLowerCase();
  if (!/^0x[a-fA-F0-9]{40}$/.test(lowerAddress)) {
    throw new Error('Invalid Ethereum address format');
  }
  
  // اگر Redis available باشد، از آن استفاده کن
  if (isRedisAvailable()) {
    return generateAndStoreNonceWithRedis(address);
  }
  
  // در غیر این صورت از memory استفاده کن
  return generateAndStoreNonceWithMemory(address);
}

// ✅ **Redis-based nonce verification**
async function verifyAndConsumeNonceWithRedis(address: string, nonce: string): Promise<boolean> {
  try {
    const { Redis } = await import('@upstash/redis');
    
    const redis = new Redis({
      url: process.env.UPSTASH_REDIS_REST_URL!,
      token: process.env.UPSTASH_REDIS_REST_TOKEN!,
    });
    
    const lowerAddress = address.toLowerCase();
    const nonceKey = `nonce:${lowerAddress}`;
    
    // ✅ Atomic operation: get و delete
    const multi = redis.multi();
    multi.get(nonceKey);
    multi.del(nonceKey);
    
    const results = await multi.exec();
    const storedData = results[0] as string | null;
    
    if (!storedData) {
      return false;
    }
    
    const parsedData = JSON.parse(storedData);
    const now = Date.now();
    
    const checks = [
      parsedData.nonce === nonce,
      parsedData.address === lowerAddress,
      parsedData.expiresAt > now,
      now - parsedData.createdAt > 1000,
    ];
    
    if (checks.some(check => !check)) {
      return false;
    }
    
    // ✅ جلوگیری از replay attack
    const usedNonceKey = `used:nonce:${nonce}`;
    await redis.setex(usedNonceKey, NONCE_EXPIRY_SECONDS * 2, '1');
    
    return true;
    
  } catch (error) {
    console.error('Redis nonce verification failed, falling back to memory:', error);
    return verifyAndConsumeNonceWithMemory(address, nonce);
  }
}

// ✅ **Memory-based nonce verification** (fallback)
function verifyAndConsumeNonceWithMemory(address: string, nonce: string): boolean {
  try {
    const lowerAddress = address.toLowerCase();
    const nonceKey = `nonce:${lowerAddress}`;
    const stored = memoryCache.get(nonceKey);
    
    if (!stored) {
      return false;
    }
    
    // Type assertion برای stored data
    const storedData = stored as { nonce: string; createdAt: number };
    const now = Date.now();
    
    const checks = [
      storedData.nonce === nonce,
      now - storedData.createdAt < (NONCE_EXPIRY_SECONDS * 1000),
      now - storedData.createdAt > 1000,
    ];
    
    if (checks.some(check => !check)) {
      memoryCache.delete(nonceKey);
      return false;
    }
    
    // ✅ Consume nonce
    memoryCache.delete(nonceKey);
    
    // ✅ Mark as used
    const usedKey = `used:${nonce}`;
    memoryCache.set(usedKey, { nonce, createdAt: now }, { ttl: NONCE_EXPIRY_SECONDS * 2 * 1000 });
    
    return true;
    
  } catch (error) {
    console.error('Memory nonce verification error:', error);
    return false;
  }
}

// ✅ **تابع اصلی verifyAndConsumeNonce**
export async function verifyAndConsumeNonce(address: string, nonce: string): Promise<boolean> {
  // اگر Redis available باشد، از آن استفاده کن
  if (isRedisAvailable()) {
    return verifyAndConsumeNonceWithRedis(address, nonce);
  }
  
  // در غیر این صورت از memory استفاده کن
  return verifyAndConsumeNonceWithMemory(address, nonce);
}

// ✅ Cleanup function (optional)
export function cleanupNonceStore(): number {
  return memoryCache.size;
}

// ✅ Get stats for monitoring
export function getNonceStoreStats() {
  const stats = {
    totalEntries: memoryCache.size,
    hasRedis: isRedisAvailable(),
  };
  
  return stats;
}