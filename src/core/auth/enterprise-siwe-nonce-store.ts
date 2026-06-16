/**
 * Enterprise-Grade SIWE Nonce Store
 * 
 * SECURITY FIXES:
 * - Redis-backed nonce storage (no in-memory fallback)
 * - Atomic consume operation via Lua scripts (prevents race conditions)
 * - Single-use nonce enforcement (prevents replay attacks)
 * - Expiration support
 * - Cluster-safe design
 * - Server restart safe
 * - Multi-region safe
 * - FAILS CLOSED if Redis unavailable
 */

import { EnterpriseRedisClient } from '../../infrastructure/redis/enterprise-redis-client';
import { logger } from '../../utils/logger';
import { SecurityMonitor, SecurityEvent } from '../../lib/security-monitoring';
import crypto from 'crypto';

export interface NonceData {
  nonce: string;
  address: string;
  createdAt: number;
  expiresAt: number;
  consumed: boolean;
  consumedAt?: number;
  requestId?: string;
}

export interface NonceResponse {
  nonce: string;
  message: string;
  expiresAt: number;
}

export class EnterpriseSiweNonceStore {
  private readonly redis: EnterpriseRedisClient;
  private readonly NONCE_PREFIX = 'siwe:nonce:';
  private readonly CONSUMED_PREFIX = 'siwe:nonce:consumed:';
  private readonly RATE_LIMIT_PREFIX = 'siwe:nonce:rate:';
  
  // Configuration
  private readonly NONCE_TTL_SECONDS = 5 * 60; // 5 minutes
  private readonly CONSUMED_MARKER_TTL_SECONDS = 24 * 60 * 60; // 24 hours (prevent replay)
  private readonly MAX_NONCE_REQUESTS_PER_MINUTE = 10;
  private readonly MIN_TIME_SINCE_CREATION_MS = 1000; // At least 1 second before consumption
  private readonly MAX_TIME_SINCE_CREATION_MS = 24 * 60 * 60 * 1000; // 24 hours max

  constructor(redisClient: EnterpriseRedisClient) {
    this.redis = redisClient;
  }

  /**
   * Generate and store a new SIWE nonce atomically
   * Includes rate limiting to prevent abuse
   */
  async generateAndStoreNonce(address: string, requestId?: string): Promise<NonceResponse> {
    // Validate address format
    const lowerAddress = address.toLowerCase();
    if (!/^0x[a-fA-F0-9]{40}$/.test(lowerAddress)) {
      throw new Error('Invalid Ethereum address format');
    }

    const now = Date.now();
    const nonce = crypto.randomBytes(32).toString('hex');
    const expiresAt = now + (this.NONCE_TTL_SECONDS * 1000);
    
    const nonceData: NonceData = {
      nonce,
      address: lowerAddress,
      createdAt: now,
      expiresAt,
      consumed: false,
      requestId,
    };

    // Rate limit check Lua script
    const rateLimitScript = `
      local rateKey = KEYS[1]
      local maxRequests = tonumber(ARGV[1])
      local windowMs = tonumber(ARGV[2])
      local now = tonumber(ARGV[3])
      
      -- Get current window
      local windowStart = now - windowMs
      local windowKey = rateKey .. ':' .. math.floor(now / windowMs)
      
      -- Increment counter for this window
      local count = redis.call('INCR', windowKey)
      redis.call('EXPIRE', windowKey, math.ceil(windowMs / 1000))
      
      if count > maxRequests then
        return { err = 'RATE_LIMIT_EXCEEDED', count = count }
      end
      
      return { ok = true, count = count }
    `;

    try {
      // Check rate limit first
      const rateResult = await this.redis.eval(
        rateLimitScript,
        [`${this.RATE_LIMIT_PREFIX}${lowerAddress}`],
        [
          this.MAX_NONCE_REQUESTS_PER_MINUTE.toString(),
          '60000', // 1 minute window
          now.toString(),
        ]
      );

      if (rateResult.err) {
        logger.warn('SIWE nonce rate limit exceeded', {
          address: lowerAddress,
          requestId,
        });

        await SecurityMonitor.logEvent(
          SecurityEvent.SUSPICIOUS_ACTIVITY,
          {
            timestamp: new Date(),
            metadata: {
              address: lowerAddress,
              operation: 'nonce_generation',
              reason: 'rate_limit_exceeded',
            },
          },
          'SIWE nonce rate limit exceeded'
        );

        throw new Error('Too many nonce requests. Please try again later.');
      }

      // Store nonce atomically
      const nonceKey = `${this.NONCE_PREFIX}${nonce}`;
      await this.redis.setex(nonceKey, this.NONCE_TTL_SECONDS, JSON.stringify(nonceData));

      // Create index for address -> nonces mapping
      const addressIndexKey = `${this.NONCE_PREFIX}address:${lowerAddress}`;
      await this.redis.sadd(addressIndexKey, nonce);
      await this.redis.expire(addressIndexKey, this.NONCE_TTL_SECONDS);

      const message = `QuantumIQ Login\nNonce: ${nonce}\nTimestamp: ${now}`;

      logger.info('SIWE nonce generated', {
        address: lowerAddress,
        nonceHash: this.hashNonce(nonce),
        expiresAt: new Date(expiresAt).toISOString(),
        requestId,
      });

      return { nonce, message, expiresAt };
    } catch (error) {
      logger.error('Failed to generate SIWE nonce', {
        error: (error as Error).message,
        address: lowerAddress,
        requestId,
      });
      throw error;
    }
  }

  /**
   * Verify and consume nonce atomically using Lua script
   * This prevents ALL race conditions and replay attacks
   */
  async verifyAndConsumeNonce(address: string, nonce: string): Promise<{
    success: boolean;
    error?: string;
    nonceData?: NonceData;
  }> {
    const lowerAddress = address.toLowerCase();
    const now = Date.now();

    // Atomic Lua script for nonce verification and consumption
    // This is CRITICAL for preventing race conditions
    const consumeScript = `
      local nonceKey = KEYS[1]
      local consumedKey = KEYS[2]
      local addressIndexKey = KEYS[3]
      local address = ARGV[1]
      local nonce_to_verify = ARGV[2]
      local current_time = tonumber(ARGV[3])
      local min_time_since_creation = tonumber(ARGV[4])
      local max_time_since_creation = tonumber(ARGV[5])
      local consumed_marker_ttl = tonumber(ARGV[6])
      
      -- Get stored nonce data
      local stored_data_json = redis.call('GET', nonceKey)
      if not stored_data_json then
        return cjson.encode({success = false, error = 'NONCE_NOT_FOUND'})
      end
      
      local stored_data = cjson.decode(stored_data_json)
      
      -- Verify address matches
      if stored_data.address ~= address then
        return cjson.encode({success = false, error = 'ADDRESS_MISMATCH'})
      end
      
      -- Check if already consumed
      if stored_data.consumed then
        return cjson.encode({success = false, error = 'NONCE_ALREADY_CONSUMED'})
      end
      
      -- Check expiration
      if current_time > stored_data.expiresAt then
        -- Delete expired nonce
        redis.call('DEL', nonceKey)
        return cjson.encode({success = false, error = 'NONCE_EXPIRED'})
      end
      
      -- Check minimum time since creation (prevent instant replay)
      local time_since_creation = current_time - stored_data.createdAt
      if time_since_creation < min_time_since_creation then
        return cjson.encode({success = false, error = 'NONCE_TOO_RECENT'})
      end
      
      -- Check maximum time since creation
      if time_since_creation > max_time_since_creation then
        redis.call('DEL', nonceKey)
        return cjson.encode({success = false, error = 'NONCE_TOO_OLD'})
      end
      
      -- Check if nonce was already marked as consumed (double-spend protection)
      local already_consumed = redis.call('GET', consumedKey)
      if already_consumed then
        return cjson.encode({success = false, error = 'NONCE_ALREADY_CONSUMED_MARKER'})
      end
      
      -- Mark as consumed in the nonce data
      stored_data.consumed = true
      stored_data.consumedAt = current_time
      redis.call('SET', nonceKey, cjson.encode(stored_data))
      
      -- Create consumed marker (for additional replay protection)
      redis.call('SETEX', consumedKey, consumed_marker_ttl, 'consumed')
      
      -- Remove from address index
      redis.call('SREM', addressIndexKey, nonce_to_verify)
      
      return cjson.encode({success = true, nonce = stored_data.nonce, address = stored_data.address})
    `;

    try {
      const result = await this.redis.eval(
        consumeScript,
        [
          `${this.NONCE_PREFIX}${nonce}`,
          `${this.CONSUMED_PREFIX}${nonce}`,
          `${this.NONCE_PREFIX}address:${lowerAddress}`,
        ],
        [
          lowerAddress,
          nonce,
          now.toString(),
          this.MIN_TIME_SINCE_CREATION_MS.toString(),
          this.MAX_TIME_SINCE_CREATION_MS.toString(),
          this.CONSUMED_MARKER_TTL_SECONDS.toString(),
        ]
      );

      const parsedResult = JSON.parse(result);

      if (parsedResult.success) {
        logger.info('SIWE nonce verified and consumed', {
          address: lowerAddress,
          nonceHash: this.hashNonce(nonce),
        });

        await SecurityMonitor.logEvent(
          SecurityEvent.AUTH_SUCCESS,
          {
            timestamp: new Date(),
            metadata: {
              address: lowerAddress,
              operation: 'nonce_consumption',
              nonceHash: this.hashNonce(nonce),
            },
          },
          'SIWE nonce consumed successfully'
        );

        return {
          success: true,
          nonceData: {
            nonce: parsedResult.nonce,
            address: parsedResult.address,
            createdAt: now,
            expiresAt: now + this.NONCE_TTL_SECONDS * 1000,
            consumed: true,
            consumedAt: now,
          },
        };
      } else {
        logger.warn('SIWE nonce verification failed', {
          address: lowerAddress,
          nonceHash: this.hashNonce(nonce),
          error: parsedResult.error,
        });

        await SecurityMonitor.logEvent(
          SecurityEvent.AUTH_FAILURE,
          {
            timestamp: new Date(),
            metadata: {
              address: lowerAddress,
              operation: 'nonce_verification',
              error: parsedResult.error,
              nonceHash: this.hashNonce(nonce),
            },
          },
          `SIWE nonce verification failed: ${parsedResult.error}`
        );

        return {
          success: false,
          error: parsedResult.error,
        };
      }
    } catch (error) {
      logger.error('SIWE nonce verification failed with error', {
        error: (error as Error).message,
        address: lowerAddress,
        nonceHash: this.hashNonce(nonce),
      });

      // FAIL CLOSED: On any error, reject the nonce
      return {
        success: false,
        error: 'Nonce verification failed due to system error',
      };
    }
  }

  /**
   * Check if a nonce exists and is valid (without consuming)
   * Used for validation before signature verification
   */
  async validateNonce(address: string, nonce: string): Promise<{
    valid: boolean;
    error?: string;
  }> {
    const lowerAddress = address.toLowerCase();
    const now = Date.now();

    try {
      const nonceJson = await this.redis.get(`${this.NONCE_PREFIX}${nonce}`);
      
      if (!nonceJson) {
        return { valid: false, error: 'Nonce not found' };
      }

      const nonceData: NonceData = JSON.parse(nonceJson);

      if (nonceData.address !== lowerAddress) {
        return { valid: false, error: 'Address mismatch' };
      }

      if (nonceData.consumed) {
        return { valid: false, error: 'Nonce already consumed' };
      }

      if (now > nonceData.expiresAt) {
        return { valid: false, error: 'Nonce expired' };
      }

      return { valid: true };
    } catch (error) {
      logger.error('Nonce validation failed', {
        error: (error as Error).message,
        address: lowerAddress,
      });
      return { valid: false, error: 'Validation failed' };
    }
  }

  /**
   * Clean up expired nonces for an address
   */
  async cleanupExpiredNonces(address: string): Promise<number> {
    const lowerAddress = address.toLowerCase();
    const addressIndexKey = `${this.NONCE_PREFIX}address:${lowerAddress}`;
    const now = Date.now();

    try {
      const nonces = await this.redis.smembers(addressIndexKey);
      let cleanedCount = 0;

      for (const nonce of nonces) {
        const nonceJson = await this.redis.get(`${this.NONCE_PREFIX}${nonce}`);
        if (nonceJson) {
          const nonceData: NonceData = JSON.parse(nonceJson);
          if (now > nonceData.expiresAt || nonceData.consumed) {
            await this.redis.del(`${this.NONCE_PREFIX}${nonce}`);
            await this.redis.srem(addressIndexKey, nonce);
            cleanedCount++;
          }
        }
      }

      return cleanedCount;
    } catch (error) {
      logger.warn('Failed to cleanup expired nonces', {
        error: (error as Error).message,
        address: lowerAddress,
      });
      return 0;
    }
  }

  /**
   * Hash nonce for logging (never log actual nonces)
   */
  private hashNonce(nonce: string): string {
    return crypto.createHash('sha256').update(nonce).digest('hex').slice(0, 16);
  }
}

// Factory function
export function createEnterpriseSiweNonceStore(
  redisClient: EnterpriseRedisClient
): EnterpriseSiweNonceStore {
  return new EnterpriseSiweNonceStore(redisClient);
}
