import { Redis } from '@upstash/redis';
import { logger } from './logger';
import { SecurityMonitor } from './security-monitoring';
import { SecurityEvent } from './security-monitoring';

interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  bounceFactor?: number; // Factor to increase rate limit after violations
}

interface AnomalyDetectionConfig {
  nonceAbuseThreshold: number;
  authFailureThreshold: number;
  payloadAnomalyThreshold: number;
  windowMs: number;
}

export class EnhancedRateLimiter {
  private redis: Redis;
  private readonly RATE_LIMIT_PREFIX = 'rate_limit:';
  private readonly ANOMALY_PREFIX = 'anomaly:';
  private readonly GLOBAL_PAYLOAD_SIZE_CAP = 1024 * 1024; // 1MB
  
  constructor() {
    this.redis = Redis.fromEnv();
  }

  /**
   * Apply rate limiting with adaptive thresholds
   */
  async applyRateLimit(
    identifier: string,
    config: RateLimitConfig,
    endpoint?: string
  ): Promise<{ allowed: boolean; resetTime?: number; remaining?: number; error?: string }> {
    try {
      const key = `${this.RATE_LIMIT_PREFIX}${identifier}`;
      
      // Get current counter and expiry time
      const [currentValue, expiryTime] = await Promise.all([
        this.redis.get(key),
        this.redis.pttl(key)
      ]);
      
      const current = currentValue ? parseInt(currentValue as string, 10) : 0;
      
      // Check if we're within the rate limit
      if (current >= config.maxRequests) {
        const resetTime = expiryTime > 0 ? Date.now() + expiryTime : Date.now() + config.windowMs;
        
        // Log potential abuse
        await SecurityMonitor.logEvent(
          SecurityEvent.SUSPICIOUS_ACTIVITY,
          {
            timestamp: new Date(),
            userId: identifier,
            ipAddress: identifier,
            userAgent: 'unknown',
            metadata: {
              operation: 'rate_limit_exceeded',
              endpoint,
              identifier
            }
          },
          'Rate limit exceeded'
        );
        
        return {
          allowed: false,
          resetTime,
          remaining: 0
        };
      }
      
      // Increment the counter with expiry
      const newValue = current + 1;
      await this.redis.setex(key, Math.ceil(config.windowMs / 1000), newValue.toString());
      
      const remaining = config.maxRequests - newValue;
      const resetTime = Date.now() + config.windowMs;
      
      return {
        allowed: true,
        remaining,
        resetTime
      };
    } catch (error) {
      logger.error('Rate limiting error', { error: (error as Error).message });
      // Fail open on rate limiter errors to avoid blocking legitimate requests
      return { allowed: true, error: (error as Error).message };
    }
  }

  /**
   * Apply adaptive rate limiting based on violation history
   */
  async applyAdaptiveRateLimit(
    identifier: string,
    baseConfig: RateLimitConfig,
    endpoint?: string
  ): Promise<{ allowed: boolean; resetTime?: number; remaining?: number; error?: string }> {
    try {
      // Check for previous violations to adjust rate limit
      const violationCount = await this.getViolationCount(identifier);
      const adjustedConfig = { ...baseConfig };
      
      // Increase restrictions based on violation count
      if (violationCount > 0) {
        // Reduce max requests by bounce factor for each violation
        adjustedConfig.maxRequests = Math.max(1, Math.floor(baseConfig.maxRequests / (1 + violationCount * (baseConfig.bounceFactor || 0.5))));
      }
      
      return await this.applyRateLimit(identifier, adjustedConfig, endpoint);
    } catch (error) {
      logger.error('Adaptive rate limiting error', { error: (error as Error).message });
      return { allowed: true, error: (error as Error).message };
    }
  }

  /**
   * Detect anomalies in request patterns
   */
  async detectAnomalies(
    identifier: string,
    config: AnomalyDetectionConfig,
    eventType: 'nonce_abuse' | 'auth_failure' | 'payload_anomaly'
  ): Promise<boolean> {
    try {
      const key = `${this.ANOMALY_PREFIX}${eventType}:${identifier}`;
      
      // Get current count and increment
      const current = (await this.redis.get(key)) ? parseInt(await this.redis.get(key) as string, 10) : 0;
      const newCount = current + 1;
      
      // Set with expiry
      await this.redis.setex(key, Math.ceil(config.windowMs / 1000), newCount.toString());
      
      // Check if threshold is exceeded
      let thresholdExceeded = false;
      switch (eventType) {
        case 'nonce_abuse':
          thresholdExceeded = newCount > config.nonceAbuseThreshold;
          break;
        case 'auth_failure':
          thresholdExceeded = newCount > config.authFailureThreshold;
          break;
        case 'payload_anomaly':
          thresholdExceeded = newCount > config.payloadAnomalyThreshold;
          break;
      }
      
      if (thresholdExceeded) {
        // Log security event
        await SecurityMonitor.logEvent(
          SecurityEvent.SUSPICIOUS_ACTIVITY,
          {
            timestamp: new Date(),
            userId: identifier,
            ipAddress: identifier,
            userAgent: 'unknown',
            metadata: {
              operation: `anomaly_detected_${eventType}`,
              count: newCount,
              threshold: eventType === 'nonce_abuse' ? config.nonceAbuseThreshold :
                        eventType === 'auth_failure' ? config.authFailureThreshold :
                        config.payloadAnomalyThreshold
            }
          },
          `Anomaly detected: ${eventType}`
        );
        
        // Increase violation count
        await this.incrementViolation(identifier);
      }
      
      return thresholdExceeded;
    } catch (error) {
      logger.error('Anomaly detection error', { error: (error as Error).message });
      return false;
    }
  }

  /**
   * Enforce global payload size cap
   */
  enforcePayloadSizeCap(payload: any): boolean {
    try {
      const payloadSize = JSON.stringify(payload).length;
      return payloadSize <= this.GLOBAL_PAYLOAD_SIZE_CAP;
    } catch (error) {
      logger.error('Payload size enforcement error', { error: (error as Error).message });
      return false;
    }
  }

  /**
   * Check if a payload looks anomalous
   */
  detectPayloadAnomalies(payload: any): boolean {
    try {
      // Check for unusually large payloads
      const payloadSize = JSON.stringify(payload).length;
      if (payloadSize > this.GLOBAL_PAYLOAD_SIZE_CAP * 0.8) { // 80% of cap
        return true;
      }
      
      // Check for potential injection patterns
      const payloadStr = JSON.stringify(payload).toLowerCase();
      const injectionPatterns = [
        /union\s+select/,
        /drop\s+table/,
        /exec\s*\(/,
        /<script/,
        /javascript:/,
        /on\w+\s*=/
      ];
      
      for (const pattern of injectionPatterns) {
        if (pattern.test(payloadStr)) {
          return true;
        }
      }
      
      return false;
    } catch (error) {
      logger.error('Payload anomaly detection error', { error: (error as Error).message });
      return false;
    }
  }

  /**
   * Get violation count for an identifier
   */
  private async getViolationCount(identifier: string): Promise<number> {
    try {
      const key = `${this.ANOMALY_PREFIX}violations:${identifier}`;
      const count = await this.redis.get(key);
      return count ? parseInt(count as string, 10) : 0;
    } catch (error) {
      logger.error('Get violation count error', { error: (error as Error).message });
      return 0;
    }
  }

  /**
   * Increment violation count for an identifier
   */
  private async incrementViolation(identifier: string): Promise<void> {
    try {
      const key = `${this.ANOMALY_PREFIX}violations:${identifier}`;
      const current = await this.getViolationCount(identifier);
      const newCount = current + 1;
      await this.redis.setex(key, 60 * 60 * 24, newCount.toString()); // 24 hours
    } catch (error) {
      logger.error('Increment violation error', { error: (error as Error).message });
    }
  }

  /**
   * Reset violation count for an identifier
   */
  async resetViolations(identifier: string): Promise<void> {
    try {
      const key = `${this.ANOMALY_PREFIX}violations:${identifier}`;
      await this.redis.del(key);
    } catch (error) {
      logger.error('Reset violations error', { error: (error as Error).message });
    }
  }
}

// Global instance for easy access
export const enhancedRateLimiter = new EnhancedRateLimiter();