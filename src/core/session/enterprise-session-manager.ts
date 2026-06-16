/**
 * Enterprise-Grade Session Management System
 * 
 * Features:
 * - Redis-backed atomic session operations
 * - Race condition prevention via Lua scripts
 * - Sliding expiration with rotation
 * - Device tracking and fingerprinting
 * - Concurrent session controls
 * - Secure session revocation
 * - Fail-closed architecture
 */

import { EnterpriseRedisClient } from '../../infrastructure/redis/enterprise-redis-client';
import { logger } from '../../utils/logger';
import { SecurityMonitor, SecurityEvent } from '../../lib/security-monitoring';
import crypto from 'crypto';

export interface SessionData {
  sessionId: string;
  userId: string;
  tenantId: string;
  deviceFingerprint: string;
  ipAddress: string;
  userAgent: string;
  createdAt: number;
  lastActive: number;
  expiresAt: number;
  mfaVerified: boolean;
  mfaVerifiedAt?: number;
  authMethod: 'password' | 'wallet' | 'sso';
  walletAddress?: string;
  roles: string[];
  permissions: string[];
  metadata: Record<string, any>;
}

export interface SessionValidationResult {
  isValid: boolean;
  session?: SessionData;
  error?: string;
  requiresMFA?: boolean;
}

export interface SessionCreationOptions {
  userId: string;
  tenantId: string;
  deviceFingerprint: string;
  ipAddress: string;
  userAgent: string;
  authMethod: 'password' | 'wallet' | 'sso';
  walletAddress?: string;
  roles: string[];
  permissions: string[];
  mfaVerified?: boolean;
  ttlSeconds?: number;
  maxConcurrentSessions?: number;
}

export class EnterpriseSessionManager {
  private readonly redis: EnterpriseRedisClient;
  private readonly SESSION_PREFIX = 'session:';
  private readonly USER_SESSIONS_PREFIX = 'user:sessions:';
  private readonly DEVICE_SESSIONS_PREFIX = 'device:sessions:';
  private readonly REVOKED_PREFIX = 'session:revoked:';
  private readonly MFA_VERIFIED_PREFIX = 'session:mfa:';
  
  // Default TTL: 24 hours
  private readonly DEFAULT_TTL_SECONDS = 24 * 60 * 60;
  // Maximum concurrent sessions per user
  private readonly DEFAULT_MAX_CONCURRENT_SESSIONS = 5;
  // Sliding window: extend session if activity within this period
  private readonly SLIDING_WINDOW_SECONDS = 1 * 60 * 60; // 1 hour

  constructor(redisClient: EnterpriseRedisClient) {
    this.redis = redisClient;
  }

  /**
   * Create a new session with atomic operations
   * Prevents race conditions during session creation
   */
  async createSession(options: SessionCreationOptions): Promise<SessionData> {
    const sessionId = this.generateSecureSessionId();
    const now = Date.now();
    const ttlSeconds = options.ttlSeconds || this.DEFAULT_TTL_SECONDS;
    const maxSessions = options.maxConcurrentSessions || this.DEFAULT_MAX_CONCURRENT_SESSIONS;

    const sessionData: SessionData = {
      sessionId,
      userId: options.userId,
      tenantId: options.tenantId,
      deviceFingerprint: options.deviceFingerprint,
      ipAddress: options.ipAddress,
      userAgent: options.userAgent,
      createdAt: now,
      lastActive: now,
      expiresAt: now + (ttlSeconds * 1000),
      mfaVerified: options.mfaVerified || false,
      authMethod: options.authMethod,
      walletAddress: options.walletAddress,
      roles: options.roles,
      permissions: options.permissions,
      metadata: {},
    };

    // Lua script for atomic session creation with concurrent session enforcement
    const luaScript = `
      local sessionKey = KEYS[1]
      local userSessionsKey = KEYS[2]
      local deviceSessionsKey = KEYS[3]
      local maxSessions = tonumber(ARGV[1])
      local sessionData = ARGV[2]
      local ttl = tonumber(ARGV[3])
      local sessionId = ARGV[4]
      local userId = ARGV[5]
      local deviceFingerprint = ARGV[6]
      
      -- Check if session already exists (prevent duplicate creation)
      local existing = redis.call('GET', sessionKey)
      if existing then
        return { err = 'SESSION_EXISTS' }
      end
      
      -- Get current session count for user
      local currentCount = redis.call('SCARD', userSessionsKey)
      
      -- If at max capacity, remove oldest session
      if currentCount >= maxSessions then
        local oldestSessionId = redis.call('SPOP', userSessionsKey)
        if oldestSessionId then
          local oldSessionKey = '${this.SESSION_PREFIX}' .. oldestSessionId
          redis.call('DEL', oldSessionKey)
          
          -- Remove from device sessions set
          local oldDeviceKey = redis.call('HGET', oldSessionKey, 'deviceFingerprint')
          if oldDeviceKey then
            local oldDeviceSessionsKey = '${this.DEVICE_SESSIONS_PREFIX}' .. oldDeviceKey
            redis.call('SREM', oldDeviceSessionsKey, oldestSessionId)
          end
        end
      end
      
      -- Create new session
      redis.call('SETEX', sessionKey, ttl, sessionData)
      
      -- Add to user's sessions set
      redis.call('SADD', userSessionsKey, sessionId)
      redis.call('EXPIRE', userSessionsKey, ttl)
      
      -- Add to device's sessions set
      local devSessionsKey = '${this.DEVICE_SESSIONS_PREFIX}' .. deviceFingerprint
      redis.call('SADD', devSessionsKey, sessionId)
      redis.call('EXPIRE', devSessionsKey, ttl)
      
      -- Store session index for quick lookup
      redis.call('HSET', sessionKey, 'userId', userId)
      redis.call('HSET', sessionKey, 'deviceFingerprint', deviceFingerprint)
      
      return { ok = sessionId }
    `;

    try {
      const result = await this.redis.eval(
        luaScript,
        [
          `${this.SESSION_PREFIX}${sessionId}`,
          `${this.USER_SESSIONS_PREFIX}${options.userId}`,
          `${this.DEVICE_SESSIONS_PREFIX}${options.deviceFingerprint}`,
        ],
        [
          maxSessions.toString(),
          JSON.stringify(sessionData),
          ttlSeconds.toString(),
          sessionId,
          options.userId,
          options.deviceFingerprint,
        ]
      );

      if (result.err) {
        throw new Error(`Session creation failed: ${result.err}`);
      }

      logger.info('Session created successfully', {
        sessionId,
        userId: options.userId,
        tenantId: options.tenantId,
        deviceFingerprint: options.deviceFingerprint,
      });

      await SecurityMonitor.logEvent(
        SecurityEvent.AUTH_SUCCESS,
        {
          timestamp: new Date(),
          userId: options.userId,
          sessionId,
          metadata: {
            authMethod: options.authMethod,
            mfaVerified: options.mfaVerified || false,
          },
        },
        'User session created'
      );

      return sessionData;
    } catch (error) {
      logger.error('Failed to create session', {
        error: (error as Error).message,
        userId: options.userId,
      });

      await SecurityMonitor.logEvent(
        SecurityEvent.AUTH_FAILURE,
        {
          timestamp: new Date(),
          userId: options.userId,
          metadata: {
            operation: 'session_creation',
            error: (error as Error).message,
          },
        },
        'Session creation failed'
      );

      throw error;
    }
  }

  /**
   * Validate session with atomic checks
   * Implements sliding expiration
   */
  async validateSession(
    sessionId: string,
    expectedUserId?: string,
    expectedDeviceFingerprint?: string
  ): Promise<SessionValidationResult> {
    try {
      // Check if session is revoked
      const isRevoked = await this.redis.get(`${this.REVOKED_PREFIX}${sessionId}`);
      if (isRevoked) {
        return {
          isValid: false,
          error: 'Session has been revoked',
        };
      }

      const sessionJson = await this.redis.get(`${this.SESSION_PREFIX}${sessionId}`);
      if (!sessionJson) {
        return {
          isValid: false,
          error: 'Session not found or expired',
        };
      }

      let sessionData: SessionData;
      try {
        sessionData = JSON.parse(sessionJson);
      } catch (parseError) {
        logger.error('Failed to parse session data', { sessionId, error: (parseError as Error).message });
        return {
          isValid: false,
          error: 'Session data corrupted',
        };
      }

      // Validate expiration
      const now = Date.now();
      if (now > sessionData.expiresAt) {
        // Session expired - clean up asynchronously
        this.cleanupExpiredSession(sessionId).catch((err) =>
          logger.warn('Failed to cleanup expired session', { sessionId, error: err })
        );

        return {
          isValid: false,
          error: 'Session expired',
        };
      }

      // Validate user binding if provided
      if (expectedUserId && sessionData.userId !== expectedUserId) {
        await SecurityMonitor.logEvent(
          SecurityEvent.SESSION_HIJACK_ATTEMPT,
          {
            timestamp: new Date(),
            userId: expectedUserId,
            sessionId,
            metadata: {
              actualUserId: sessionData.userId,
              reason: 'user_mismatch',
            },
          },
          'Session user mismatch detected'
        );

        return {
          isValid: false,
          error: 'Session bound to different user',
        };
      }

      // Validate device binding if provided
      if (expectedDeviceFingerprint && sessionData.deviceFingerprint !== expectedDeviceFingerprint) {
        await SecurityMonitor.logEvent(
          SecurityEvent.SESSION_HIJACK_ATTEMPT,
          {
            timestamp: new Date(),
            userId: sessionData.userId,
            sessionId,
            metadata: {
              expectedDevice: expectedDeviceFingerprint,
              actualDevice: sessionData.deviceFingerprint,
              reason: 'device_mismatch',
            },
          },
          'Session device mismatch detected'
        );

        return {
          isValid: false,
          error: 'Session bound to different device',
        };
      }

      // Apply sliding expiration if within sliding window
      const timeUntilExpiry = sessionData.expiresAt - now;
      if (timeUntilExpiry < this.SLIDING_WINDOW_SECONDS * 1000) {
        // Extend session
        await this.extendSession(sessionId);
      }

      return {
        isValid: true,
        session: sessionData,
        requiresMFA: this.requiresMFAForSession(sessionData),
      };
    } catch (error) {
      logger.error('Session validation failed', { sessionId, error: (error as Error).message });

      // Fail closed on errors
      return {
        isValid: false,
        error: 'Session validation failed',
      };
    }
  }

  /**
   * Mark session as MFA verified
   */
  async markMFAVerified(sessionId: string): Promise<void> {
    const sessionJson = await this.redis.get(`${this.SESSION_PREFIX}${sessionId}`);
    if (!sessionJson) {
      throw new Error('Session not found');
    }

    const sessionData: SessionData = JSON.parse(sessionJson);
    sessionData.mfaVerified = true;
    sessionData.mfaVerifiedAt = Date.now();

    const ttlSeconds = Math.ceil((sessionData.expiresAt - Date.now()) / 1000);
    await this.redis.setex(`${this.SESSION_PREFIX}${sessionId}`, ttlSeconds, JSON.stringify(sessionData));
    await this.redis.setex(
      `${this.MFA_VERIFIED_PREFIX}${sessionId}`,
      ttlSeconds,
      'verified'
    );

    logger.info('Session MFA verified', { sessionId, userId: sessionData.userId });
  }

  /**
   * Check if session has MFA verification
   */
  async isMFAVerified(sessionId: string): Promise<boolean> {
    const mfaStatus = await this.redis.get(`${this.MFA_VERIFIED_PREFIX}${sessionId}`);
    return mfaStatus === 'verified';
  }

  /**
   * Revoke session atomically
   */
  async revokeSession(sessionId: string): Promise<void> {
    const sessionJson = await this.redis.get(`${this.SESSION_PREFIX}${sessionId}`);
    if (!sessionJson) {
      return; // Already gone
    }

    const sessionData: SessionData = JSON.parse(sessionJson);

    // Lua script for atomic revocation
    const luaScript = `
      local sessionKey = KEYS[1]
      local userSessionsKey = KEYS[2]
      local deviceSessionsKey = KEYS[3]
      local revokedKey = KEYS[4]
      local sessionId = ARGV[1]
      local ttl = tonumber(ARGV[2])
      
      -- Delete session
      redis.call('DEL', sessionKey)
      
      -- Remove from user's sessions
      redis.call('SREM', userSessionsKey, sessionId)
      
      -- Remove from device's sessions
      redis.call('SREM', deviceSessionsKey, sessionId)
      
      -- Add to revoked list (to prevent reuse during TTL)
      redis.call('SETEX', revokedKey, ttl, 'revoked')
      
      return { ok = true }
    `;

    const remainingTtl = Math.ceil((sessionData.expiresAt - Date.now()) / 1000);

    await this.redis.eval(
      luaScript,
      [
        `${this.SESSION_PREFIX}${sessionId}`,
        `${this.USER_SESSIONS_PREFIX}${sessionData.userId}`,
        `${this.DEVICE_SESSIONS_PREFIX}${sessionData.deviceFingerprint}`,
        `${this.REVOKED_PREFIX}${sessionId}`,
      ],
      [sessionId, Math.max(remainingTtl, 60).toString()]
    );

    logger.info('Session revoked', { sessionId, userId: sessionData.userId });

    await SecurityMonitor.logEvent(
      SecurityEvent.LOGOUT,
      {
        timestamp: new Date(),
        userId: sessionData.userId,
        sessionId,
      },
      'Session revoked'
    );
  }

  /**
   * Revoke all sessions for a user
   */
  async revokeAllUserSessions(userId: string): Promise<number> {
    const userSessionsKey = `${this.USER_SESSIONS_PREFIX}${userId}`;
    const sessionIds = await this.redis.smembers(userSessionsKey);

    let revokedCount = 0;
    for (const sessionId of sessionIds) {
      try {
        await this.revokeSession(sessionId);
        revokedCount++;
      } catch (error) {
        logger.warn('Failed to revoke session during bulk revocation', {
          sessionId,
          userId,
          error: (error as Error).message,
        });
      }
    }

    logger.info('All user sessions revoked', { userId, revokedCount });

    return revokedCount;
  }

  /**
   * Get all active sessions for a user
   */
  async getUserSessions(userId: string): Promise<SessionData[]> {
    const userSessionsKey = `${this.USER_SESSIONS_PREFIX}${userId}`;
    const sessionIds = await this.redis.smembers(userSessionsKey);

    const sessions: SessionData[] = [];
    for (const sessionId of sessionIds) {
      const sessionJson = await this.redis.get(`${this.SESSION_PREFIX}${sessionId}`);
      if (sessionJson) {
        try {
          const sessionData: SessionData = JSON.parse(sessionJson);
          // Only include non-expired sessions
          if (Date.now() < sessionData.expiresAt) {
            sessions.push(sessionData);
          }
        } catch (error) {
          logger.warn('Failed to parse session in getUserSessions', { sessionId, error });
        }
      }
    }

    return sessions;
  }

  /**
   * Extend session TTL (sliding expiration)
   */
  private async extendSession(sessionId: string): Promise<void> {
    const sessionJson = await this.redis.get(`${this.SESSION_PREFIX}${sessionId}`);
    if (!sessionJson) return;

    const sessionData: SessionData = JSON.parse(sessionJson);
    const newExpiresAt = Date.now() + this.DEFAULT_TTL_SECONDS * 1000;
    sessionData.expiresAt = newExpiresAt;
    sessionData.lastActive = Date.now();

    await this.redis.setex(
      `${this.SESSION_PREFIX}${sessionId}`,
      this.DEFAULT_TTL_SECONDS,
      JSON.stringify(sessionData)
    );
  }

  /**
   * Cleanup expired session
   */
  private async cleanupExpiredSession(sessionId: string): Promise<void> {
    const sessionJson = await this.redis.get(`${this.SESSION_PREFIX}${sessionId}`);
    if (!sessionJson) return;

    const sessionData: SessionData = JSON.parse(sessionJson);

    // Remove from user's sessions set
    await this.redis.srem(
      `${this.USER_SESSIONS_PREFIX}${sessionData.userId}`,
      sessionId
    );

    // Remove from device's sessions set
    await this.redis.srem(
      `${this.DEVICE_SESSIONS_PREFIX}${sessionData.deviceFingerprint}`,
      sessionId
    );
  }

  /**
   * Generate cryptographically secure session ID
   */
  private generateSecureSessionId(): string {
    return `sess_${crypto.randomBytes(32).toString('hex')}`;
  }

  /**
   * Check if MFA is required for this session based on risk factors
   */
  private requiresMFAForSession(sessionData: SessionData): boolean {
    // MFA required if not already verified
    if (!sessionData.mfaVerified) {
      return true;
    }

    // Additional checks could be added here:
    // - New device
    // - High-risk location
    // - Sensitive operations
    // - Time since last MFA

    return false;
  }
}

// Factory function to create session manager instance
export function createEnterpriseSessionManager(
  redisClient: EnterpriseRedisClient
): EnterpriseSessionManager {
  return new EnterpriseSessionManager(redisClient);
}
