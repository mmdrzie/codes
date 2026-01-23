import { Redis } from 'ioredis';
import { CryptoOperations } from './crypto/crypto-operations';
import { logger } from './logger';
import { SecurityMonitor } from './security-monitoring';
import { SecurityEvent } from './security-monitoring';

interface SessionInfo {
  sessionId: string;
  userId: string;
  ip: string;
  userAgent: string;
  createdAt: number;
  lastActive: number;
  expiresAt: number;
  tenantId: string;
}

export class SecureSessionManager {
  private redis: Redis;
  private cryptoOps: CryptoOperations;
  private readonly MAX_CONCURRENT_SESSIONS = parseInt(process.env.MAX_CONCURRENT_SESSIONS || '5', 10);
  private readonly SESSION_EXPIRATION_SECONDS = 60 * 60 * 24; // 24 hours
  private readonly MOBILE_USER_AGENT_REGEX = /mobile|android|iphone|ipad|phone|tablet|ios/i;
  private readonly MOBILE_IP_TOLERANCE_ENABLED = process.env.MOBILE_IP_TOLERANCE_ENABLED === 'true';

  constructor(redisClient: Redis) {
    this.redis = redisClient;
    this.cryptoOps = new CryptoOperations();
  }

  /**
   * Encrypt session data before storing in Redis
   */
  private async encryptSessionData(sessionInfo: SessionInfo): Promise<string> {
    try {
      // Create a unique key per tenant and environment for session encryption
      const keyType = `session_${sessionInfo.tenantId}_${process.env.NODE_ENV || 'development'}`;
      
      const encryptedPayload = await this.cryptoOps.encrypt(
        JSON.stringify(sessionInfo),
        keyType
      );
      
      // Store as JSON with encrypted data and metadata
      return JSON.stringify({
        encrypted: encryptedPayload.encryptedData,
        iv: encryptedPayload.iv,
        tag: encryptedPayload.tag,
        keyVersion: encryptedPayload.keyVersion,
        timestamp: Date.now()
      });
    } catch (error) {
      logger.error('Failed to encrypt session data', { error: (error as Error).message });
      throw new Error('Session encryption failed');
    }
  }

  /**
   * Decrypt session data retrieved from Redis
   */
  private async decryptSessionData(encryptedJson: string, tenantId: string): Promise<SessionInfo | null> {
    try {
      const encryptedObj = JSON.parse(encryptedJson);
      
      if (!encryptedObj.encrypted || !encryptedObj.iv) {
        logger.error('Invalid encrypted session data format');
        return null;
      }

      // Use tenant-specific key for decryption
      const keyType = `session_${tenantId}_${process.env.NODE_ENV || 'development'}`;
      
      const decryptedData = await this.cryptoOps.decrypt(
        encryptedObj.encrypted,
        encryptedObj.iv,
        encryptedObj.tag,
        keyType,
        encryptedObj.keyVersion
      );

      return JSON.parse(decryptedData) as SessionInfo;
    } catch (error) {
      logger.error('Failed to decrypt session data', { error: (error as Error).message });
      // On decryption failure, fail closed - return null
      return null;
    }
  }

  /**
   * Track a new session for a user with encrypted storage
   */
  async trackSession(sessionInfo: SessionInfo): Promise<boolean> {
    try {
      const { userId, sessionId, tenantId } = sessionInfo;

      // Check current active sessions for the user
      const currentSessions = await this.getUserSessions(userId, tenantId);

      // If at max capacity, evict the oldest session
      if (currentSessions.length >= this.MAX_CONCURRENT_SESSIONS) {
        await this.evictOldestSession(userId, tenantId);
      }

      // Store the new session with encrypted data
      const sessionKey = `session:${sessionId}`;
      const userSessionsKey = `user_sessions:${userId}`;

      // Encrypt session data before storing
      const encryptedSessionData = await this.encryptSessionData(sessionInfo);

      // Set encrypted session data with expiration
      await this.redis.setex(sessionKey, this.SESSION_EXPIRATION_SECONDS, encryptedSessionData);

      // Add session to user's session list
      await this.redis.sadd(userSessionsKey, sessionId);
      await this.redis.expire(userSessionsKey, this.SESSION_EXPIRATION_SECONDS);

      logger.info('Encrypted session tracked successfully', {
        userId,
        sessionId,
        currentSessionCount: await this.redis.scard(userSessionsKey)
      });

      return true;
    } catch (error) {
      logger.error('Failed to track encrypted session', { error: (error as Error).message });
      return false;
    }
  }

  /**
   * Validate session with enhanced IP tolerance for mobile users and encrypted session data
   */
  async validateSession(sessionId: string, currentIp: string, currentUserAgent: string, tenantId: string): Promise<{ isValid: boolean; message?: string }> {
    try {
      const sessionKey = `session:${sessionId}`;
      const encryptedSessionData = await this.redis.get(sessionKey);

      if (!encryptedSessionData) {
        return { isValid: false, message: 'Session not found' };
      }

      // Decrypt session data
      const sessionData = await this.decryptSessionData(encryptedSessionData, tenantId);

      if (!sessionData) {
        // Decryption failed - this is a critical security event
        logger.error('Session decryption failed - possible tampering', {
          sessionId,
          tenantId
        });

        // Log security event
        await SecurityMonitor.logEvent(
          SecurityEvent.SUSPICIOUS_ACTIVITY,
          {
            timestamp: new Date(),
            userId: 'unknown',
            ipAddress: currentIp,
            userAgent: currentUserAgent,
            metadata: {
              operation: 'session_decryption_failure',
              sessionId,
              tenantId
            }
          },
          'Session decryption failed - possible tampering'
        );

        return { isValid: false, message: 'Session data corrupted or tampered' };
      }

      // Refresh session expiration
      const encryptedSessionData = await this.encryptSessionData(sessionData);
      await this.redis.setex(sessionKey, this.SESSION_EXPIRATION_SECONDS, encryptedSessionData);

      const storedIp = sessionData.ip;
      const storedUserAgent = sessionData.userAgent;
      const userId = sessionData.userId;

      // Check if user agent is mobile
      const isMobileUser = this.MOBILE_USER_AGENT_REGEX.test(currentUserAgent);

      if (isMobileUser && this.MOBILE_IP_TOLERANCE_ENABLED) {
        // For mobile users, allow IP changes with tolerance
        const ipMatch = await this.checkMobileIpTolerance(storedIp, currentIp, userId);

        if (!ipMatch) {
          logger.warn('Mobile IP tolerance check failed', {
            userId,
            sessionId,
            storedIp,
            currentIp,
            userAgent: currentUserAgent
          });

          return { isValid: false, message: 'Mobile IP changed beyond tolerance' };
        }
      } else {
        // For desktop users, strict IP matching
        if (storedIp !== currentIp) {
          logger.warn('IP mismatch detected', {
            userId,
            sessionId,
            storedIp,
            currentIp,
            userAgent: currentUserAgent
          });

          // Log security event
          await SecurityMonitor.logEvent(
            SecurityEvent.SESSION_HIJACK_ATTEMPT,
            {
              timestamp: new Date(),
              userId,
              ipAddress: currentIp,
              userAgent: currentUserAgent,
              metadata: {
                originalIp: storedIp,
                newIp: currentIp,
                sessionType: isMobileUser ? 'mobile' : 'desktop'
              }
            },
            'IP mismatch in session binding'
          );

          return { isValid: false, message: 'IP address changed unexpectedly' };
        }
      }

      // Validate user agent hasn't changed significantly
      if (storedUserAgent !== currentUserAgent) {
        // For mobile users, allow some user agent variations
        if (isMobileUser) {
          const userAgentMatch = this.isSimilarUserAgent(storedUserAgent, currentUserAgent);
          if (!userAgentMatch) {
            logger.warn('Mobile user agent changed significantly', {
              userId,
              sessionId,
              storedUserAgent,
              currentUserAgent
            });

            return { isValid: false, message: 'User agent changed unexpectedly' };
          }
        } else {
          logger.warn('Desktop user agent changed', {
            userId,
            sessionId,
            storedUserAgent,
            currentUserAgent
          });

          return { isValid: false, message: 'User agent changed unexpectedly' };
        }
      }

      // Update last active time in the session data
      sessionData.lastActive = Date.now();
      const updatedEncryptedSessionData = await this.encryptSessionData(sessionData);
      await this.redis.setex(sessionKey, this.SESSION_EXPIRATION_SECONDS, updatedEncryptedSessionData);

      return { isValid: true };
    } catch (error) {
      logger.error('Session validation error', { error: (error as Error).message });
      return { isValid: false, message: 'Session validation failed' };
    }
  }

  /**
   * Check if IP change is acceptable for mobile users
   */
  private async checkMobileIpTolerance(storedIp: string, currentIp: string, userId: string): Promise<boolean> {
    // For now, we'll implement basic IP similarity check
    // In a production environment, you'd want to use GeoIP services to check if IPs are in the same region

    // Basic check: if IPs are very different, log for review
    if (storedIp !== currentIp) {
      logger.info('Mobile IP change detected but allowed due to tolerance', {
        userId,
        storedIp,
        currentIp
      });

      // Log as a geo-IP anomaly for monitoring
      await SecurityMonitor.logGeoIpAnomaly(
        {
          timestamp: new Date(),
          userId,
          ipAddress: currentIp,
          metadata: {
            previousIp: storedIp,
            currentIp,
            sessionType: 'mobile'
          }
        },
        storedIp,
        currentIp
      );
    }

    // For now, allow IP changes for mobile users
    // In a real implementation, you'd check against GeoIP data
    return true;
  }

  /**
   * Check if user agents are similar enough (for mobile apps that update)
   */
  private isSimilarUserAgent(storedUserAgent: string, currentUserAgent: string): boolean {
    // Basic similarity check - in production, implement more sophisticated comparison
    const storedIsMobile = this.MOBILE_USER_AGENT_REGEX.test(storedUserAgent);
    const currentIsMobile = this.MOBILE_USER_AGENT_REGEX.test(currentUserAgent);

    // Both should be mobile or both desktop
    if (storedIsMobile !== currentIsMobile) {
      return false;
    }

    // For mobile, check if they're from the same platform family
    if (storedIsMobile) {
      const storedPlatform = storedUserAgent.match(/(iPhone|Android|iPad)/i)?.[0]?.toLowerCase();
      const currentPlatform = currentUserAgent.match(/(iPhone|Android|iPad)/i)?.[0]?.toLowerCase();

      return storedPlatform === currentPlatform;
    }

    return true;
  }

  /**
   * Get all sessions for a user
   */
  private async getUserSessions(userId: string, tenantId: string): Promise<SessionInfo[]> {
    try {
      const userSessionsKey = `user_sessions:${userId}`;
      const sessionIds = await this.redis.smembers(userSessionsKey);

      const sessions: SessionInfo[] = [];
      for (const sessionId of sessionIds) {
        const sessionKey = `session:${sessionId}`;
        const encryptedSessionData = await this.redis.get(sessionKey);

        if (encryptedSessionData) {
          const sessionData = await this.decryptSessionData(encryptedSessionData, tenantId);
          if (sessionData) {
            sessions.push(sessionData);
          }
        }
      }

      // Sort by creation time (oldest first)
      return sessions.sort((a, b) => a.createdAt - b.createdAt);
    } catch (error) {
      logger.error('Failed to get user sessions', { error: (error as Error).message });
      return [];
    }
  }

  /**
   * Evict the oldest session for a user
   */
  private async evictOldestSession(userId: string, tenantId: string): Promise<void> {
    try {
      const sessions = await this.getUserSessions(userId, tenantId);
      if (sessions.length === 0) {
        return;
      }

      // Get the oldest session
      const oldestSession = sessions[0];
      const { sessionId } = oldestSession;

      // Remove from user's session list
      const userSessionsKey = `user_sessions:${userId}`;
      await this.redis.srem(userSessionsKey, sessionId);

      // Delete session data
      const sessionKey = `session:${sessionId}`;
      await this.redis.del(sessionKey);

      logger.info('Evicted oldest session due to max concurrent sessions limit', {
        userId,
        sessionId,
        sessionCreatedAt: new Date(oldestSession.createdAt).toISOString()
      });

      // Log the eviction
      await SecurityMonitor.logEvent(
        SecurityEvent.AUTH_SUCCESS,
        {
          timestamp: new Date(),
          userId,
          metadata: {
            operation: 'session_eviction',
            reason: 'max_concurrent_sessions',
            sessionId
          }
        },
        `Evicted oldest session for user ${userId}`
      );
    } catch (error) {
      logger.error('Failed to evict oldest session', { error: (error as Error).message });
    }
  }

  /**
   * Remove a specific session
   */
  async removeSession(sessionId: string, userId: string, tenantId: string): Promise<void> {
    try {
      // Remove from user's session list
      const userSessionsKey = `user_sessions:${userId}`;
      await this.redis.srem(userSessionsKey, sessionId);

      // Delete session data
      const sessionKey = `session:${sessionId}`;
      await this.redis.del(sessionKey);

      logger.info('Session removed', { userId, sessionId });
    } catch (error) {
      logger.error('Failed to remove session', { error: (error as Error).message });
    }
  }

  /**
   * Get active session count for a user
   */
  async getActiveSessionCount(userId: string): Promise<number> {
    try {
      const userSessionsKey = `user_sessions:${userId}`;
      return await this.redis.scard(userSessionsKey);
    } catch (error) {
      logger.error('Failed to get active session count', { error: (error as Error).message });
      return 0;
    }
  }

  /**
   * Cleanup expired sessions (call periodically)
   */
  async cleanupExpiredSessions(): Promise<void> {
    // This would be called periodically to clean up expired sessions
    // Implementation depends on your specific needs
    logger.info('Session cleanup completed');
  }
}