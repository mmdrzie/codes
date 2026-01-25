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
  // Additional fields for cryptographic binding
  deviceFingerprint?: string;
  sessionKey?: string;
  boundToUserId: string; // Explicitly bind to user
  boundToDevice: string; // Bind to device fingerprint
}

export class SecureSessionManager {
  private redis: Redis;
  private cryptoOps: CryptoOperations;
  private readonly MAX_CONCURRENT_SESSIONS = parseInt(process.env.MAX_CONCURRENT_SESSIONS || '5', 10);
  private readonly SESSION_EXPIRATION_SECONDS = 60 * 60 * 24; // 24 hours
  private readonly MOBILE_USER_AGENT_REGEX = /mobile|android|iphone|ipad|phone|tablet|ios/i;
  private readonly MOBILE_IP_TOLERANCE_ENABLED = process.env.MOBILE_IP_TOLERANCE_ENABLED === 'true';
  private readonly SESSION_KEY_PREFIX = 'session_bound:';
  private readonly USER_SESSIONS_PREFIX = 'user_sessions_bound:';

  constructor(redisClient: Redis) {
    this.redis = redisClient;
    this.cryptoOps = new CryptoOperations();
  }

  /**
   * Generate cryptographically bound session data
   */
  private async generateCryptographicSessionData(sessionInfo: SessionInfo): Promise<string> {
    try {
      // Create a unique key per user, device, and environment for session binding
      const keyType = `session_bound_${sessionInfo.tenantId}_${sessionInfo.userId}_${sessionInfo.deviceFingerprint || 'unknown'}_${process.env.NODE_ENV || 'development'}`;
      
      // Create session key for this specific session
      const sessionKey = await this.generateSessionKey(sessionInfo);
      
      // Include all binding information in the session data
      const boundSessionData = {
        ...sessionInfo,
        sessionKey, // Include the session-specific key
        boundToUserId: sessionInfo.userId, // Explicit binding to user
        boundToDevice: sessionInfo.deviceFingerprint || 'unknown' // Explicit binding to device
      };
      
      const encryptedPayload = await this.cryptoOps.encrypt(
        JSON.stringify(boundSessionData),
        keyType
      );
      
      // Store as JSON with encrypted data and metadata
      return JSON.stringify({
        encrypted: encryptedPayload.encryptedData,
        iv: encryptedPayload.iv,
        tag: encryptedPayload.tag,
        keyVersion: encryptedPayload.keyVersion,
        timestamp: Date.now(),
        // Include cryptographic proof of binding
        bindingProof: await this.generateBindingProof(boundSessionData)
      });
    } catch (error) {
      logger.error('Failed to generate cryptographic session data', { error: (error as Error).message });
      throw new Error('Session encryption failed');
    }
  }

  /**
   * Generate a unique session key for cryptographic binding
   */
  private async generateSessionKey(sessionInfo: SessionInfo): Promise<string> {
    // Generate a cryptographically strong session key
    const sessionKeyData = JSON.stringify({
      userId: sessionInfo.userId,
      deviceId: sessionInfo.deviceFingerprint || 'unknown',
      sessionId: sessionInfo.sessionId,
      timestamp: Date.now()
    });
    
    // Create a hash-based session key
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(sessionKeyData).digest('hex');
  }

  /**
   * Generate cryptographic binding proof
   */
  private async generateBindingProof(sessionData: SessionInfo): Promise<string> {
    const bindingData = JSON.stringify({
      userId: sessionData.boundToUserId,
      deviceId: sessionData.boundToDevice,
      sessionId: sessionData.sessionId,
      timestamp: sessionData.createdAt
    });
    
    const crypto = require('crypto');
    return crypto.createHmac('sha256', process.env.SESSION_BINDING_SECRET || 'default-binding-secret')
      .update(bindingData)
      .digest('hex');
  }

  /**
   * Verify cryptographic binding proof
   */
  private async verifyBindingProof(sessionData: SessionInfo, storedProof: string): Promise<boolean> {
    const bindingData = JSON.stringify({
      userId: sessionData.boundToUserId,
      deviceId: sessionData.boundToDevice,
      sessionId: sessionData.sessionId,
      timestamp: sessionData.createdAt
    });
    
    const crypto = require('crypto');
    const computedProof = crypto.createHmac('sha256', process.env.SESSION_BINDING_SECRET || 'default-binding-secret')
      .update(bindingData)
      .digest('hex');
    
    return crypto.timingSafeEqual(Buffer.from(computedProof), Buffer.from(storedProof));
  }

  /**
   * Decrypt and validate cryptographically bound session data retrieved from Redis
   */
  private async decryptAndValidateBoundSessionData(encryptedJson: string, tenantId: string, userId: string, deviceFingerprint: string): Promise<SessionInfo | null> {
    try {
      const encryptedObj = JSON.parse(encryptedJson);
      
      if (!encryptedObj.encrypted || !encryptedObj.iv) {
        logger.error('Invalid encrypted session data format');
        return null;
      }

      // Use tenant, user, and device-specific key for decryption
      const keyType = `session_bound_${tenantId}_${userId}_${deviceFingerprint || 'unknown'}_${process.env.NODE_ENV || 'development'}`;
      
      const decryptedData = await this.cryptoOps.decrypt(
        encryptedObj.encrypted,
        encryptedObj.iv,
        encryptedObj.tag,
        keyType,
        encryptedObj.keyVersion
      );

      const sessionData = JSON.parse(decryptedData) as SessionInfo;

      // Verify cryptographic binding proof
      if (!encryptedObj.bindingProof || !(await this.verifyBindingProof(sessionData, encryptedObj.bindingProof))) {
        logger.error('Session binding proof verification failed - possible tampering', {
          sessionId: sessionData.sessionId,
          userId: sessionData.userId
        });
        return null;
      }

      // Additional validation: ensure session is bound to the expected user and device
      if (sessionData.boundToUserId !== userId) {
        logger.error('Session user binding mismatch', {
          sessionId: sessionData.sessionId,
          expectedUser: userId,
          boundToUser: sessionData.boundToUserId
        });
        return null;
      }

      if (sessionData.boundToDevice !== deviceFingerprint) {
        logger.error('Session device binding mismatch', {
          sessionId: sessionData.sessionId,
          expectedDevice: deviceFingerprint,
          boundToDevice: sessionData.boundToDevice
        });
        return null;
      }

      return sessionData;
    } catch (error) {
      logger.error('Failed to decrypt and validate bound session data', { error: (error as Error).message });
      // On decryption failure, fail closed - return null
      return null;
    }
  }

  /**
   * Track a new cryptographically bound session for a user with encrypted storage
   */
  async trackSession(sessionInfo: SessionInfo): Promise<boolean> {
    try {
      const { userId, sessionId, tenantId, deviceFingerprint = 'unknown' } = sessionInfo;

      // Check current active sessions for the user
      const currentSessions = await this.getUserSessions(userId, tenantId);

      // If at max capacity, evict the oldest session
      if (currentSessions.length >= this.MAX_CONCURRENT_SESSIONS) {
        await this.evictOldestSession(userId, tenantId);
      }

      // Store the new session with cryptographic binding
      const sessionKey = `${this.SESSION_KEY_PREFIX}${sessionId}`;
      const userSessionsKey = `${this.USER_SESSIONS_PREFIX}${userId}`;

      // Generate cryptographically bound session data
      const boundSessionData = await this.generateCryptographicSessionData(sessionInfo);

      // Set encrypted session data with expiration
      await this.redis.setex(sessionKey, this.SESSION_EXPIRATION_SECONDS, boundSessionData);

      // Add session to user's session list
      await this.redis.sadd(userSessionsKey, sessionId);
      await this.redis.expire(userSessionsKey, this.SESSION_EXPIRATION_SECONDS);

      logger.info('Cryptographically bound session tracked successfully', {
        userId,
        sessionId,
        deviceFingerprint,
        currentSessionCount: await this.redis.scard(userSessionsKey)
      });

      return true;
    } catch (error) {
      logger.error('Failed to track cryptographically bound session', { error: (error as Error).message });
      return false;
    }
  }

  /**
   * Validate cryptographically bound session with enhanced IP tolerance for mobile users
   */
  async validateSession(sessionId: string, currentIp: string, currentUserAgent: string, tenantId: string, userId: string, deviceFingerprint: string): Promise<{ isValid: boolean; message?: string }> {
    try {
      const sessionKey = `${this.SESSION_KEY_PREFIX}${sessionId}`;
      const encryptedSessionData = await this.redis.get(sessionKey);

      if (!encryptedSessionData) {
        return { isValid: false, message: 'Session not found' };
      }

      // Decrypt and validate bound session data
      const sessionData = await this.decryptAndValidateBoundSessionData(encryptedSessionData, tenantId, userId, deviceFingerprint);

      if (!sessionData) {
        // Decryption failed or binding verification failed - this is a critical security event
        logger.error('Session decryption or binding verification failed - possible tampering', {
          sessionId,
          tenantId,
          userId
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
              operation: 'session_validation_failure',
              sessionId,
              tenantId,
              deviceFingerprint
            }
          },
          'Session decryption or binding verification failed - possible tampering'
        );

        return { isValid: false, message: 'Session data corrupted, tampered, or binding invalid' };
      }

      // Refresh session expiration with bound data
      const boundSessionData = await this.generateCryptographicSessionData(sessionData);
      await this.redis.setex(sessionKey, this.SESSION_EXPIRATION_SECONDS, boundSessionData);

      const storedIp = sessionData.ip;
      const storedUserAgent = sessionData.userAgent;

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
      const updatedBoundSessionData = await this.generateCryptographicSessionData(sessionData);
      await this.redis.setex(sessionKey, this.SESSION_EXPIRATION_SECONDS, updatedBoundSessionData);

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
      const userSessionsKey = `${this.USER_SESSIONS_PREFIX}${userId}`;
      const sessionIds = await this.redis.smembers(userSessionsKey);

      const sessions: SessionInfo[] = [];
      for (const sessionId of sessionIds) {
        const sessionKey = `${this.SESSION_KEY_PREFIX}${sessionId}`;
        const encryptedSessionData = await this.redis.get(sessionKey);

        if (encryptedSessionData) {
          // We can't decrypt without device fingerprint, so we'll decrypt with placeholder
          // In practice, you'd want to store session metadata separately for listing
          try {
            const parsedData = JSON.parse(encryptedSessionData);
            // Extract basic session info without full decryption for listing purposes
            const basicInfo = {
              sessionId,
              userId,
              createdAt: 0, // Will be populated after decryption
              lastActive: 0,
              expiresAt: 0,
              tenantId,
              ip: 'unknown',
              userAgent: 'unknown',
              deviceFingerprint: 'unknown',
              boundToUserId: userId,
              boundToDevice: 'unknown'
            };
            
            // For actual retrieval, we need the device fingerprint
            // So we'll just return the session IDs for this method
            sessions.push(basicInfo);
          } catch (parseError) {
            logger.error('Failed to parse session data for listing', { error: (parseError as Error).message });
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
   * Get session by ID with full validation
   */
  async getSessionById(sessionId: string, userId: string, deviceFingerprint: string, tenantId: string): Promise<SessionInfo | null> {
    try {
      const sessionKey = `${this.SESSION_KEY_PREFIX}${sessionId}`;
      const encryptedSessionData = await this.redis.get(sessionKey);

      if (!encryptedSessionData) {
        return null;
      }

      // Decrypt and validate with specific user and device context
      return await this.decryptAndValidateBoundSessionData(encryptedSessionData, tenantId, userId, deviceFingerprint);
    } catch (error) {
      logger.error('Failed to get session by ID', { error: (error as Error).message, sessionId });
      return null;
    }
  }

  /**
   * Evict the oldest session for a user
   */
  private async evictOldestSession(userId: string, tenantId: string): Promise<void> {
    try {
      // Get all session IDs for the user
      const userSessionsKey = `${this.USER_SESSIONS_PREFIX}${userId}`;
      const sessionIds = await this.redis.smembers(userSessionsKey);

      if (sessionIds.length === 0) {
        return;
      }

      // Find oldest session by checking timestamps (requires individual retrieval)
      let oldestSessionId: string | null = null;
      let oldestTimestamp = Number.MAX_SAFE_INTEGER;

      for (const sessionId of sessionIds) {
        const sessionKey = `${this.SESSION_KEY_PREFIX}${sessionId}`;
        const encryptedSessionData = await this.redis.get(sessionKey);

        if (encryptedSessionData) {
          try {
            const parsedData = JSON.parse(encryptedSessionData);
            // Access the timestamp from the encrypted data structure
            const sessionTimestamp = parsedData.timestamp || Date.now();
            if (sessionTimestamp < oldestTimestamp) {
              oldestTimestamp = sessionTimestamp;
              oldestSessionId = sessionId;
            }
          } catch (parseError) {
            logger.error('Failed to parse session data during eviction', { error: (parseError as Error).message });
          }
        }
      }

      if (oldestSessionId) {
        // Remove from user's session list
        await this.redis.srem(userSessionsKey, oldestSessionId);

        // Delete session data
        const sessionKey = `${this.SESSION_KEY_PREFIX}${oldestSessionId}`;
        await this.redis.del(sessionKey);

        logger.info('Evicted oldest session due to max concurrent sessions limit', {
          userId,
          sessionId: oldestSessionId,
          timestamp: new Date(oldestTimestamp).toISOString()
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
              sessionId: oldestSessionId
            }
          },
          `Evicted oldest session for user ${userId}`
        );
      }
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
      const userSessionsKey = `${this.USER_SESSIONS_PREFIX}${userId}`;
      await this.redis.srem(userSessionsKey, sessionId);

      // Delete session data
      const sessionKey = `${this.SESSION_KEY_PREFIX}${sessionId}`;
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
      const userSessionsKey = `${this.USER_SESSIONS_PREFIX}${userId}`;
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
    try {
      logger.info('Starting session cleanup process');
      
      // Get all keys matching our session pattern
      const sessionKeys = await this.redis.keys(`${this.SESSION_KEY_PREFIX}*`);
      
      let cleanedUpCount = 0;
      let checkedCount = 0;
      
      for (const key of sessionKeys) {
        try {
          // Check if the session data is still valid (not expired)
          const sessionData = await this.redis.get(key);
          
          if (sessionData) {
            try {
              const parsedData = JSON.parse(sessionData);
              
              // Check if the session has expired based on our internal timestamp
              if (parsedData.timestamp && 
                  (Date.now() - parsedData.timestamp) > (this.SESSION_EXPIRATION_SECONDS * 1000)) {
                
                // Session has expired, remove it
                await this.redis.del(key);
                cleanedUpCount++;
                
                logger.info('Cleaned up expired session', { 
                  key, 
                  timestamp: parsedData.timestamp,
                  current_time: Date.now()
                });
              }
            } catch (parseError) {
              logger.error('Failed to parse session data during cleanup', { 
                error: (parseError as Error).message, 
                key 
              });
              // If we can't parse it, remove it anyway
              await this.redis.del(key);
              cleanedUpCount++;
            }
          }
          
          checkedCount++;
        } catch (keyError) {
          logger.error('Error processing session key during cleanup', { 
            error: (keyError as Error).message, 
            key 
          });
        }
      }
      
      logger.info('Session cleanup completed', {
        cleanedUpCount,
        checkedCount,
        totalSessions: sessionKeys.length
      });
    } catch (error) {
      logger.error('Failed to cleanup expired sessions', { error: (error as Error).message });
    }
  }

  /**
   * Force logout all sessions for a user (e.g., password change, admin action)
   */
  async forceLogoutUser(userId: string): Promise<void> {
    try {
      const userSessionsKey = `${this.USER_SESSIONS_PREFIX}${userId}`;
      const sessionIds = await this.redis.smembers(userSessionsKey);

      // Remove all session data
      for (const sessionId of sessionIds) {
        const sessionKey = `${this.SESSION_KEY_PREFIX}${sessionId}`;
        await this.redis.del(sessionKey);
      }

      // Clear the user's session list
      await this.redis.del(userSessionsKey);

      logger.info('Forced logout for user', { 
        userId, 
        sessionCount: sessionIds.length,
        sessionIds 
      });

      // Log the forced logout
      await SecurityMonitor.logEvent(
        SecurityEvent.SESSION_REVOKED,
        {
          timestamp: new Date(),
          userId,
          metadata: {
            operation: 'force_logout',
            sessionCount: sessionIds.length,
            revokedSessions: sessionIds
          }
        },
        `Forced logout for user ${userId} - ${sessionIds.length} sessions revoked`
      );
    } catch (error) {
      logger.error('Failed to force logout user', { error: (error as Error).message, userId });
    }
  }

  /**
   * Rotate session key for enhanced security (called periodically)
   */
  async rotateSessionKey(sessionId: string, userId: string, deviceFingerprint: string, tenantId: string): Promise<boolean> {
    try {
      const sessionKey = `${this.SESSION_KEY_PREFIX}${sessionId}`;
      const encryptedSessionData = await this.redis.get(sessionKey);

      if (!encryptedSessionData) {
        return false;
      }

      // Decrypt the current session data
      const sessionData = await this.decryptAndValidateBoundSessionData(encryptedSessionData, tenantId, userId, deviceFingerprint);

      if (!sessionData) {
        logger.error('Cannot rotate session key - session validation failed', { sessionId, userId });
        return false;
      }

      // Update the session creation time to trigger a new key derivation
      sessionData.createdAt = Date.now();
      
      // Generate new bound session data with fresh key
      const newBoundSessionData = await this.generateCryptographicSessionData(sessionData);

      // Update the session with new encrypted data
      await this.redis.setex(sessionKey, this.SESSION_EXPIRATION_SECONDS, newBoundSessionData);

      logger.info('Session key rotated successfully', { sessionId, userId });

      return true;
    } catch (error) {
      logger.error('Failed to rotate session key', { error: (error as Error).message, sessionId, userId });
      return false;
    }
  }
}