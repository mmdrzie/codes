import { Redis } from 'ioredis';
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
}

export class SessionManager {
  private redis: Redis;
  private readonly MAX_CONCURRENT_SESSIONS = parseInt(process.env.MAX_CONCURRENT_SESSIONS || '5', 10);
  private readonly SESSION_EXPIRATION_SECONDS = 60 * 60 * 24; // 24 hours
  private readonly MOBILE_USER_AGENT_REGEX = /mobile|android|iphone|ipad|phone|tablet|ios/i;
  private readonly MOBILE_IP_TOLERANCE_ENABLED = process.env.MOBILE_IP_TOLERANCE_ENABLED === 'true';
  
  constructor(redisClient: Redis) {
    this.redis = redisClient;
  }

  /**
   * Track a new session for a user
   */
  async trackSession(sessionInfo: SessionInfo): Promise<boolean> {
    try {
      const { userId, sessionId } = sessionInfo;
      
      // Check current active sessions for the user
      const currentSessions = await this.getUserSessions(userId);
      
      // If at max capacity, evict the oldest session
      if (currentSessions.length >= this.MAX_CONCURRENT_SESSIONS) {
        await this.evictOldestSession(userId);
      }
      
      // Store the new session
      const sessionKey = `session:${sessionId}`;
      const userSessionsKey = `user_sessions:${userId}`;
      
      // Set session data with expiration
      await this.redis.hset(sessionKey, {
        userId: sessionInfo.userId,
        ip: sessionInfo.ip,
        userAgent: sessionInfo.userAgent,
        createdAt: sessionInfo.createdAt.toString(),
        lastActive: sessionInfo.lastActive.toString(),
        expiresAt: sessionInfo.expiresAt.toString()
      });
      
      await this.redis.expire(sessionKey, this.SESSION_EXPIRATION_SECONDS);
      
      // Add session to user's session list
      await this.redis.sadd(userSessionsKey, sessionId);
      await this.redis.expire(userSessionsKey, this.SESSION_EXPIRATION_SECONDS);
      
      logger.info('Session tracked successfully', {
        userId,
        sessionId,
        currentSessionCount: await this.redis.scard(userSessionsKey)
      });
      
      return true;
    } catch (error) {
      logger.error('Failed to track session', { error: (error as Error).message });
      return false;
    }
  }

  /**
   * Validate session with enhanced IP tolerance for mobile users
   */
  async validateSession(sessionId: string, currentIp: string, currentUserAgent: string): Promise<{ isValid: boolean; message?: string }> {
    try {
      const sessionKey = `session:${sessionId}`;
      const sessionData = await this.redis.hgetall(sessionKey);
      
      if (!Object.keys(sessionData).length) {
        return { isValid: false, message: 'Session not found' };
      }
      
      // Refresh session expiration
      await this.redis.expire(sessionKey, this.SESSION_EXPIRATION_SECONDS);
      
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
      
      // Update last active time
      await this.redis.hset(sessionKey, 'lastActive', Date.now().toString());
      
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
  private async getUserSessions(userId: string): Promise<SessionInfo[]> {
    try {
      const userSessionsKey = `user_sessions:${userId}`;
      const sessionIds = await this.redis.smembers(userSessionsKey);
      
      const sessions: SessionInfo[] = [];
      for (const sessionId of sessionIds) {
        const sessionKey = `session:${sessionId}`;
        const sessionData = await this.redis.hgetall(sessionKey);
        
        if (Object.keys(sessionData).length) {
          sessions.push({
            sessionId,
            userId: sessionData.userId,
            ip: sessionData.ip,
            userAgent: sessionData.userAgent,
            createdAt: parseInt(sessionData.createdAt),
            lastActive: parseInt(sessionData.lastActive),
            expiresAt: parseInt(sessionData.expiresAt)
          });
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
  private async evictOldestSession(userId: string): Promise<void> {
    try {
      const sessions = await this.getUserSessions(userId);
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
  async removeSession(sessionId: string, userId: string): Promise<void> {
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