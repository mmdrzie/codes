import { Redis } from '@upstash/redis';
import { createHash, randomBytes } from 'crypto';
import { logger } from '../logger';
import { DeviceFingerprint } from './device-fingerprint';

export interface ActiveSession {
  sessionId: string;
  userId: string;
  deviceId: string;
  deviceFingerprint: DeviceFingerprint;
  ipAddress: string;
  userAgent: string;
  createdAt: number;
  lastAccessed: number;
  expiresAt: number;
  location?: string;
  isActive: boolean;
}

export class ConcurrentSessionManager {
  private redis: Redis;
  private readonly maxConcurrentSessions: number;
  private readonly sessionSalt: string;

  constructor(maxConcurrentSessions: number = 3) {
    this.maxConcurrentSessions = maxConcurrentSessions;
    this.sessionSalt = process.env.SESSION_BINDING_SALT || this.generateSalt();
    
    // Initialize Redis connection
    this.redis = Redis.fromEnv();
  }

  /**
   * Generate a secure salt for hashing
   */
  private generateSalt(): string {
    return randomBytes(32).toString('hex');
  }

  /**
   * Create a new session for a user, enforcing concurrent session limits
   */
  async createSession(
    userId: string,
    sessionId: string,
    deviceFingerprint: DeviceFingerprint,
    ipAddress: string,
    userAgent: string
  ): Promise<{ success: boolean; message?: string; sessions?: ActiveSession[] }> {
    try {
      const userSessionsKey = `user_sessions:${userId}`;
      const sessionKey = `session:${sessionId}`;
      
      // Get current active sessions for the user
      const currentSessions = await this.getActiveSessions(userId);
      
      // Check if user has reached the maximum concurrent session limit
      if (currentSessions.length >= this.maxConcurrentSessions) {
        // Remove oldest session to make room for the new one (FIFO)
        const oldestSession = currentSessions.reduce((oldest, current) => 
          current.createdAt < oldest.createdAt ? current : oldest
        );
        
        await this.terminateSession(oldestSession.sessionId, userId);
        
        logger.info('Evicted oldest session due to concurrent session limit', {
          userId,
          evictedSessionId: oldestSession.sessionId,
          newSessionId: sessionId
        });
      }
      
      // Create new session object
      const newSession: ActiveSession = {
        sessionId,
        userId,
        deviceId: this.generateDeviceId(deviceFingerprint),
        deviceFingerprint,
        ipAddress,
        userAgent,
        createdAt: Date.now(),
        lastAccessed: Date.now(),
        expiresAt: Date.now() + (24 * 60 * 60 * 1000), // 24 hours from now
        isActive: true
      };
      
      // Store the new session in Redis
      await this.redis.setex(sessionKey, 24 * 60 * 60, newSession); // 24 hours TTL
      
      // Add session ID to user's session set
      await this.redis.sadd(userSessionsKey, sessionId);
      await this.redis.expire(userSessionsKey, 24 * 60 * 60); // 24 hours TTL
      
      logger.info('New session created', {
        userId,
        sessionId,
        currentSessionCount: await this.redis.scard(userSessionsKey)
      });
      
      // Get updated list of active sessions
      const updatedSessions = await this.getActiveSessions(userId);
      
      return {
        success: true,
        sessions: updatedSessions
      };
    } catch (error) {
      logger.error('Failed to create session', {
        error: (error as Error).message,
        userId,
        sessionId
      });
      
      return {
        success: false,
        message: 'Failed to create session'
      };
    }
  }

  /**
   * Get all active sessions for a user
   */
  async getActiveSessions(userId: string): Promise<ActiveSession[]> {
    try {
      const userSessionsKey = `user_sessions:${userId}`;
      const sessionIds = await this.redis.smembers(userSessionsKey);
      
      const activeSessions: ActiveSession[] = [];
      
      for (const sessionId of sessionIds) {
        const sessionKey = `session:${sessionId}`;
        const session = await this.redis.get<ActiveSession>(sessionKey);
        
        if (session && session.isActive && session.expiresAt > Date.now()) {
          activeSessions.push(session);
        } else if (session && (!session.isActive || session.expiresAt <= Date.now())) {
          // Clean up inactive or expired sessions
          await this.redis.srem(userSessionsKey, sessionId);
          if (session && session.isActive) {
            // Mark as inactive in the session data too
            session.isActive = false;
            await this.redis.setex(sessionKey, 24 * 60 * 60, session);
          }
        }
      }
      
      return activeSessions;
    } catch (error) {
      logger.error('Failed to get active sessions', {
        error: (error as Error).message,
        userId
      });
      
      return [];
    }
  }

  /**
   * Terminate a specific session
   */
  async terminateSession(sessionId: string, userId: string): Promise<boolean> {
    try {
      const sessionKey = `session:${sessionId}`;
      const userSessionsKey = `user_sessions:${userId}`;
      
      // Get the session to log details
      const session = await this.redis.get<ActiveSession>(sessionKey);
      
      // Remove session from user's session set
      await this.redis.srem(userSessionsKey, sessionId);
      
      // Delete the session data
      await this.redis.del(sessionKey);
      
      if (session) {
        logger.info('Session terminated', {
          userId,
          sessionId,
          terminatedAt: new Date().toISOString()
        });
      }
      
      return true;
    } catch (error) {
      logger.error('Failed to terminate session', {
        error: (error as Error).message,
        userId,
        sessionId
      });
      
      return false;
    }
  }

  /**
   * Terminate all sessions for a user (logout from all devices)
   */
  async terminateAllSessions(userId: string): Promise<boolean> {
    try {
      const userSessionsKey = `user_sessions:${userId}`;
      const sessionIds = await this.redis.smembers(userSessionsKey);
      
      // Terminate each session individually
      for (const sessionId of sessionIds) {
        await this.terminateSession(sessionId, userId);
      }
      
      logger.info('All sessions terminated for user', {
        userId,
        terminatedSessionCount: sessionIds.length
      });
      
      return true;
    } catch (error) {
      logger.error('Failed to terminate all sessions', {
        error: (error as Error).message,
        userId
      });
      
      return false;
    }
  }

  /**
   * Verify if a session is still valid and active
   */
  async verifySession(sessionId: string, userId: string): Promise<{ isValid: boolean; session?: ActiveSession }> {
    try {
      const sessionKey = `session:${sessionId}`;
      const session = await this.redis.get<ActiveSession>(sessionKey);
      
      if (!session) {
        return { isValid: false };
      }
      
      if (!session.isActive || session.expiresAt <= Date.now() || session.userId !== userId) {
        // Session is invalid, clean up
        await this.terminateSession(sessionId, userId);
        return { isValid: false };
      }
      
      // Update last accessed time
      session.lastAccessed = Date.now();
      await this.redis.setex(sessionKey, 24 * 60 * 60, session);
      
      return {
        isValid: true,
        session
      };
    } catch (error) {
      logger.error('Failed to verify session', {
        error: (error as Error).message,
        userId,
        sessionId
      });
      
      return { isValid: false };
    }
  }

  /**
   * Get session count for a user
   */
  async getSessionCount(userId: string): Promise<number> {
    try {
      const sessions = await this.getActiveSessions(userId);
      return sessions.length;
    } catch (error) {
      logger.error('Failed to get session count', {
        error: (error as Error).message,
        userId
      });
      
      return 0;
    }
  }

  /**
   * Get session by ID
   */
  async getSessionById(sessionId: string): Promise<ActiveSession | null> {
    try {
      const sessionKey = `session:${sessionId}`;
      const session = await this.redis.get<ActiveSession>(sessionKey);
      
      if (session && session.isActive && session.expiresAt > Date.now()) {
        return session;
      }
      
      return null;
    } catch (error) {
      logger.error('Failed to get session by ID', {
        error: (error as Error).message,
        sessionId
      });
      
      return null;
    }
  }

  /**
   * Update session activity time
   */
  async updateSessionActivity(sessionId: string): Promise<boolean> {
    try {
      const sessionKey = `session:${sessionId}`;
      const session = await this.redis.get<ActiveSession>(sessionKey);
      
      if (!session || !session.isActive || session.expiresAt <= Date.now()) {
        return false;
      }
      
      session.lastAccessed = Date.now();
      await this.redis.setex(sessionKey, 24 * 60 * 60, session);
      
      return true;
    } catch (error) {
      logger.error('Failed to update session activity', {
        error: (error as Error).message,
        sessionId
      });
      
      return false;
    }
  }

  /**
   * Generate a device ID based on device fingerprint
   */
  private generateDeviceId(fingerprint: DeviceFingerprint): string {
    const fingerprintStr = JSON.stringify(fingerprint);
    return createHash('sha256')
      .update(fingerprintStr + this.sessionSalt)
      .digest('hex');
  }

  /**
   * Check if a user has reached the maximum concurrent session limit
   */
  async isAtMaxConcurrentSessions(userId: string): Promise<boolean> {
    const sessionCount = await this.getSessionCount(userId);
    return sessionCount >= this.maxConcurrentSessions;
  }

  /**
   * Clean up expired sessions (should be called periodically)
   */
  async cleanupExpiredSessions(): Promise<number> {
    // This method would normally scan through all sessions to find expired ones
    // However, since we're using Redis TTL, this is largely handled automatically
    // We'll just log the cleanup event
    
    logger.info('Session cleanup completed');
    return 0;
  }
}