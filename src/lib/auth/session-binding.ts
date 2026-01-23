import { Redis } from '@upstash/redis';
import { createHash } from 'crypto';
import { logger } from '../logger';

export interface SessionMetadata {
  sessionId: string;
  userId: string;
  ipHash: string;
  userAgentHash: string;
  createdAt: number;
  lastAccessed: number;
  idleTimeout: number;
  absoluteTimeout: number;
  isActive: boolean;
}

export class SessionBindingValidator {
  private redis: Redis;
  private readonly sessionSalt: string;
  private readonly idleTimeoutMs: number;
  private readonly absoluteTimeoutMs: number;
  private readonly strictMode: boolean;

  constructor() {
    this.sessionSalt = process.env.SESSION_BINDING_SALT || this.generateSalt();
    this.idleTimeoutMs = parseInt(process.env.SESSION_IDLE_TIMEOUT_MS || '900000', 10); // 15 minutes default
    this.absoluteTimeoutMs = parseInt(process.env.SESSION_ABSOLUTE_TIMEOUT_MS || '28800000', 10); // 8 hours default
    this.strictMode = process.env.SESSION_BINDING_STRICT_MODE === 'true';
    
    // Initialize Redis connection
    this.redis = Redis.fromEnv();
  }

  /**
   * Generate a secure salt for hashing
   */
  private generateSalt(): string {
    const crypto = require('crypto') as typeof import('crypto');
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Hash IP address with salt for privacy
   */
  private hashIp(ip: string): string {
    return createHash('sha256')
      .update(ip + this.sessionSalt)
      .digest('hex');
  }

  /**
   * Hash User-Agent for consistent fingerprinting
   */
  private hashUserAgent(userAgent: string): string {
    // Extract stable parts of user agent to avoid minor version changes
    const stableUA = userAgent.replace(/\s*\([^)]+\)/g, '').trim();
    return createHash('sha256')
      .update(stableUA + this.sessionSalt)
      .digest('hex');
  }

  /**
   * Create session metadata with binding information
   */
  async createSessionBinding(
    sessionId: string,
    userId: string,
    ip: string,
    userAgent: string
  ): Promise<SessionMetadata> {
    const metadata: SessionMetadata = {
      sessionId,
      userId,
      ipHash: this.hashIp(ip),
      userAgentHash: this.hashUserAgent(userAgent),
      createdAt: Date.now(),
      lastAccessed: Date.now(),
      idleTimeout: this.idleTimeoutMs,
      absoluteTimeout: this.absoluteTimeoutMs,
      isActive: true
    };

    try {
      // Store session metadata in Redis with TTL
      const sessionKey = `session_binding:${sessionId}`;
      await this.redis.setex(sessionKey, this.calculateSessionTtl(), metadata);
      
      logger.info('Session binding created', {
        sessionId,
        userId,
        ipHash: metadata.ipHash,
        userAgentHash: metadata.userAgentHash
      });
      
      return metadata;
    } catch (error) {
      logger.error('Failed to create session binding', {
        error: (error as Error).message,
        sessionId,
        userId
      });
      throw new Error('Session binding creation failed');
    }
  }

  /**
   * Validate session binding against current request
   */
  async validateSessionBinding(
    sessionId: string,
    userId: string,
    currentIp: string,
    currentUserAgent: string
  ): Promise<{ isValid: boolean; reason?: string; metadata?: SessionMetadata }> {
    try {
      const sessionKey = `session_binding:${sessionId}`;
      const storedMetadata = await this.redis.get<SessionMetadata>(sessionKey);

      if (!storedMetadata) {
        logger.warn('Session binding not found', {
          sessionId,
          userId,
          currentIp
        });
        
        return {
          isValid: false,
          reason: 'Session binding not found'
        };
      }

      // Check if session is still active
      if (!storedMetadata.isActive) {
        logger.warn('Session binding is inactive', {
          sessionId,
          userId,
          currentIp
        });
        
        return {
          isValid: false,
          reason: 'Session is inactive'
        };
      }

      // Check absolute timeout
      if (Date.now() - storedMetadata.createdAt > storedMetadata.absoluteTimeout) {
        logger.warn('Session absolute timeout exceeded', {
          sessionId,
          userId,
          currentIp,
          timeElapsed: Date.now() - storedMetadata.createdAt
        });
        
        await this.invalidateSession(sessionId);
        return {
          isValid: false,
          reason: 'Session absolute timeout exceeded'
        };
      }

      // Check idle timeout
      if (Date.now() - storedMetadata.lastAccessed > storedMetadata.idleTimeout) {
        logger.warn('Session idle timeout exceeded', {
          sessionId,
          userId,
          currentIp,
          lastAccessed: storedMetadata.lastAccessed,
          idleTimeout: storedMetadata.idleTimeout
        });
        
        await this.invalidateSession(sessionId);
        return {
          isValid: false,
          reason: 'Session idle timeout exceeded'
        };
      }

      // Validate IP binding
      const currentIpHash = this.hashIp(currentIp);
      if (storedMetadata.ipHash !== currentIpHash) {
        logger.warn('IP binding violation detected', {
          sessionId,
          userId,
          expectedIpHash: storedMetadata.ipHash,
          actualIpHash: currentIpHash,
          currentIp
        });

        // Log security event for IP binding violation
        logger.securityEvent('SESSION_HIJACK_ATTEMPT', 'high', {
          userId,
          sessionId,
          eventType: 'IP_BINDING_VIOLATION',
          expectedIpHash: storedMetadata.ipHash,
          actualIpHash: currentIpHash,
          currentIp,
          userAgent: currentUserAgent
        });

        if (this.strictMode) {
          await this.invalidateSession(sessionId);
        }
        
        return {
          isValid: false,
          reason: 'IP binding violation'
        };
      }

      // Validate User-Agent binding
      const currentUserAgentHash = this.hashUserAgent(currentUserAgent);
      if (storedMetadata.userAgentHash !== currentUserAgentHash) {
        logger.warn('User-Agent binding violation detected', {
          sessionId,
          userId,
          expectedUserAgentHash: storedMetadata.userAgentHash,
          actualUserAgentHash: currentUserAgentHash,
          currentUserAgent
        });

        // Log security event for User-Agent binding violation
        logger.securityEvent('SESSION_HIJACK_ATTEMPT', 'medium', {
          userId,
          sessionId,
          eventType: 'USER_AGENT_BINDING_VIOLATION',
          expectedUserAgentHash: storedMetadata.userAgentHash,
          actualUserAgentHash: currentUserAgentHash,
          currentUserAgent
        });

        if (this.strictMode) {
          await this.invalidateSession(sessionId);
        }
        
        return {
          isValid: false,
          reason: 'User-Agent binding violation'
        };
      }

      // Update last accessed time
      storedMetadata.lastAccessed = Date.now();
      await this.redis.setex(sessionKey, this.calculateSessionTtl(), storedMetadata);

      return {
        isValid: true,
        metadata: storedMetadata
      };
    } catch (error) {
      logger.error('Session binding validation error', {
        error: (error as Error).message,
        sessionId,
        userId,
        currentIp
      });
      
      return {
        isValid: false,
        reason: 'Session validation error'
      };
    }
  }

  /**
   * Invalidate a session binding
   */
  async invalidateSession(sessionId: string): Promise<boolean> {
    try {
      const sessionKey = `session_binding:${sessionId}`;
      const result = await this.redis.del(sessionKey);
      
      if (result > 0) {
        logger.info('Session invalidated', { sessionId });
        return true;
      }
      
      logger.warn('Attempted to invalidate non-existent session', { sessionId });
      return false;
    } catch (error) {
      logger.error('Failed to invalidate session', {
        error: (error as Error).message,
        sessionId
      });
      return false;
    }
  }

  /**
   * Calculate session TTL based on absolute timeout
   */
  private calculateSessionTtl(): number {
    // TTL should be slightly longer than absolute timeout to account for clock differences
    return Math.ceil(this.absoluteTimeoutMs / 1000) + 300; // 5 minutes extra
  }

  /**
   * Clean up expired sessions (should be called periodically)
   */
  async cleanupExpiredSessions(): Promise<number> {
    // This would involve scanning Redis for expired keys
    // For now, we rely on Redis's built-in expiration
    logger.info('Session cleanup completed');
    return 0;
  }

  /**
   * Get session metadata for administrative purposes
   */
  async getSessionMetadata(sessionId: string): Promise<SessionMetadata | null> {
    try {
      const sessionKey = `session_binding:${sessionId}`;
      return await this.redis.get<SessionMetadata>(sessionKey);
    } catch (error) {
      logger.error('Failed to retrieve session metadata', {
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
      const sessionKey = `session_binding:${sessionId}`;
      const metadata = await this.redis.get<SessionMetadata>(sessionKey);
      
      if (!metadata) {
        return false;
      }

      metadata.lastAccessed = Date.now();
      await this.redis.setex(sessionKey, this.calculateSessionTtl(), metadata);
      
      return true;
    } catch (error) {
      logger.error('Failed to update session activity', {
        error: (error as Error).message,
        sessionId
      });
      return false;
    }
  }
}