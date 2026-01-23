import { createHash } from 'crypto';

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
  deviceFingerprint?: string;
  geographicLocation?: string;
  lastActivityTimestamp?: number;
}

/**
 * SessionMetadata class provides methods for managing session metadata
 */
export class SessionMetadataManager {
  private readonly salt: string;

  constructor(salt?: string) {
    this.salt = salt || process.env.SESSION_BINDING_SALT || this.generateSalt();
  }

  /**
   * Generate a secure salt for hashing
   */
  private generateSalt(): string {
    const crypto = require('crypto') as typeof import('crypto');
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Create session metadata with all required fields
   */
  createSessionMetadata(
    sessionId: string,
    userId: string,
    ip: string,
    userAgent: string,
    idleTimeoutMs: number = 900000, // 15 minutes
    absoluteTimeoutMs: number = 28800000 // 8 hours
  ): SessionMetadata {
    return {
      sessionId,
      userId,
      ipHash: this.hashWithSalt(ip),
      userAgentHash: this.hashWithSalt(this.extractStableUserAgent(userAgent)),
      createdAt: Date.now(),
      lastAccessed: Date.now(),
      idleTimeout: idleTimeoutMs,
      absoluteTimeout: absoluteTimeoutMs,
      isActive: true
    };
  }

  /**
   * Serialize session metadata for storage
   */
  serialize(metadata: SessionMetadata): string {
    return JSON.stringify(metadata);
  }

  /**
   * Deserialize session metadata from storage
   */
  deserialize(serialized: string): SessionMetadata {
    const parsed = JSON.parse(serialized);
    return this.validateSessionMetadata(parsed);
  }

  /**
   * Validate session metadata structure and values
   */
  validateSessionMetadata(metadata: any): SessionMetadata {
    if (!metadata || typeof metadata !== 'object') {
      throw new Error('Invalid session metadata: not an object');
    }

    // Required fields validation
    const requiredFields = [
      'sessionId', 'userId', 'ipHash', 'userAgentHash', 
      'createdAt', 'lastAccessed', 'idleTimeout', 'absoluteTimeout', 'isActive'
    ];

    for (const field of requiredFields) {
      if (metadata[field] === undefined || metadata[field] === null) {
        throw new Error(`Invalid session metadata: missing required field '${field}'`);
      }
    }

    // Type validation
    if (typeof metadata.sessionId !== 'string' || !metadata.sessionId) {
      throw new Error('Invalid session metadata: sessionId must be a non-empty string');
    }

    if (typeof metadata.userId !== 'string' || !metadata.userId) {
      throw new Error('Invalid session metadata: userId must be a non-empty string');
    }

    if (typeof metadata.ipHash !== 'string' || !metadata.ipHash) {
      throw new Error('Invalid session metadata: ipHash must be a non-empty string');
    }

    if (typeof metadata.userAgentHash !== 'string' || !metadata.userAgentHash) {
      throw new Error('Invalid session metadata: userAgentHash must be a non-empty string');
    }

    if (typeof metadata.createdAt !== 'number' || metadata.createdAt <= 0) {
      throw new Error('Invalid session metadata: createdAt must be a positive number');
    }

    if (typeof metadata.lastAccessed !== 'number' || metadata.lastAccessed <= 0) {
      throw new Error('Invalid session metadata: lastAccessed must be a positive number');
    }

    if (typeof metadata.idleTimeout !== 'number' || metadata.idleTimeout <= 0) {
      throw new Error('Invalid session metadata: idleTimeout must be a positive number');
    }

    if (typeof metadata.absoluteTimeout !== 'number' || metadata.absoluteTimeout <= 0) {
      throw new Error('Invalid session metadata: absoluteTimeout must be a positive number');
    }

    if (typeof metadata.isActive !== 'boolean') {
      throw new Error('Invalid session metadata: isActive must be a boolean');
    }

    // Additional validation
    if (metadata.lastAccessed < metadata.createdAt) {
      throw new Error('Invalid session metadata: lastAccessed cannot be before createdAt');
    }

    return metadata as SessionMetadata;
  }

  /**
   * Check if session has exceeded idle timeout
   */
  isIdleTimeoutExceeded(metadata: SessionMetadata): boolean {
    return Date.now() - metadata.lastAccessed > metadata.idleTimeout;
  }

  /**
   * Check if session has exceeded absolute timeout
   */
  isAbsoluteTimeoutExceeded(metadata: SessionMetadata): boolean {
    return Date.now() - metadata.createdAt > metadata.absoluteTimeout;
  }

  /**
   * Check if session is expired (either idle or absolute timeout)
   */
  isSessionExpired(metadata: SessionMetadata): boolean {
    return this.isIdleTimeoutExceeded(metadata) || this.isAbsoluteTimeoutExceeded(metadata);
  }

  /**
   * Update last accessed time
   */
  updateLastAccessed(metadata: SessionMetadata): SessionMetadata {
    const updatedMetadata = { ...metadata };
    updatedMetadata.lastAccessed = Date.now();
    return updatedMetadata;
  }

  /**
   * Deactivate session
   */
  deactivateSession(metadata: SessionMetadata): SessionMetadata {
    const updatedMetadata = { ...metadata };
    updatedMetadata.isActive = false;
    return updatedMetadata;
  }

  /**
   * Hash data with salt for privacy
   */
  private hashWithSalt(data: string): string {
    return createHash('sha256')
      .update(data + this.salt)
      .digest('hex');
  }

  /**
   * Extract stable parts of user agent to avoid minor version changes
   */
  private extractStableUserAgent(userAgent: string): string {
    // Remove version numbers and other volatile parts
    const cleanedUA = userAgent
      .replace(/\s*[\/\-]\s*\d+[\.\d+]*/g, '') // Remove version numbers after / or -
      .replace(/\s*\([^)]*\)/g, '') // Remove everything in parentheses
      .trim();
    
    return cleanedUA;
  }

  /**
   * Migrate legacy session metadata to current format
   */
  migrateLegacyMetadata(legacyData: any): SessionMetadata | null {
    try {
      // Check if this is already in the current format
      if (this.isValidCurrentFormat(legacyData)) {
        return this.validateSessionMetadata(legacyData);
      }

      // Attempt migration from common legacy formats
      const migrated: SessionMetadata = {
        sessionId: legacyData.sessionId || legacyData.id || '',
        userId: legacyData.userId || legacyData.user_id || '',
        ipHash: legacyData.ipHash || legacyData.ip_hash || this.hashWithSalt(legacyData.ip || ''),
        userAgentHash: legacyData.userAgentHash || legacyData.user_agent_hash || 
                       this.hashWithSalt(this.extractStableUserAgent(legacyData.userAgent || legacyData.user_agent || '')),
        createdAt: legacyData.createdAt || legacyData.created_at || Date.now(),
        lastAccessed: legacyData.lastAccessed || legacyData.last_accessed || Date.now(),
        idleTimeout: legacyData.idleTimeout || legacyData.idle_timeout || 900000, // 15 minutes
        absoluteTimeout: legacyData.absoluteTimeout || legacyData.absolute_timeout || 28800000, // 8 hours
        isActive: legacyData.isActive || legacyData.active || legacyData.is_active !== false, // Default to true
      };

      return this.validateSessionMetadata(migrated);
    } catch (error) {
      console.error('Failed to migrate legacy session metadata:', error);
      return null;
    }
  }

  /**
   * Check if data is already in current format
   */
  private isValidCurrentFormat(data: any): boolean {
    try {
      this.validateSessionMetadata(data);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get session age in milliseconds
   */
  getSessionAge(metadata: SessionMetadata): number {
    return Date.now() - metadata.createdAt;
  }

  /**
   * Get time until idle timeout in milliseconds
   */
  getTimeUntilIdleTimeout(metadata: SessionMetadata): number {
    return metadata.idleTimeout - (Date.now() - metadata.lastAccessed);
  }

  /**
   * Get time until absolute timeout in milliseconds
   */
  getTimeUntilAbsoluteTimeout(metadata: SessionMetadata): number {
    return metadata.absoluteTimeout - (Date.now() - metadata.createdAt);
  }

  /**
   * Get remaining session time (minimum of idle and absolute timeouts)
   */
  getRemainingSessionTime(metadata: SessionMetadata): number {
    const timeUntilIdle = this.getTimeUntilIdleTimeout(metadata);
    const timeUntilAbs = this.getTimeUntilAbsoluteTimeout(metadata);
    return Math.min(timeUntilIdle, timeUntilAbs);
  }
}