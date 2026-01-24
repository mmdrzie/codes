import { Redis } from 'ioredis';

export interface KeyVersionInfo {
  keyId: string;
  version: number;
  createdAt: Date;
  expiresAt?: Date;
}

export class KeyVersioning {
  private redis: Redis;

  constructor() {
    this.redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
  }

  /**
   * Update current key version for a key type
   */
  async updateCurrentKeyVersion(
    keyType: string, 
    newKeyId: string, 
    tenantId?: string
  ): Promise<void> {
    const key = tenantId 
      ? `key_version:${keyType}:${tenantId}:current`
      : `key_version:${keyType}:current`;
    
    await this.redis.set(key, newKeyId);
    
    // Store rotation timestamp
    const timestampKey = tenantId
      ? `key_version:${keyType}:${tenantId}:last_rotation`
      : `key_version:${keyType}:last_rotation`;
    
    await this.redis.set(timestampKey, Date.now());
  }

  /**
   * Get current key version
   */
  async getCurrentKeyVersion(
    keyType: string, 
    tenantId?: string
  ): Promise<string | null> {
    const key = tenantId
      ? `key_version:${keyType}:${tenantId}:current`
      : `key_version:${keyType}:current`;
    
    return await this.redis.get<string>(key);
  }

  /**
   * Get last rotation date
   */
  async getLastRotationDate(keyType: string): Promise<Date | null> {
    const key = `key_version:${keyType}:last_rotation`;
    const timestamp = await this.redis.get<number>(key);
    
    return timestamp ? new Date(timestamp) : null;
  }

  /**
   * Get historical key versions
   */
  async getHistoricalKeyVersions(
    keyType: string, 
    tenantId?: string
  ): Promise<string[]> {
    const pattern = tenantId
      ? `key_version:${keyType}:${tenantId}:history:*`
      : `key_version:${keyType}:history:*`;
    
    // In production, implement proper Redis SCAN
    return [];
  }

  /**
   * Get key epoch for tenant binding
   */
  async getKeyEpoch(keyType: string, tenantId: string): Promise<number> {
    const key = `key_version:${keyType}:${tenantId}:epoch`;
    const epoch = await this.redis.get<number>(key);
    
    if (!epoch) {
      // Initialize epoch
      const newEpoch = Math.floor(Date.now() / 1000);
      await this.redis.set(key, newEpoch);
      return newEpoch;
    }
    
    return epoch;
  }

  /**
   * Updates the current key version for a specific key type
   */
  async updateCurrentKeyVersionLegacy(keyType: string, newKeyId: string): Promise<void> {
    try {
      const keyVersionsKey = `key_versions:${keyType}`;
      const currentKeyKey = `current_key:${keyType}`;
      
      // Get current version info
      const currentVersionStr = await this.redis.get(currentKeyKey);
      let newVersion = 1;
      
      if (currentVersionStr) {
        const currentVersion = JSON.parse(currentVersionStr) as KeyVersionInfo;
        
        // Add current key to historical versions
        await this.addToHistoricalVersions(keyType, currentVersion);
        
        // Increment version number
        newVersion = currentVersion.version + 1;
      }
      
      // Create new version info
      const newVersionInfo: KeyVersionInfo = {
        keyId: newKeyId,
        version: newVersion,
        createdAt: new Date(),
        expiresAt: this.calculateExpirationDate()
      };
      
      // Update current key
      await this.redis.set(currentKeyKey, JSON.stringify(newVersionInfo));
      
      // Add to sorted set for historical tracking
      await this.redis.zadd(
        keyVersionsKey, 
        newVersionInfo.createdAt.getTime(), 
        JSON.stringify(newVersionInfo)
      );
      
      console.log(`[KEY_VERSIONING] Updated ${keyType} to version ${newVersion}, key: ${newKeyId}`);
    } catch (error) {
      console.error(`[KEY_VERSIONING] Error updating current key version for ${keyType}:`, error);
      throw error;
    }
  }

  /**
   * Adds a key version to historical versions
   */
  private async addToHistoricalVersions(keyType: string, versionInfo: KeyVersionInfo): Promise<void> {
    const historicalKey = `historical_keys:${keyType}`;
    
    // Add to historical list
    await this.redis.lpush(historicalKey, JSON.stringify(versionInfo));
    
    // Keep only last N versions (default 10)
    const maxVersions = parseInt(process.env.KEY_HISTORY_MAX_VERSIONS || '10');
    await this.redis.ltrim(historicalKey, 0, maxVersions - 1);
  }

  /**
   * Gets all historical key versions for a specific type
   */
  async getHistoricalKeyVersionsLegacy(keyType: string): Promise<string[]> {
    try {
      const historicalKey = `historical_keys:${keyType}`;
      const versions = await this.redis.lrange(historicalKey, 0, -1);
      
      return versions.map(version => {
        const parsed = JSON.parse(version) as KeyVersionInfo;
        return parsed.keyId;
      });
    } catch (error) {
      console.error(`[KEY_VERSIONING] Error getting historical key versions for ${keyType}:`, error);
      throw error;
    }
  }

  /**
   * Finds the appropriate key to decrypt data based on version
   */
  async findDecryptionKeyByVersion(keyType: string, version: number): Promise<string | null> {
    try {
      const keyVersionsKey = `key_versions:${keyType}`;
      
      // Get all versions
      const allVersions = await this.redis.zrange(keyVersionsKey, 0, -1, 'WITHSCORES');
      
      // Parse versions and find the one that was active at the time
      for (let i = 0; i < allVersions.length; i += 2) {
        const versionInfo = JSON.parse(allVersions[i]) as KeyVersionInfo;
        const timestamp = parseInt(allVersions[i + 1]);
        
        if (versionInfo.version === version) {
          return versionInfo.keyId;
        }
      }
      
      return null;
    } catch (error) {
      console.error(`[KEY_VERSIONING] Error finding decryption key for ${keyType}, version ${version}:`, error);
      throw error;
    }
  }

  /**
   * Calculates expiration date based on retention policy
   */
  private calculateExpirationDate(): Date {
    const retentionDays = parseInt(process.env.KEY_RETENTION_DAYS || '365');
    const expirationDate = new Date();
    expirationDate.setDate(expirationDate.getDate() + retentionDays);
    return expirationDate;
  }

  /**
   * Cleans up expired keys based on retention policy
   */
  async cleanupExpiredKeys(): Promise<void> {
    try {
      const keyTypes = ['session', 'jwt', 'api', 'database'];
      
      for (const keyType of keyTypes) {
        const keyVersionsKey = `key_versions:${keyType}`;
        const cutoffTime = Date.now();
        
        // Remove expired keys
        await this.redis.zremrangebyscore(keyVersionsKey, '-inf', cutoffTime);
      }
      
      console.log('[KEY_VERSIONING] Completed cleanup of expired keys');
    } catch (error) {
      console.error('[KEY_VERSIONING] Error cleaning up expired keys:', error);
      throw error;
    }
  }
}