import { Redis } from 'ioredis';

export interface BypassEntry {
  id: string;
  type: 'ip' | 'apiKey' | 'userId';
  value: string;
  reason: string;
  createdBy: string;
  createdAt: Date;
  expiresAt?: Date;
}

export class BypassWhitelist {
  private redis: Redis;

  constructor(redisUrl?: string) {
    this.redis = new Redis(redisUrl || process.env.REDIS_URL || 'redis://localhost:6379');
  }

  /**
   * Checks if an IP address is whitelisted for rate limit bypass
   */
  async isIpWhitelisted(ip: string): Promise<boolean> {
    try {
      const key = `whitelist:ip:${ip}`;
      const exists = await this.redis.exists(key);
      return exists === 1;
    } catch (error) {
      console.error(`[WHITELIST] Error checking IP whitelist for ${ip}:`, error);
      return false; // Fail closed - don't bypass if there's an error
    }
  }

  /**
   * Checks if an API key is whitelisted for rate limit bypass
   */
  async isApiKeyWhitelisted(apiKey: string): Promise<boolean> {
    try {
      const key = `whitelist:api:${apiKey}`;
      const exists = await this.redis.exists(key);
      return exists === 1;
    } catch (error) {
      console.error(`[WHITELIST] Error checking API key whitelist for ${apiKey}:`, error);
      return false; // Fail closed
    }
  }

  /**
   * Checks if a user ID is whitelisted for rate limit bypass
   */
  async isUserWhitelisted(userId: string): Promise<boolean> {
    try {
      const key = `whitelist:user:${userId}`;
      const exists = await this.redis.exists(key);
      return exists === 1;
    } catch (error) {
      console.error(`[WHITELIST] Error checking user whitelist for ${userId}:`, error);
      return false; // Fail closed
    }
  }

  /**
   * Adds an IP to the whitelist
   */
  async addIpToWhitelist(
    ip: string,
    reason: string,
    createdBy: string,
    durationHours?: number
  ): Promise<boolean> {
    try {
      const key = `whitelist:ip:${ip}`;
      const entry: BypassEntry = {
        id: `whitelist_ip_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        type: 'ip',
        value: ip,
        reason,
        createdBy,
        createdAt: new Date()
      };

      if (durationHours) {
        entry.expiresAt = new Date(Date.now() + durationHours * 60 * 60 * 1000);
      }

      // Store the entry
      await this.redis.setex(
        key,
        durationHours ? durationHours * 60 * 60 : 60 * 60 * 24, // Default to 24 hours if no duration specified
        JSON.stringify(entry)
      );

      // Add to the list of all whitelisted IPs for management purposes
      await this.redis.zadd('whitelist:all', Date.now(), JSON.stringify(entry));

      console.log(`[WHITELIST] Added IP ${ip} to whitelist. Reason: ${reason}. Created by: ${createdBy}.`);
      
      return true;
    } catch (error) {
      console.error(`[WHITELIST] Error adding IP ${ip} to whitelist:`, error);
      return false;
    }
  }

  /**
   * Adds an API key to the whitelist
   */
  async addApiKeyToWhitelist(
    apiKey: string,
    reason: string,
    createdBy: string,
    durationHours?: number
  ): Promise<boolean> {
    try {
      const key = `whitelist:api:${apiKey}`;
      const entry: BypassEntry = {
        id: `whitelist_api_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        type: 'apiKey',
        value: apiKey,
        reason,
        createdBy,
        createdAt: new Date()
      };

      if (durationHours) {
        entry.expiresAt = new Date(Date.now() + durationHours * 60 * 60 * 1000);
      }

      // Store the entry
      await this.redis.setex(
        key,
        durationHours ? durationHours * 60 * 60 : 60 * 60 * 24, // Default to 24 hours if no duration specified
        JSON.stringify(entry)
      );

      // Add to the list of all whitelisted entries
      await this.redis.zadd('whitelist:all', Date.now(), JSON.stringify(entry));

      console.log(`[WHITELIST] Added API key ${apiKey} to whitelist. Reason: ${reason}. Created by: ${createdBy}.`);
      
      return true;
    } catch (error) {
      console.error(`[WHITELIST] Error adding API key ${apiKey} to whitelist:`, error);
      return false;
    }
  }

  /**
   * Adds a user to the whitelist
   */
  async addUserToWhitelist(
    userId: string,
    reason: string,
    createdBy: string,
    durationHours?: number
  ): Promise<boolean> {
    try {
      const key = `whitelist:user:${userId}`;
      const entry: BypassEntry = {
        id: `whitelist_user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        type: 'userId',
        value: userId,
        reason,
        createdBy,
        createdAt: new Date()
      };

      if (durationHours) {
        entry.expiresAt = new Date(Date.now() + durationHours * 60 * 60 * 1000);
      }

      // Store the entry
      await this.redis.setex(
        key,
        durationHours ? durationHours * 60 * 60 : 60 * 60 * 24, // Default to 24 hours if no duration specified
        JSON.stringify(entry)
      );

      // Add to the list of all whitelisted entries
      await this.redis.zadd('whitelist:all', Date.now(), JSON.stringify(entry));

      console.log(`[WHITELIST] Added user ${userId} to whitelist. Reason: ${reason}. Created by: ${createdBy}.`);
      
      return true;
    } catch (error) {
      console.error(`[WHITELIST] Error adding user ${userId} to whitelist:`, error);
      return false;
    }
  }

  /**
   * Removes an IP from the whitelist
   */
  async removeIpFromWhitelist(ip: string): Promise<boolean> {
    try {
      const key = `whitelist:ip:${ip}`;
      const deleted = await this.redis.del(key);
      
      if (deleted > 0) {
        console.log(`[WHITELIST] Removed IP ${ip} from whitelist.`);
        return true;
      }
      
      return false;
    } catch (error) {
      console.error(`[WHITELIST] Error removing IP ${ip} from whitelist:`, error);
      return false;
    }
  }

  /**
   * Removes an API key from the whitelist
   */
  async removeApiKeyFromWhitelist(apiKey: string): Promise<boolean> {
    try {
      const key = `whitelist:api:${apiKey}`;
      const deleted = await this.redis.del(key);
      
      if (deleted > 0) {
        console.log(`[WHITELIST] Removed API key ${apiKey} from whitelist.`);
        return true;
      }
      
      return false;
    } catch (error) {
      console.error(`[WHITELIST] Error removing API key ${apiKey} from whitelist:`, error);
      return false;
    }
  }

  /**
   * Removes a user from the whitelist
   */
  async removeUserFromWhitelist(userId: string): Promise<boolean> {
    try {
      const key = `whitelist:user:${userId}`;
      const deleted = await this.redis.del(key);
      
      if (deleted > 0) {
        console.log(`[WHITELIST] Removed user ${userId} from whitelist.`);
        return true;
      }
      
      return false;
    } catch (error) {
      console.error(`[WHITELIST] Error removing user ${userId} from whitelist:`, error);
      return false;
    }
  }

  /**
   * Gets all whitelisted entries
   */
  async getAllWhitelisted(): Promise<BypassEntry[]> {
    try {
      const allEntries = await this.redis.zrange('whitelist:all', 0, -1);
      return allEntries.map(entry => JSON.parse(entry) as BypassEntry);
    } catch (error) {
      console.error('[WHITELIST] Error getting all whitelisted entries:', error);
      return [];
    }
  }

  /**
   * Gets whitelisted IPs
   */
  async getWhitelistedIps(): Promise<BypassEntry[]> {
    try {
      const allEntries = await this.getAllWhitelisted();
      return allEntries.filter(entry => entry.type === 'ip');
    } catch (error) {
      console.error('[WHITELIST] Error getting whitelisted IPs:', error);
      return [];
    }
  }

  /**
   * Gets whitelisted API keys
   */
  async getWhitelistedApiKeys(): Promise<BypassEntry[]> {
    try {
      const allEntries = await this.getAllWhitelisted();
      return allEntries.filter(entry => entry.type === 'apiKey');
    } catch (error) {
      console.error('[WHITELIST] Error getting whitelisted API keys:', error);
      return [];
    }
  }

  /**
   * Gets whitelisted users
   */
  async getWhitelistedUsers(): Promise<BypassEntry[]> {
    try {
      const allEntries = await this.getAllWhitelisted();
      return allEntries.filter(entry => entry.type === 'userId');
    } catch (error) {
      console.error('[WHITELIST] Error getting whitelisted users:', error);
      return [];
    }
  }

  /**
   * Removes expired entries from the whitelist
   */
  async cleanupExpiredEntries(): Promise<void> {
    try {
      const allEntries = await this.getAllWhitelisted();
      const now = new Date();
      
      for (const entry of allEntries) {
        if (entry.expiresAt && entry.expiresAt < now) {
          // Entry is expired, remove it
          let key = '';
          switch (entry.type) {
            case 'ip':
              key = `whitelist:ip:${entry.value}`;
              break;
            case 'apiKey':
              key = `whitelist:api:${entry.value}`;
              break;
            case 'userId':
              key = `whitelist:user:${entry.value}`;
              break;
          }
          
          if (key) {
            await this.redis.del(key);
            console.log(`[WHITELIST] Removed expired entry: ${entry.id} (${entry.type}: ${entry.value})`);
          }
        }
      }
      
      // Clean up the sorted set as well
      await this.redis.zremrangebyscore('whitelist:all', 0, now.getTime());
      
      console.log('[WHITELIST] Cleanup of expired entries completed.');
    } catch (error) {
      console.error('[WHITELIST] Error cleaning up expired entries:', error);
    }
  }

  /**
   * Checks if a request should bypass rate limiting
   */
  async shouldBypassRateLimit(
    ip: string,
    apiKey?: string,
    userId?: string
  ): Promise<{ bypass: boolean; reason?: string }> {
    try {
      // Check IP whitelist
      if (await this.isIpWhitelisted(ip)) {
        return { bypass: true, reason: 'IP is whitelisted' };
      }

      // Check API key whitelist if provided
      if (apiKey && await this.isApiKeyWhitelisted(apiKey)) {
        return { bypass: true, reason: 'API key is whitelisted' };
      }

      // Check user whitelist if provided
      if (userId && await this.isUserWhitelisted(userId)) {
        return { bypass: true, reason: 'User is whitelisted' };
      }

      return { bypass: false };
    } catch (error) {
      console.error('[WHITELIST] Error checking bypass status:', error);
      return { bypass: false }; // Fail closed
    }
  }
}