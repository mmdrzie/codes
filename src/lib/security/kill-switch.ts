import { Redis } from '@upstash/redis';
import { logger } from '../logger';

// Initialize Redis
const redis = Redis.fromEnv();

const KILL_SWITCH_KEY = 'kill-switch';
const KILL_SWITCH_REASON_KEY = 'kill-switch-reason';

export class KillSwitchService {
  /**
   * Check if the system is in emergency lockdown
   */
  static async isActive(): Promise<boolean> {
    try {
      const status = await redis.get(KILL_SWITCH_KEY);
      return status === 'active';
    } catch (error) {
      logger.error('Failed to check kill switch status', { error: (error as Error).message });
      // In case of Redis failure, we should consider this a critical issue
      throw new Error('Kill switch check failed due to Redis connectivity issue');
    }
  }

  /**
   * Activate the kill switch to freeze all operations during emergencies
   */
  static async activate(reason: string, activatedBy: string): Promise<void> {
    try {
      const multi = redis.multi();
      
      // Set kill switch to active
      multi.set(KILL_SWITCH_KEY, 'active');
      
      // Store reason and who activated it
      multi.set(KILL_SWITCH_REASON_KEY, JSON.stringify({
        reason,
        activatedBy,
        timestamp: new Date().toISOString()
      }));
      
      await multi.exec();
      
      logger.error('Kill switch activated - THE SYSTEM IS IN EMERGENCY LOCKDOWN', {
        reason,
        activatedBy,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      logger.error('Failed to activate kill switch', { error: (error as Error).message });
      throw new Error('Kill switch activation failed');
    }
  }

  /**
   * Deactivate the kill switch
   */
  static async deactivate(deactivatedBy: string): Promise<void> {
    try {
      const multi = redis.multi();
      
      // Get current reason before clearing
      const reason = await redis.get(KILL_SWITCH_REASON_KEY);
      
      // Clear both keys
      multi.del(KILL_SWITCH_KEY);
      multi.del(KILL_SWITCH_REASON_KEY);
      
      await multi.exec();
      
      logger.info('Kill switch deactivated', {
        deactivatedBy,
        previousReason: reason,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      logger.error('Failed to deactivate kill switch', { error: (error as Error).message });
      throw new Error('Kill switch deactivation failed');
    }
  }

  /**
   * Get information about the current kill switch status
   */
  static async getStatus(): Promise<{
    active: boolean;
    reason?: string;
    activatedBy?: string;
    timestamp?: string;
  }> {
    try {
      const [status, reasonStr] = await Promise.all([
        redis.get(KILL_SWITCH_KEY),
        redis.get(KILL_SWITCH_REASON_KEY)
      ]);

      const reason = reasonStr ? JSON.parse(reasonStr as string) : null;

      return {
        active: status === 'active',
        reason: reason?.reason,
        activatedBy: reason?.activatedBy,
        timestamp: reason?.timestamp
      };
    } catch (error) {
      logger.error('Failed to get kill switch status', { error: (error as Error).message });
      return {
        active: false,
        reason: 'Failed to retrieve status',
        activatedBy: 'system',
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Middleware function to enforce kill switch check
   */
  static async enforceKillSwitch(): Promise<void> {
    const isActive = await this.isActive();
    
    if (isActive) {
      const status = await this.getStatus();
      logger.warn('Request blocked due to active kill switch', {
        reason: status.reason,
        activatedBy: status.activatedBy,
        timestamp: status.timestamp
      });
      
      throw new Error('The system is in emergency lockdown. No transactions can be processed.');
    }
  }
}