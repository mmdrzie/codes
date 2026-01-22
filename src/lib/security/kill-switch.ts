import { Redis } from '@upstash/redis';
import { logger } from '../logger';

// Initialize Redis
const redis = Redis.fromEnv();

const KILL_SWITCH_KEY = 'kill-switch';
const KILL_SWITCH_REASON_KEY = 'kill-switch-reason';
const GRANULAR_KILL_SWITCH_PREFIX = 'kill-switch:granular:';

export class KillSwitchService {
  /**
   * Check if the system is in emergency lockdown
   */
  static async isActive(component?: string): Promise<boolean> {
    try {
      // Check global kill switch first
      const globalStatus = await redis.get(KILL_SWITCH_KEY);
      if (globalStatus === 'active') {
        return true;
      }
      
      // If checking a specific component, check granular kill switch
      if (component) {
        const componentKey = `${GRANULAR_KILL_SWITCH_PREFIX}${component}`;
        const status = await redis.get(componentKey);
        return status === 'active';
      }
      
      return false;
    } catch (error) {
      logger.error('Failed to check kill switch status', { error: (error as Error).message });
      // In case of Redis failure, we should consider this a critical issue
      throw new Error('Kill switch check failed due to Redis connectivity issue');
    }
  }

  /**
   * Activate the global kill switch to freeze all operations during emergencies
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
      
      logger.error('GLOBAL Kill switch activated - THE SYSTEM IS IN EMERGENCY LOCKDOWN', {
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
   * Activate a granular kill switch for specific components or services
   */
  static async activateGranular(component: string, reason: string, activatedBy: string): Promise<void> {
    try {
      const componentKey = `${GRANULAR_KILL_SWITCH_PREFIX}${component}`;
      const reasonKey = `${GRANULAR_KILL_SWITCH_PREFIX}${component}:reason`;
      
      const multi = redis.multi();
      
      // Set component-specific kill switch to active
      multi.set(componentKey, 'active');
      
      // Store reason and who activated it
      multi.set(reasonKey, JSON.stringify({
        reason,
        activatedBy,
        timestamp: new Date().toISOString(),
        component
      }));
      
      await multi.exec();
      
      logger.error('Component-specific kill switch activated', {
        component,
        reason,
        activatedBy,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      logger.error('Failed to activate granular kill switch', { 
        error: (error as Error).message,
        component
      });
      throw new Error(`Granular kill switch activation failed for component: ${component}`);
    }
  }

  /**
   * Deactivate the global kill switch
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
      
      logger.info('Global kill switch deactivated', {
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
   * Deactivate a granular kill switch for a specific component
   */
  static async deactivateGranular(component: string, deactivatedBy: string): Promise<void> {
    try {
      const componentKey = `${GRANULAR_KILL_SWITCH_PREFIX}${component}`;
      const reasonKey = `${GRANULAR_KILL_SWITCH_PREFIX}${component}:reason`;
      
      const multi = redis.multi();
      
      // Clear component-specific keys
      multi.del(componentKey);
      multi.del(reasonKey);
      
      await multi.exec();
      
      logger.info('Component-specific kill switch deactivated', {
        component,
        deactivatedBy,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      logger.error('Failed to deactivate granular kill switch', { 
        error: (error as Error).message,
        component
      });
      throw new Error(`Granular kill switch deactivation failed for component: ${component}`);
    }
  }

  /**
   * Get information about the current kill switch status
   */
  static async getStatus(component?: string): Promise<{
    active: boolean;
    reason?: string;
    activatedBy?: string;
    timestamp?: string;
    component?: string;
  }> {
    try {
      if (component) {
        // Check specific component
        const componentKey = `${GRANULAR_KILL_SWITCH_PREFIX}${component}`;
        const reasonKey = `${GRANULAR_KILL_SWITCH_PREFIX}${component}:reason`;
        
        const [status, reasonStr] = await Promise.all([
          redis.get(componentKey),
          redis.get(reasonKey)
        ]);

        const reason = reasonStr ? JSON.parse(reasonStr as string) : null;

        return {
          active: status === 'active',
          reason: reason?.reason,
          activatedBy: reason?.activatedBy,
          timestamp: reason?.timestamp,
          component: reason?.component
        };
      } else {
        // Check global status
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
      }
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
   * Get status of all kill switches
   */
  static async getAllStatuses(): Promise<Record<string, any>> {
    try {
      // Note: In a real implementation, you would scan for all keys with the prefix
      // However, Upstash Redis scan is limited, so we'll return a placeholder
      const globalStatus = await this.getStatus();
      
      return {
        global: globalStatus,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error('Failed to get all kill switch statuses', { error: (error as Error).message });
      return {
        error: 'Failed to retrieve statuses',
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Middleware function to enforce kill switch check
   */
  static async enforceKillSwitch(component?: string): Promise<void> {
    const isActive = await this.isActive(component);
    
    if (isActive) {
      const status = await this.getStatus(component);
      logger.warn('Request blocked due to active kill switch', {
        reason: status.reason,
        activatedBy: status.activatedBy,
        timestamp: status.timestamp,
        component: status.component
      });
      
      throw new Error(`The system${component ? ` component ${component}` : ''} is in emergency lockdown. No transactions can be processed.`);
    }
  }
}