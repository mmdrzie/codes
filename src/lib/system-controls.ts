/**
 * System Controls - Kill Switch and Freeze Mechanisms
 * Bank-grade safety controls that operate independently of other system components
 */

import { Redis } from '@upstash/redis';
import { logger } from './logger';
import { SecurityMonitor, SecurityEvent } from './security-monitoring';


// Redis for system control state management
const redis = Redis.fromEnv();

// System control keys
const SYSTEM_STATUS_KEY = 'system_operational_status';
const ACCOUNT_FREEZE_KEY = 'account_freeze_status:';
const FROZEN_REASON_KEY = 'freeze_reason:';
const EMERGENCY_CONTACT_KEY = 'emergency_contacts';

// System status types
export enum SystemStatus {
  OPERATIONAL = 'operational',
  READ_ONLY = 'read_only',
  FROZEN = 'frozen',
  EMERGENCY_FROZEN = 'emergency_frozen'
}

// Freeze types
export enum FreezeType {
  ACCOUNT_LEVEL = 'account_level',
  SYSTEM_WIDE = 'system_wide',
  EMERGENCY = 'emergency'
}

// Freeze reason codes
export enum FreezeReason {
  WALLET_OPERATION_VIOLATION = 'wallet_operation_violation',
  CUSTODY_INTEGRITY_FAILURE = 'custody_integrity_failure',
  FULL_REDIS_OUTAGE = 'full_redis_outage',
  SECURITY_BREACH = 'security_breach',
  DATA_CORRUPTION = 'data_corruption',
  MANUAL_ADMIN_ACTION = 'manual_admin_action',
  CUSTOMER_REQUEST = 'customer_request',
  FRAUD_DETECTION = 'fraud_detection',
  TECHNICAL_MAINTENANCE = 'technical_maintenance'
}

export interface FreezeDetails {
  freezeType: FreezeType;
  reason: FreezeReason;
  frozenBy: string;
  timestamp: number;
  expiresAt?: number;
  notes?: string;
}

export interface SystemStatusInfo {
  status: SystemStatus;
  lastUpdated: number;
  frozenAccounts: string[];
  activeFreezes: number;
}

export class SystemControls {
  /**
   * Check if the system is operational for transactions
   */
  static async isSystemOperational(): Promise<boolean> {
    const status = await redis.get(SYSTEM_STATUS_KEY);
    return status === SystemStatus.OPERATIONAL;
  }

  /**
   * Check if the system is in read-only mode
   */
  static async isSystemReadOnly(): Promise<boolean> {
    const status = await redis.get(SYSTEM_STATUS_KEY);
    return status === SystemStatus.READ_ONLY;
  }

  /**
   * Check if the system is frozen
   */
  static async isSystemFrozen(): Promise<boolean> {
    const status = await redis.get(SYSTEM_STATUS_KEY);
    return status === SystemStatus.FROZEN || status === SystemStatus.EMERGENCY_FROZEN;
  }

  /**
   * Check if a specific account is frozen
   */
  static async isAccountFrozen(accountId: string): Promise<boolean> {
    return await redis.exists(`${ACCOUNT_FREEZE_KEY}${accountId}`);
  }

  /**
   * Get system status information
   */
  static async getSystemStatus(): Promise<SystemStatusInfo> {
    const status = await redis.get(SYSTEM_STATUS_KEY);
    const frozenAccounts = await redis.keys(`${ACCOUNT_FREEZE_KEY}*`);
    
    return {
      status: status as SystemStatus || SystemStatus.OPERATIONAL,
      lastUpdated: Date.now(),
      frozenAccounts: frozenAccounts.map(key => key.replace(ACCOUNT_FREEZE_KEY, '')),
      activeFreezes: frozenAccounts.length
    };
  }

  /**
   * Freeze a specific account
   */
  static async freezeAccount(
    accountId: string, 
    reason: FreezeReason, 
    frozenBy: string,
    notes?: string
  ): Promise<boolean> {
    try {
      const freezeDetails: FreezeDetails = {
        freezeType: FreezeType.ACCOUNT_LEVEL,
        reason,
        frozenBy,
        timestamp: Date.now(),
        notes
      };

      const multi = redis.multi();
      multi.set(`${ACCOUNT_FREEZE_KEY}${accountId}`, 'frozen');
      multi.set(`${FROZEN_REASON_KEY}${accountId}`, JSON.stringify(freezeDetails));
      
      // Set expiration for account freezes (30 days default, extendable)
      multi.expire(`${ACCOUNT_FREEZE_KEY}${accountId}`, 86400 * 30);
      multi.expire(`${FROZEN_REASON_KEY}${accountId}`, 86400 * 30);
      
      await multi.exec();

      // Log the freeze event
      await SecurityMonitor.logEvent(
        SecurityEvent.SUSPICIOUS_ACTIVITY,
        {
          userId: frozenBy,
          timestamp: new Date(),
          metadata: {
            event: 'account_freeze',
            accountId,
            reason,
            frozenBy
          }
        },
        `Account ${accountId} frozen by ${frozenBy} for reason: ${reason}`
      );

      logger.info('Account frozen successfully', {
        accountId,
        reason,
        frozenBy,
        timestamp: Date.now()
      });

      return true;
    } catch (error) {
      logger.error('Failed to freeze account', {
        error: (error as Error).message,
        accountId,
        reason,
        frozenBy
      });
      return false;
    }
  }

  /**
   * Unfreeze a specific account
   */
  static async unfreezeAccount(accountId: string, unfrozenBy: string): Promise<boolean> {
    try {
      const multi = redis.multi();
      multi.del(`${ACCOUNT_FREEZE_KEY}${accountId}`);
      multi.del(`${FROZEN_REASON_KEY}${accountId}`);
      
      await multi.exec();

      // Log the unfreeze event
      await SecurityMonitor.logEvent(
        SecurityEvent.AUTH_SUCCESS,
        {
          userId: unfrozenBy,
          timestamp: new Date(),
          metadata: {
            event: 'account_unfreeze',
            accountId,
            unfrozenBy
          }
        },
        `Account ${accountId} unfrozen by ${unfrozenBy}`
      );

      logger.info('Account unfrozen successfully', {
        accountId,
        unfrozenBy,
        timestamp: Date.now()
      });

      return true;
    } catch (error) {
      logger.error('Failed to unfreeze account', {
        error: (error as Error).message,
        accountId,
        unfrozenBy
      });
      return false;
    }
  }

  /**
   * Activate system-wide freeze
   */
  static async activateSystemWideFreeze(
    reason: FreezeReason, 
    frozenBy: string,
    durationHours: number = 1,
    notes?: string
  ): Promise<boolean> {
    try {
      const freezeDetails: FreezeDetails = {
        freezeType: FreezeType.SYSTEM_WIDE,
        reason,
        frozenBy,
        timestamp: Date.now(),
        expiresAt: Date.now() + (durationHours * 60 * 60 * 1000),
        notes
      };

      // Set system status to frozen
      await redis.setex(SYSTEM_STATUS_KEY, durationHours * 3600, SystemStatus.FROZEN);

      // Log the freeze event
      await SecurityMonitor.logEvent(
        SecurityEvent.CRITICAL,
        {
          userId: frozenBy,
          timestamp: new Date(),
          metadata: {
            event: 'system_wide_freeze',
            reason,
            frozenBy,
            durationHours
          }
        },
        'SYSTEM WIDE FREEZE ACTIVATED'
      );

      logger.error('System wide freeze activated', {
        reason,
        frozenBy,
        durationHours,
        timestamp: Date.now()
      });

      return true;
    } catch (error) {
      logger.error('Failed to activate system-wide freeze', {
        error: (error as Error).message,
        reason,
        frozenBy
      });
      return false;
    }
  }

  /**
   * Activate emergency freeze (highest priority)
   */
  static async activateEmergencyFreeze(
    reason: FreezeReason, 
    frozenBy: string,
    notes?: string
  ): Promise<boolean> {
    try {
      const freezeDetails: FreezeDetails = {
        freezeType: FreezeType.EMERGENCY,
        reason,
        frozenBy,
        timestamp: Date.now(),
        notes
      };

      // Set system status to emergency frozen (1 hour default, can be renewed)
      await redis.setex(SYSTEM_STATUS_KEY, 3600, SystemStatus.EMERGENCY_FROZEN);

      // Log the emergency freeze event with highest priority
      await SecurityMonitor.logQuantumThreat(
        {
          userId: frozenBy,
          timestamp: new Date(),
          metadata: {
            event: 'emergency_system_freeze',
            reason,
            frozenBy
          }
        },
        `EMERGENCY SYSTEM FREEZE: ${reason}`
      );

      logger.fatal('Emergency system freeze activated', {
        reason,
        frozenBy,
        timestamp: Date.now()
      });

      return true;
    } catch (error) {
      logger.error('Failed to activate emergency freeze', {
        error: (error as Error).message,
        reason,
        frozenBy
      });
      return false;
    }
  }

  /**
   * Lift system-wide freeze
   */
  static async liftSystemFreeze(liftedBy: string): Promise<boolean> {
    try {
      // Reset system status to operational
      await redis.set(SYSTEM_STATUS_KEY, SystemStatus.OPERATIONAL);

      // Log the unfreeze event
      await SecurityMonitor.logEvent(
        SecurityEvent.AUTH_SUCCESS,
        {
          userId: liftedBy,
          timestamp: new Date(),
          metadata: {
            event: 'system_unfreeze',
            liftedBy
          }
        },
        'SYSTEM FREEZE LIFTED'
      );

      logger.info('System freeze lifted', {
        liftedBy,
        timestamp: Date.now()
      });

      return true;
    } catch (error) {
      logger.error('Failed to lift system freeze', {
        error: (error as Error).message,
        liftedBy
      });
      return false;
    }
  }

  /**
   * Force system to read-only mode
   */
  static async setSystemReadOnly(activatedBy: string, notes?: string): Promise<boolean> {
    try {
      await redis.set(SYSTEM_STATUS_KEY, SystemStatus.READ_ONLY);

      // Log the read-only mode activation
      await SecurityMonitor.logEvent(
        SecurityEvent.AUTH_SUCCESS,
        {
          userId: activatedBy,
          timestamp: new Date(),
          metadata: {
            event: 'system_read_only_mode',
            activatedBy,
            notes
          }
        },
        'SYSTEM SET TO READ-ONLY MODE'
      );

      logger.warn('System set to read-only mode', {
        activatedBy,
        notes,
        timestamp: Date.now()
      });

      return true;
    } catch (error) {
      logger.error('Failed to set system to read-only mode', {
        error: (error as Error).message,
        activatedBy
      });
      return false;
    }
  }

  /**
   * Get freeze details for an account
   */
  static async getAccountFreezeDetails(accountId: string): Promise<FreezeDetails | null> {
    try {
      const freezeDetailsStr = await redis.get(`${FROZEN_REASON_KEY}${accountId}`);
      
      if (freezeDetailsStr) {
        return JSON.parse(freezeDetailsStr as string);
      }
      
      return null;
    } catch (error) {
      logger.error('Failed to get account freeze details', {
        error: (error as Error).message,
        accountId
      });
      return null;
    }
  }

  /**
   * Add emergency contact for notifications
   */
  static async addEmergencyContact(contact: string): Promise<boolean> {
    try {
      await redis.sadd(EMERGENCY_CONTACT_KEY, contact);
      logger.info('Emergency contact added', { contact });
      return true;
    } catch (error) {
      logger.error('Failed to add emergency contact', {
        error: (error as Error).message,
        contact
      });
      return false;
    }
  }

  /**
   * Get all emergency contacts
   */
  static async getEmergencyContacts(): Promise<string[]> {
    try {
      return await redis.smembers(EMERGENCY_CONTACT_KEY);
    } catch (error) {
      logger.error('Failed to get emergency contacts', {
        error: (error as Error).message
      });
      return [];
    }
  }

  /**
   * Validate that kill-switch works even when other components fail
   */
  static async validateKillSwitchIntegrity(): Promise<boolean> {
    try {
      // Test basic functionality without relying on other components
      const testKey = `health_check_${Date.now()}`;
      await redis.setex(testKey, 60, 'healthy');
      const result = await redis.get(testKey);
      
      if (result !== 'healthy') {
        logger.error('Kill switch integrity check failed - Redis not responding properly');
        return false;
      }

      // Test that freeze status can be set and retrieved independently
      await redis.setex(SYSTEM_STATUS_KEY + '_test', 60, SystemStatus.FROZEN);
      const testStatus = await redis.get(SYSTEM_STATUS_KEY + '_test');
      
      if (testStatus !== SystemStatus.FROZEN) {
        logger.error('Kill switch integrity check failed - status not properly set');
        return false;
      }

      logger.info('Kill switch integrity check passed');
      return true;
    } catch (error) {
      logger.error('Kill switch integrity check failed with error', {
        error: (error as Error).message
      });
      return false;
    }
  }
}