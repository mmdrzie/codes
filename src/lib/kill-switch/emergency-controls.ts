import { getRedisClient } from '../redis/redis-client';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../logger';

// Define emergency levels
export enum EmergencyLevel {
  NONE = 'NONE',
  ELEVATED = 'ELEVATED',
  HIGH = 'HIGH',
  SEVERE = 'SEVERE',
  CRITICAL = 'CRITICAL'
}

// Multi-admin approval configuration
interface MultiAdminApprovalConfig {
  requiredApprovals: number;
  admins: string[];
  approvalTimeout: number; // in seconds
}

interface AccountFreezeRecord {
  accountId: string;
  reason: string;
  frozenAt: Date;
  frozenBy: string;
}

interface EmergencyAction {
  id: string;
  action: string;
  level: EmergencyLevel;
  initiatedBy: string;
  initiatedAt: Date;
  approvals: string[]; // Admin IDs who approved
  status: 'pending' | 'approved' | 'executed';
  requiredApprovals: number;
  expiresAt: Date;
}

class KillSwitchManager {
  private static instance: KillSwitchManager;
  private redisClient = getRedisClient();
  private readonly EMERGENCY_LEVEL_KEY = 'emergency_level';
  private readonly EMERGENCY_ACTIONS_KEY = 'emergency_actions';
  private readonly FROZEN_ACCOUNTS_KEY = 'frozen_accounts';
  private readonly EMERGENCY_CONTACTS_KEY = 'emergency_contacts';
  private readonly MULTI_ADMIN_CONFIG_KEY = 'multi_admin_config';

  private constructor() {}

  public static getInstance(): KillSwitchManager {
    if (!KillSwitchManager.instance) {
      KillSwitchManager.instance = new KillSwitchManager();
    }
    return KillSwitchManager.instance;
  }

  /**
   * Initialize multi-admin configuration
   */
  public async initializeMultiAdminConfig(config: MultiAdminApprovalConfig): Promise<void> {
    try {
      await this.redisClient.set(this.MULTI_ADMIN_CONFIG_KEY, JSON.stringify(config));
      logger.info('Multi-admin configuration initialized', { requiredApprovals: config.requiredApprovals, adminCount: config.admins.length });
    } catch (error) {
      logger.error('Failed to initialize multi-admin config', { error: (error as Error).message });
      throw error;
    }
  }

  /**
   * Get multi-admin configuration
   */
  public async getMultiAdminConfig(): Promise<MultiAdminApprovalConfig | null> {
    try {
      const configStr = await this.redisClient.get(this.MULTI_ADMIN_CONFIG_KEY);
      if (!configStr) {
        return null;
      }
      return JSON.parse(configStr) as MultiAdminApprovalConfig;
    } catch (error) {
      logger.error('Failed to get multi-admin config', { error: (error as Error).message });
      return null;
    }
  }

  /**
   * Initiate an emergency action requiring multi-admin approval
   */
  public async initiateEmergencyAction(action: string, level: EmergencyLevel, initiatedBy: string): Promise<EmergencyAction> {
    try {
      const config = await this.getMultiAdminConfig();
      if (!config) {
        throw new Error('Multi-admin configuration not initialized');
      }

      // Check if the initiating user is an authorized admin
      if (!config.admins.includes(initiatedBy)) {
        throw new Error(`User ${initiatedBy} is not authorized to initiate emergency actions`);
      }

      const actionId = uuidv4();
      const now = new Date();
      const expiresAt = new Date(now.getTime() + config.approvalTimeout * 1000);

      const emergencyAction: EmergencyAction = {
        id: actionId,
        action,
        level,
        initiatedBy,
        initiatedAt: now,
        approvals: [initiatedBy], // Initiator automatically approves
        status: config.requiredApprovals <= 1 ? 'approved' : 'pending',
        requiredApprovals: config.requiredApprovals,
        expiresAt
      };

      // Store the emergency action
      const key = `${this.EMERGENCY_ACTIONS_KEY}:${actionId}`;
      await this.redisClient.setex(key, config.approvalTimeout, JSON.stringify(emergencyAction));

      logger.info('Emergency action initiated', {
        actionId,
        action,
        level,
        initiatedBy,
        requiredApprovals: config.requiredApprovals,
        status: emergencyAction.status
      });

      // If action is already approved, execute it
      if (emergencyAction.status === 'approved') {
        await this.executeApprovedAction(emergencyAction);
      }

      return emergencyAction;
    } catch (error) {
      logger.error('Failed to initiate emergency action', { error: (error as Error).message });
      throw error;
    }
  }

  /**
   * Approve an emergency action
   */
  public async approveEmergencyAction(actionId: string, approver: string): Promise<EmergencyAction> {
    try {
      const config = await this.getMultiAdminConfig();
      if (!config) {
        throw new Error('Multi-admin configuration not initialized');
      }

      // Check if the approver is an authorized admin
      if (!config.admins.includes(approver)) {
        throw new Error(`User ${approver} is not authorized to approve emergency actions`);
      }

      const key = `${this.EMERGENCY_ACTIONS_KEY}:${actionId}`;
      const actionStr = await this.redisClient.get(key);

      if (!actionStr) {
        throw new Error(`Emergency action ${actionId} not found`);
      }

      const action = JSON.parse(actionStr) as EmergencyAction;

      // Check if already executed
      if (action.status === 'executed') {
        throw new Error('Emergency action already executed');
      }

      // Check if already approved by this user
      if (action.approvals.includes(approver)) {
        return action;
      }

      // Add approval
      action.approvals.push(approver);

      // Check if we have enough approvals
      if (action.approvals.length >= config.requiredApprovals) {
        action.status = 'approved';
      }

      // Update the action in Redis
      await this.redisClient.setex(key, Math.floor((action.expiresAt.getTime() - Date.now()) / 1000), JSON.stringify(action));

      logger.info('Emergency action approved', {
        actionId,
        approver,
        currentApprovals: action.approvals.length,
        requiredApprovals: config.requiredApprovals,
        status: action.status
      });

      // If now approved, execute the action
      if (action.status === 'approved') {
        await this.executeApprovedAction(action);
      }

      return action;
    } catch (error) {
      logger.error('Failed to approve emergency action', { error: (error as Error).message });
      throw error;
    }
  }

  /**
   * Execute an approved emergency action
   */
  private async executeApprovedAction(action: EmergencyAction): Promise<void> {
    try {
      // Update the action status to executed
      action.status = 'executed';
      
      const key = `${this.EMERGENCY_ACTIONS_KEY}:${action.id}`;
      const config = await this.getMultiAdminConfig();
      const ttl = config ? Math.floor((action.expiresAt.getTime() - Date.now()) / 1000) : 3600; // Default 1 hour
      await this.redisClient.setex(key, ttl > 0 ? ttl : 3600, JSON.stringify(action));

      // Now execute the actual emergency action
      switch (action.action.toLowerCase()) {
        case 'set_emergency_level':
          await this.executeSetEmergencyLevel(action.level, action.initiatedBy);
          break;
        case 'trigger_shutdown':
          await this.executeTriggerShutdown('Emergency shutdown', action.initiatedBy);
          break;
        case 'freeze_account':
          // Additional parameters would be needed for account freezing
          logger.warn('Account freeze action requires additional parameters', { actionId: action.id });
          break;
        default:
          logger.warn('Unknown emergency action', { action: action.action, actionId: action.id });
      }

      logger.info('Emergency action executed', {
        actionId: action.id,
        action: action.action,
        level: action.level,
        executedBy: action.initiatedBy
      });
    } catch (error) {
      logger.error('Failed to execute emergency action', { error: (error as Error).message, actionId: action.id });
      throw error;
    }
  }

  /**
   * Execute setting emergency level
   */
  private async executeSetEmergencyLevel(level: EmergencyLevel, actor: string): Promise<void> {
    const previousLevel = await this.getCurrentEmergencyLevel();
    
    // Store the new level in Redis
    await this.redisClient.set(this.EMERGENCY_LEVEL_KEY, level.toString(), 86400); // 24 hours TTL
    
    logger.info(`Emergency level changed from ${previousLevel} to ${level} by ${actor}`);
    
    // Trigger notifications if moving to higher levels
    if (this.isHigherEmergencyLevel(level, previousLevel)) {
      await this.sendEmergencyNotification(level, actor);
    }
  }

  /**
   * Execute triggering service shutdown
   */
  private async executeTriggerShutdown(reason: string, triggeredBy: string): Promise<void> {
    logger.info(`Service shutdown executed by ${triggeredBy}. Reason: ${reason}`);
    
    // Set emergency level to CRITICAL
    await this.executeSetEmergencyLevel(EmergencyLevel.CRITICAL, triggeredBy);
    
    // Send emergency notification
    await this.sendEmergencyNotification(EmergencyLevel.CRITICAL, triggeredBy);
  }

  /**
   * Get an emergency action by ID
   */
  public async getEmergencyAction(actionId: string): Promise<EmergencyAction | null> {
    try {
      const key = `${this.EMERGENCY_ACTIONS_KEY}:${actionId}`;
      const actionStr = await this.redisClient.get(key);
      
      if (!actionStr) {
        return null;
      }
      
      return JSON.parse(actionStr) as EmergencyAction;
    } catch (error) {
      logger.error('Failed to get emergency action', { error: (error as Error).message, actionId });
      return null;
    }
  }

  /**
   * Get the current emergency level
   */
  public async getCurrentEmergencyLevel(): Promise<EmergencyLevel> {
    const level = await this.redisClient.get(this.EMERGENCY_LEVEL_KEY);
    return level ? level as EmergencyLevel : EmergencyLevel.NONE;
  }

  /**
   * Check if a specific operation should be blocked based on current emergency level
   */
  public async isOperationBlocked(operation: string): Promise<boolean> {
    const currentLevel = await this.getCurrentEmergencyLevel();
    
    // Define which operations are blocked at each level
    const blockedOperations: Record<EmergencyLevel, string[]> = {
      [EmergencyLevel.NONE]: [],
      [EmergencyLevel.ELEVATED]: [],
      [EmergencyLevel.HIGH]: [],
      [EmergencyLevel.SEVERE]: ['write', 'transfer', 'payment', 'withdrawal', 'delete'],
      [EmergencyLevel.CRITICAL]: ['read', 'write', 'transfer', 'payment', 'withdrawal', 'delete', 'login']
    };
    
    // Check if the operation is blocked at current level
    const blockedOps = blockedOperations[currentLevel] || [];
    return blockedOps.some(blockedOp => operation.toLowerCase().includes(blockedOp));
  }

  /**
   * Freeze a specific account (requires multi-admin approval)
   */
  public async freezeAccount(accountId: string, reason: string, frozenBy: string): Promise<EmergencyAction> {
    // Create an emergency action for account freezing
    return await this.initiateEmergencyAction(
      'freeze_account', 
      EmergencyLevel.HIGH, 
      frozenBy
    );
  }

  /**
   * Unfreeze a specific account
   */
  public async unfreezeAccount(accountId: string, unfrozenBy: string): Promise<void> {
    const key = `${this.FROZEN_ACCOUNTS_KEY}:${accountId}`;
    await this.redisClient.del(key);
    
    logger.info(`Account ${accountId} unfrozen by ${unfrozenBy}`);
  }

  /**
   * Check if an account is frozen
   */
  public async isAccountFrozen(accountId: string): Promise<boolean> {
    const key = `${this.FROZEN_ACCOUNTS_KEY}:${accountId}`;
    const record = await this.redisClient.get(key);
    return record !== null;
  }

  /**
   * Get details about a frozen account
   */
  public async getAccountFreezeDetails(accountId: string): Promise<AccountFreezeRecord | null> {
    const key = `${this.FROZEN_ACCOUNTS_KEY}:${accountId}`;
    const recordStr = await this.redisClient.get(key);
    
    if (!recordStr) {
      return null;
    }
    
    try {
      return JSON.parse(recordStr) as AccountFreezeRecord;
    } catch (error) {
      logger.error('Error parsing account freeze record:', error);
      return null;
    }
  }

  /**
   * Get all frozen accounts
   */
  public async getAllFrozenAccounts(): Promise<AccountFreezeRecord[]> {
    // This would require a scan operation to find all keys matching the pattern
    // For simplicity, we'll return an empty array - in a real implementation
    // you might want to maintain a separate list of all frozen accounts
    return [];
  }

  /**
   * Trigger a complete service shutdown (requires multi-admin approval)
   */
  public async triggerServiceShutdown(reason: string, triggeredBy: string): Promise<EmergencyAction> {
    return await this.initiateEmergencyAction(
      'trigger_shutdown', 
      EmergencyLevel.CRITICAL, 
      triggeredBy
    );
  }

  /**
   * Add an emergency contact
   */
  public async addEmergencyContact(contact: { name: string; email: string; phone: string }): Promise<void> {
    const contactsStr = await this.redisClient.get(this.EMERGENCY_CONTACTS_KEY);
    let contacts: Array<{ name: string; email: string; phone: string }> = [];
    
    if (contactsStr) {
      try {
        contacts = JSON.parse(contactsStr);
      } catch (error) {
        logger.error('Error parsing emergency contacts:', error);
      }
    }
    
    // Check if contact already exists
    const exists = contacts.some(c => c.email === contact.email);
    if (!exists) {
      contacts.push(contact);
      await this.redisClient.set(this.EMERGENCY_CONTACTS_KEY, JSON.stringify(contacts), 86400 * 365); // 1 year TTL
    }
  }

  /**
   * Get all emergency contacts
   */
  public async getEmergencyContacts(): Promise<Array<{ name: string; email: string; phone: string }>> {
    const contactsStr = await this.redisClient.get(this.EMERGENCY_CONTACTS_KEY);
    
    if (!contactsStr) {
      return [];
    }
    
    try {
      return JSON.parse(contactsStr);
    } catch (error) {
      logger.error('Error parsing emergency contacts:', error);
      return [];
    }
  }

  /**
   * Send emergency notification
   */
  private async sendEmergencyNotification(level: EmergencyLevel, actor: string): Promise<void> {
    logger.info(`Sending emergency notification for level ${level} triggered by ${actor}`);
    
    // In a real implementation, this would send notifications via:
    // - Email
    // - SMS
    // - Slack/Discord webhook
    // - PagerDuty
    // etc.
    
    const contacts = await this.getEmergencyContacts();
    for (const contact of contacts) {
      logger.info(`Notifying emergency contact: ${contact.name} (${contact.email})`);
      // Actual notification logic would go here
    }
  }

  /**
   * Check if new level is higher than previous level
   */
  private isHigherEmergencyLevel(newLevel: EmergencyLevel, oldLevel: EmergencyLevel): boolean {
    const levelOrder: EmergencyLevel[] = [
      EmergencyLevel.NONE,
      EmergencyLevel.ELEVATED,
      EmergencyLevel.HIGH,
      EmergencyLevel.SEVERE,
      EmergencyLevel.CRITICAL
    ];
    
    const newLevelIndex = levelOrder.indexOf(newLevel);
    const oldLevelIndex = levelOrder.indexOf(oldLevel);
    
    return newLevelIndex > oldLevelIndex;
  }
}

export default KillSwitchManager;