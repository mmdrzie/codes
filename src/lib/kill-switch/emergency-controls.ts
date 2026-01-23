import { getRedisClient } from '../redis/redis-client';

// Define emergency levels
export enum EmergencyLevel {
  NONE = 'NONE',
  ELEVATED = 'ELEVATED',
  HIGH = 'HIGH',
  SEVERE = 'SEVERE',
  CRITICAL = 'CRITICAL'
}

interface AccountFreezeRecord {
  accountId: string;
  reason: string;
  frozenAt: Date;
  frozenBy: string;
}

class KillSwitchManager {
  private static instance: KillSwitchManager;
  private redisClient = getRedisClient();
  private readonly EMERGENCY_LEVEL_KEY = 'emergency_level';
  private readonly FROZEN_ACCOUNTS_KEY = 'frozen_accounts';
  private readonly EMERGENCY_CONTACTS_KEY = 'emergency_contacts';

  private constructor() {}

  public static getInstance(): KillSwitchManager {
    if (!KillSwitchManager.instance) {
      KillSwitchManager.instance = new KillSwitchManager();
    }
    return KillSwitchManager.instance;
  }

  /**
   * Set the current emergency level
   */
  public async setEmergencyLevel(level: EmergencyLevel, actor: string): Promise<void> {
    const previousLevel = await this.getCurrentEmergencyLevel();
    
    // Store the new level in Redis
    await this.redisClient.set(this.EMERGENCY_LEVEL_KEY, level.toString(), 86400); // 24 hours TTL
    
    // Log the change
    console.log(`Emergency level changed from ${previousLevel} to ${level} by ${actor}`);
    
    // Trigger notifications if moving to higher levels
    if (this.isHigherEmergencyLevel(level, previousLevel)) {
      await this.sendEmergencyNotification(level, actor);
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
   * Freeze a specific account
   */
  public async freezeAccount(accountId: string, reason: string, frozenBy: string): Promise<void> {
    const freezeRecord: AccountFreezeRecord = {
      accountId,
      reason,
      frozenAt: new Date(),
      frozenBy
    };
    
    // Store the freeze record in Redis as a hash
    const key = `${this.FROZEN_ACCOUNTS_KEY}:${accountId}`;
    await this.redisClient.set(key, JSON.stringify(freezeRecord), 86400 * 30); // 30 days TTL
    
    console.log(`Account ${accountId} frozen by ${frozenBy}. Reason: ${reason}`);
    
    // Send notification about account freeze
    await this.sendAccountFreezeNotification(accountId, reason, frozenBy);
  }

  /**
   * Unfreeze a specific account
   */
  public async unfreezeAccount(accountId: string, unfrozenBy: string): Promise<void> {
    const key = `${this.FROZEN_ACCOUNTS_KEY}:${accountId}`;
    await this.redisClient.del(key);
    
    console.log(`Account ${accountId} unfrozen by ${unfrozenBy}`);
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
      console.error('Error parsing account freeze record:', error);
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
   * Trigger a complete service shutdown
   */
  public async triggerServiceShutdown(reason: string, triggeredBy: string): Promise<void> {
    console.log(`Service shutdown triggered by ${triggeredBy}. Reason: ${reason}`);
    
    // In a real implementation, this might:
    // - Set emergency level to CRITICAL
    // - Notify all services to shut down gracefully
    // - Perform cleanup operations
    // - Log the shutdown event
    
    await this.setEmergencyLevel(EmergencyLevel.CRITICAL, triggeredBy);
    
    // Send emergency notification
    await this.sendEmergencyNotification(EmergencyLevel.CRITICAL, triggeredBy);
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
        console.error('Error parsing emergency contacts:', error);
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
      console.error('Error parsing emergency contacts:', error);
      return [];
    }
  }

  /**
   * Send emergency notification
   */
  private async sendEmergencyNotification(level: EmergencyLevel, actor: string): Promise<void> {
    console.log(`Sending emergency notification for level ${level} triggered by ${actor}`);
    
    // In a real implementation, this would send notifications via:
    // - Email
    // - SMS
    // - Slack/Discord webhook
    // - PagerDuty
    // etc.
    
    const contacts = await this.getEmergencyContacts();
    for (const contact of contacts) {
      console.log(`Notifying emergency contact: ${contact.name} (${contact.email})`);
      // Actual notification logic would go here
    }
  }

  /**
   * Send account freeze notification
   */
  private async sendAccountFreezeNotification(accountId: string, reason: string, frozenBy: string): Promise<void> {
    console.log(`Sending account freeze notification for account ${accountId}`);
    
    // In a real implementation, this would notify relevant parties
    const contacts = await this.getEmergencyContacts();
    for (const contact of contacts) {
      console.log(`Notifying about account freeze: ${contact.name} (${contact.email})`);
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