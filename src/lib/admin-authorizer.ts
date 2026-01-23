import { Redis } from '@upstash/redis';
import { createHash, randomBytes } from 'crypto';
import { logger } from './logger';
import { integrityLog } from './integrity-log';

interface AdminAction {
  id: string;
  action: string;
  target: string;
  requester: string;
  reason: string;
  timestamp: number;
  approvals: string[];
  requiredApprovals: number;
  status: 'pending' | 'approved' | 'rejected' | 'executed';
  timeLockExpiry?: number;
}

interface AdminKey {
  id: string;
  publicKey: string;
  role: 'super_admin' | 'admin' | 'auditor';
  isActive: boolean;
}

export class AdminAuthorizer {
  private redis: Redis;
  private readonly ADMIN_ACTIONS_PREFIX = 'admin_action:';
  private readonly ADMIN_KEYS_PREFIX = 'admin_keys:';
  private readonly APPROVAL_REQUESTS_PREFIX = 'approval_request:';
  private readonly AUDIT_LOG_PREFIX = 'admin_audit_log:';

  constructor() {
    this.redis = Redis.fromEnv();
  }

  /**
   * Submit an admin action for multi-party approval
   */
  async submitAction(
    action: string,
    target: string,
    requester: string,
    reason: string,
    requiredApprovals: number,
    timeLockHours?: number
  ): Promise<{ actionId: string; status: string }> {
    try {
      const actionId = this.generateActionId();
      
      // Calculate time lock expiry if specified
      const timeLockExpiry = timeLockHours 
        ? Date.now() + (timeLockHours * 60 * 60 * 1000)
        : undefined;
      
      const adminAction: AdminAction = {
        id: actionId,
        action,
        target,
        requester,
        reason,
        timestamp: Date.now(),
        approvals: [],
        requiredApprovals,
        status: 'pending',
        timeLockExpiry
      };
      
      // Store the action in Redis
      const key = `${this.ADMIN_ACTIONS_PREFIX}${actionId}`;
      await this.redis.setex(key, 60 * 60 * 24 * 7, JSON.stringify(adminAction)); // Keep for 7 days
      
      // Log the action submission
      await integrityLog.logAuditEvent('Admin action submitted', {
        actionId,
        action,
        requester,
        requiredApprovals,
        timeLockExpiry
      });
      
      logger.info('Admin action submitted for approval', {
        actionId,
        action,
        requester,
        requiredApprovals
      });
      
      return { actionId, status: 'submitted_for_approval' };
    } catch (error) {
      logger.error('Failed to submit admin action', { error: (error as Error).message });
      throw error;
    }
  }

  /**
   * Approve an admin action (M-of-N approval)
   */
  async approveAction(actionId: string, approver: string, signature: string): Promise<{ approved: boolean; status: string }> {
    try {
      const key = `${this.ADMIN_ACTIONS_PREFIX}${actionId}`;
      const actionStr = await this.redis.get(key);
      
      if (!actionStr) {
        throw new Error('Action not found');
      }
      
      const action = JSON.parse(actionStr as string) as AdminAction;
      
      if (action.status !== 'pending') {
        return { approved: false, status: `Action is ${action.status}` };
      }
      
      // Verify the approver is authorized
      const isAuthorized = await this.verifyAdminAuthorization(approver, 'admin');
      if (!isAuthorized) {
        throw new Error(`Approver ${approver} is not authorized`);
      }
      
      // Verify the signature (simplified - in reality this would involve crypto verification)
      const isValidSignature = await this.verifyApprovalSignature(actionId, approver, signature);
      if (!isValidSignature) {
        throw new Error('Invalid approval signature');
      }
      
      // Check for duplicate approval
      if (action.approvals.includes(approver)) {
        return { approved: false, status: 'already_approved' };
      }
      
      // Add approval
      action.approvals.push(approver);
      
      // Check if we have enough approvals
      if (action.approvals.length >= action.requiredApprovals) {
        // Check if time lock has expired (if applicable)
        if (action.timeLockExpiry && Date.now() < action.timeLockExpiry) {
          // Action is approved but still under time lock
          action.status = 'approved';
        } else {
          // Execute immediately
          action.status = 'executed';
          
          // Log the execution
          await integrityLog.logAuditEvent('Admin action executed', {
            actionId,
            action: action.action,
            approvers: action.approvals,
            executedBy: approver
          });
        }
      } else {
        action.status = 'pending';
      }
      
      // Update the action in Redis
      await this.redis.setex(key, 60 * 60 * 24 * 7, JSON.stringify(action));
      
      // Log the approval
      await integrityLog.logAuditEvent('Admin action approved', {
        actionId,
        approver,
        currentApprovals: action.approvals.length,
        requiredApprovals: action.requiredApprovals
      });
      
      logger.info('Admin action approved', {
        actionId,
        approver,
        currentApprovals: action.approvals.length,
        requiredApprovals: action.requiredApprovals,
        status: action.status
      });
      
      return { 
        approved: true, 
        status: action.status 
      };
    } catch (error) {
      logger.error('Failed to approve admin action', { error: (error as Error).message });
      throw error;
    }
  }

  /**
   * Execute an admin action after sufficient approvals
   */
  async executeAction(actionId: string, executor: string): Promise<{ executed: boolean; result?: any }> {
    try {
      const key = `${this.ADMIN_ACTIONS_PREFIX}${actionId}`;
      const actionStr = await this.redis.get(key);
      
      if (!actionStr) {
        throw new Error('Action not found');
      }
      
      const action = JSON.parse(actionStr as string) as AdminAction;
      
      if (action.status === 'executed') {
        return { executed: true, result: 'already_executed' };
      }
      
      // Check if we have enough approvals
      if (action.approvals.length < action.requiredApprovals) {
        throw new Error(`Insufficient approvals. Required: ${action.requiredApprovals}, Got: ${action.approvals.length}`);
      }
      
      // Check if time lock has expired (if applicable)
      if (action.timeLockExpiry && Date.now() < action.timeLockExpiry) {
        throw new Error(`Time lock not expired yet. Expires at: ${new Date(action.timeLockExpiry).toISOString()}`);
      }
      
      // Verify the executor is authorized
      const isAuthorized = await this.verifyAdminAuthorization(executor, 'admin');
      if (!isAuthorized) {
        throw new Error(`Executor ${executor} is not authorized`);
      }
      
      // Update status to executed
      action.status = 'executed';
      await this.redis.setex(key, 60 * 60 * 24 * 7, JSON.stringify(action));
      
      // Log the execution
      await integrityLog.logAuditEvent('Admin action executed', {
        actionId,
        action: action.action,
        approvers: action.approvals,
        executor
      });
      
      logger.info('Admin action executed', {
        actionId,
        action: action.action,
        executor,
        approvers: action.approvals
      });
      
      // Actually execute the action based on its type
      const result = await this.executeSpecificAction(action);
      
      return { executed: true, result };
    } catch (error) {
      logger.error('Failed to execute admin action', { error: (error as Error).message });
      throw error;
    }
  }

  /**
   * Execute the specific administrative action
   */
  private async executeSpecificAction(action: AdminAction): Promise<any> {
    // This is where you'd implement the actual administrative actions
    switch (action.action) {
      case 'disable_user':
        return await this.disableUser(action.target);
      case 'enable_user':
        return await this.enableUser(action.target);
      case 'reset_user_password':
        return await this.resetUserPassword(action.target);
      case 'kill_switch_activate':
        return await this.activateKillSwitch();
      case 'kill_switch_deactivate':
        return await this.deactivateKillSwitch();
      case 'emergency_maintenance':
        return await this.emergencyMaintenance();
      default:
        throw new Error(`Unknown admin action: ${action.action}`);
    }
  }

  /**
   * Disable a user account
   */
  private async disableUser(userId: string): Promise<boolean> {
    // Implementation would disable the user account
    logger.info('User disabled via admin action', { userId });
    return true;
  }

  /**
   * Enable a user account
   */
  private async enableUser(userId: string): Promise<boolean> {
    // Implementation would enable the user account
    logger.info('User enabled via admin action', { userId });
    return true;
  }

  /**
   * Reset a user's password
   */
  private async resetUserPassword(userId: string): Promise<boolean> {
    // Implementation would reset the user's password
    logger.info('User password reset via admin action', { userId });
    return true;
  }

  /**
   * Activate kill switch
   */
  private async activateKillSwitch(): Promise<boolean> {
    // Implementation would activate the kill switch
    logger.info('Kill switch activated via admin action');
    return true;
  }

  /**
   * Deactivate kill switch
   */
  private async deactivateKillSwitch(): Promise<boolean> {
    // Implementation would deactivate the kill switch
    logger.info('Kill switch deactivated via admin action');
    return true;
  }

  /**
   * Emergency maintenance
   */
  private async emergencyMaintenance(): Promise<boolean> {
    // Implementation would put system in maintenance mode
    logger.info('Emergency maintenance mode activated');
    return true;
  }

  /**
   * Verify admin authorization
   */
  private async verifyAdminAuthorization(adminId: string, requiredRole: 'super_admin' | 'admin' | 'auditor'): Promise<boolean> {
    try {
      const key = `${this.ADMIN_KEYS_PREFIX}${adminId}`;
      const keyStr = await this.redis.get(key);
      
      if (!keyStr) {
        return false;
      }
      
      const adminKey = JSON.parse(keyStr as string) as AdminKey;
      
      if (!adminKey.isActive) {
        return false;
      }
      
      // Check role hierarchy: super_admin > admin > auditor
      if (requiredRole === 'super_admin') {
        return adminKey.role === 'super_admin';
      } else if (requiredRole === 'admin') {
        return adminKey.role === 'super_admin' || adminKey.role === 'admin';
      } else {
        // auditor role
        return adminKey.role === 'super_admin' || adminKey.role === 'admin' || adminKey.role === 'auditor';
      }
    } catch (error) {
      logger.error('Failed to verify admin authorization', { error: (error as Error).message });
      return false;
    }
  }

  /**
   * Verify approval signature
   */
  private async verifyApprovalSignature(actionId: string, approver: string, signature: string): Promise<boolean> {
    // In a real implementation, this would verify the cryptographic signature
    // For now, we'll use a simplified approach
    try {
      // Recreate the expected signature payload
      const payload = `${actionId}:${approver}:${Date.now()}`;
      const expectedSignature = createHash('sha256').update(payload).digest('hex');
      
      // In a real implementation, you'd verify the actual cryptographic signature
      // This is a simplified placeholder
      return signature.length === 64; // Basic check for hex-encoded signature
    } catch (error) {
      logger.error('Failed to verify approval signature', { error: (error as Error).message });
      return false;
    }
  }

  /**
   * Generate a unique action ID
   */
  private generateActionId(): string {
    return `admin_${Date.now()}_${randomBytes(8).toString('hex')}`;
  }

  /**
   * Get admin action by ID
   */
  async getAction(actionId: string): Promise<AdminAction | null> {
    try {
      const key = `${this.ADMIN_ACTIONS_PREFIX}${actionId}`;
      const actionStr = await this.redis.get(key);
      
      if (!actionStr) {
        return null;
      }
      
      return JSON.parse(actionStr as string) as AdminAction;
    } catch (error) {
      logger.error('Failed to get admin action', { error: (error as Error).message });
      return null;
    }
  }

  /**
   * Register an admin key
   */
  async registerAdminKey(
    adminId: string,
    publicKey: string,
    role: 'super_admin' | 'admin' | 'auditor'
  ): Promise<boolean> {
    try {
      const adminKey: AdminKey = {
        id: adminId,
        publicKey,
        role,
        isActive: true
      };
      
      const key = `${this.ADMIN_KEYS_PREFIX}${adminId}`;
      await this.redis.setex(key, 60 * 60 * 24 * 30, JSON.stringify(adminKey)); // Keep for 30 days
      
      // Log the registration
      await integrityLog.logAuditEvent('Admin key registered', {
        adminId,
        role,
        publicKey: publicKey.substring(0, 10) + '...' // Truncate for privacy
      });
      
      logger.info('Admin key registered', { adminId, role });
      
      return true;
    } catch (error) {
      logger.error('Failed to register admin key', { error: (error as Error).message });
      return false;
    }
  }

  /**
   * Revoke an admin key
   */
  async revokeAdminKey(adminId: string): Promise<boolean> {
    try {
      const key = `${this.ADMIN_KEYS_PREFIX}${adminId}`;
      const keyStr = await this.redis.get(key);
      
      if (!keyStr) {
        return false;
      }
      
      const adminKey = JSON.parse(keyStr as string) as AdminKey;
      adminKey.isActive = false;
      
      // Update with revoked status
      await this.redis.setex(key, 60 * 60 * 24 * 30, JSON.stringify(adminKey));
      
      // Log the revocation
      await integrityLog.logAuditEvent('Admin key revoked', {
        adminId,
        role: adminKey.role
      });
      
      logger.info('Admin key revoked', { adminId });
      
      return true;
    } catch (error) {
      logger.error('Failed to revoke admin key', { error: (error as Error).message });
      return false;
    }
  }
}

// Global instance for easy access
export const adminAuthorizer = new AdminAuthorizer();