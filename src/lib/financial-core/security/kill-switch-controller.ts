import { logger } from '../logger';
import { getLedger } from '../ledger/immutable-ledger';

export enum SystemState {
  OPERATIONAL = 'operational',
  READ_ONLY = 'read_only',
  FROZEN = 'frozen',
  EMERGENCY_FROZEN = 'emergency_frozen'
}

export interface KillSwitchConfig {
  enableEmergencyFreeze: boolean;
  freezeOnSecurityFailure: boolean;
  auditTrailRequired: boolean;
}

export class KillSwitchController {
  private currentState: SystemState = SystemState.OPERATIONAL;
  private readonly config: KillSwitchConfig;
  private authorizedUsers: Set<string> = new Set();
  private frozenAt: number | null = null;
  private frozenBy: string | null = null;
  private frozenReason: string | null = null;

  constructor(config?: Partial<KillSwitchConfig>) {
    this.config = {
      enableEmergencyFreeze: config?.enableEmergencyFreeze ?? true,
      freezeOnSecurityFailure: config?.freezeOnSecurityFailure ?? true,
      auditTrailRequired: config?.auditTrailRequired ?? true
    };

    logger.info('Kill Switch Controller initialized', {
      component: 'kill-switch',
      initialState: this.currentState
    });
  }

  /**
   * Activate emergency freeze - stops all write operations immediately
   */
  async activateEmergencyFreeze(activatedBy: string, reason: string = 'EMERGENCY'): Promise<boolean> {
    if (!this.config.enableEmergencyFreeze) {
      logger.warn('Emergency freeze disabled by configuration', {
        component: 'kill-switch'
      });
      return false;
    }

    const previousState = this.currentState;
    this.currentState = SystemState.EMERGENCY_FROZEN;
    this.frozenAt = Date.now();
    this.frozenBy = activatedBy;
    this.frozenReason = reason;

    // Log the state change in the ledger
    const ledger = getLedger();
    await ledger.addEntry({
      transactionId: `kill-switch-${Date.now()}`,
      userId: activatedBy,
      action: 'freeze',
      status: 'confirmed',
      metadata: {
        previousState,
        newState: this.currentState,
        reason,
        activatedBy
      }
    });

    logger.emergency('EMERGENCY KILL SWITCH ACTIVATED', {
      component: 'kill-switch',
      previousState,
      newState: this.currentState,
      activatedBy,
      reason,
      timestamp: this.frozenAt
    });

    return true;
  }

  /**
   * Activate read-only mode - allows audits but stops mutations
   */
  async activateReadOnlyMode(activatedBy: string, reason: string = 'MAINTENANCE'): Promise<boolean> {
    const previousState = this.currentState;
    this.currentState = SystemState.READ_ONLY;

    // Log the state change in the ledger
    const ledger = getLedger();
    await ledger.addEntry({
      transactionId: `readonly-${Date.now()}`,
      userId: activatedBy,
      action: 'freeze',
      status: 'confirmed',
      metadata: {
        previousState,
        newState: this.currentState,
        reason,
        activatedBy
      }
    });

    logger.warn('System switched to READ-ONLY mode', {
      component: 'kill-switch',
      previousState,
      newState: this.currentState,
      activatedBy,
      reason
    });

    return true;
  }

  /**
   * Activate full freeze - stops all operations except emergency access
   */
  async activateFullFreeze(activatedBy: string, reason: string = 'ADMIN_ACTION'): Promise<boolean> {
    const previousState = this.currentState;
    this.currentState = SystemState.FROZEN;
    this.frozenAt = Date.now();
    this.frozenBy = activatedBy;
    this.frozenReason = reason;

    // Log the state change in the ledger
    const ledger = getLedger();
    await ledger.addEntry({
      transactionId: `full-freeze-${Date.now()}`,
      userId: activatedBy,
      action: 'freeze',
      status: 'confirmed',
      metadata: {
        previousState,
        newState: this.currentState,
        reason,
        activatedBy
      }
    });

    logger.warn('System switched to FULL FREEZE mode', {
      component: 'kill-switch',
      previousState,
      newState: this.currentState,
      activatedBy,
      reason
    });

    return true;
  }

  /**
   * Deactivate freeze and return to operational state
   */
  async deactivate(activatedBy: string, reason: string = 'NORMAL_OPERATION'): Promise<boolean> {
    if (this.currentState === SystemState.OPERATIONAL) {
      logger.info('System already operational', {
        component: 'kill-switch'
      });
      return true;
    }

    const previousState = this.currentState;
    this.currentState = SystemState.OPERATIONAL;
    this.frozenAt = null;
    this.frozenBy = null;
    this.frozenReason = null;

    // Log the state change in the ledger
    const ledger = getLedger();
    await ledger.addEntry({
      transactionId: `reactivate-${Date.now()}`,
      userId: activatedBy,
      action: 'unfreeze',
      status: 'confirmed',
      metadata: {
        previousState,
        newState: this.currentState,
        reason,
        activatedBy
      }
    });

    logger.info('Kill switch deactivated, system operational', {
      component: 'kill-switch',
      previousState,
      newState: this.currentState,
      activatedBy,
      reason
    });

    return true;
  }

  /**
   * Check if the system is in an operational state for write operations
   */
  canProcessTransactions(): boolean {
    return this.currentState === SystemState.OPERATIONAL;
  }

  /**
   * Check if the system is in an operational state for read operations
   */
  canProcessReads(): boolean {
    return this.currentState !== SystemState.FROZEN && this.currentState !== SystemState.EMERGENCY_FROZEN;
  }

  /**
   * Check if the system is in an emergency frozen state
   */
  isInEmergencyFreeze(): boolean {
    return this.currentState === SystemState.EMERGENCY_FROZEN;
  }

  /**
   * Trigger freeze due to security failure
   */
  async handleSecurityFailure(failureDetails: any): Promise<boolean> {
    if (!this.config.freezeOnSecurityFailure) {
      logger.warn('Security failure detected but auto-freeze disabled', {
        component: 'kill-switch',
        failureDetails
      });
      return false;
    }

    logger.securityEvent('Security Failure Detected - Activating Kill Switch', {
      component: 'kill-switch',
      failureDetails
    });

    return await this.activateEmergencyFreeze('SYSTEM_SECURITY_MONITOR', 'SECURITY_FAILURE');
  }

  /**
   * Get current system state
   */
  getCurrentState(): SystemState {
    return this.currentState;
  }

  /**
   * Get freeze information
   */
  getFreezeInfo(): {
    frozen: boolean;
    frozenAt: number | null;
    frozenBy: string | null;
    frozenReason: string | null;
    currentState: SystemState;
  } {
    return {
      frozen: this.currentState !== SystemState.OPERATIONAL,
      frozenAt: this.frozenAt,
      frozenBy: this.frozenBy,
      frozenReason: this.frozenReason,
      currentState: this.currentState
    };
  }

  /**
   * Authorize a user for emergency operations during freeze
   */
  authorizeUserForEmergencyOperations(userId: string): void {
    this.authorizedUsers.add(userId);
    logger.info('User authorized for emergency operations', {
      component: 'kill-switch',
      userId
    });
  }

  /**
   * Check if user is authorized for operations during freeze
   */
  isUserAuthorizedDuringFreeze(userId: string): boolean {
    return this.authorizedUsers.has(userId);
  }
}

// Global singleton instance
let killSwitchController: KillSwitchController | null = null;

export function getKillSwitchController(): KillSwitchController {
  if (!killSwitchController) {
    killSwitchController = new KillSwitchController();
  }
  return killSwitchController;
}

// Convenience functions for common checks
export function isSystemOperational(): boolean {
  return getKillSwitchController().canProcessTransactions();
}

export function isSystemReadOnly(): boolean {
  const controller = getKillSwitchController();
  return controller.getCurrentState() === SystemState.READ_ONLY;
}

export function isSystemFrozen(): boolean {
  const controller = getKillSwitchController();
  return controller.getCurrentState() === SystemState.FROZEN || controller.getCurrentState() === SystemState.EMERGENCY_FROZEN;
}