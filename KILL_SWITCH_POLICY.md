# KILL-SWITCH & CUSTODY-FREEZE POLICY

## OVERVIEW
This document defines the hard stop mechanisms for the custodial system. These mechanisms must work independently of system components to ensure safety even when individual services fail.

## CUSTODY FREEZE TRIGGERS

### AUTOMATIC TRIGGERS
- **Wallet Operation Violation**: Any unauthorized operation detected
- **Custody Integrity Failure**: Discrepancy found during automated integrity checks
- **Full Redis Outage**: Complete inability to connect to Redis for >30 seconds
- **Critical Security Events**: Token forgery, replay attacks, privilege escalation detected
- **Data Integrity Failure**: Checksum validation failures in critical data

### MANUAL TRIGGERS
- **Operations Team**: Via emergency kill-switch endpoint
- **Security Team**: When security compromise is suspected
- **Executive Override**: Senior leadership authorized system halt

### MULTI-PARTY APPROVAL TRIGGERS
- **Dual Control**: Requires 2 of 3 senior staff members to approve
- **Emergency Committee**: Requires majority vote from designated emergency committee

## FREEZE ENFORCEMENT MECHANISMS

### API LAYER ENFORCEMENT
```typescript
// Example implementation
const SYSTEM_STATUS_KEY = 'system_operational_status';
const ACCOUNT_FREEZE_KEY = 'account_freeze_status:';
const FROZEN_REASON_KEY = 'freeze_reason:';

class SystemFreezeControl {
  static async isSystemOperational(): Promise<boolean> {
    const status = await redis.get(SYSTEM_STATUS_KEY);
    return status === 'operational';
  }

  static async isAccountFrozen(accountId: string): Promise<boolean> {
    return await redis.exists(`${ACCOUNT_FREEZE_KEY}${accountId}`);
  }

  static async freezeAccount(accountId: string, reason: string, frozenBy: string): Promise<boolean> {
    const multi = redis.multi();
    multi.set(`${ACCOUNT_FREEZE_KEY}${accountId}`, 'frozen');
    multi.set(`${FROZEN_REASON_KEY}${accountId}`, JSON.stringify({
      reason,
      frozenBy,
      timestamp: Date.now()
    }));
    multi.expire(`${ACCOUNT_FREEZE_KEY}${accountId}`, 86400 * 30); // 30 days
    multi.expire(`${FROZEN_REASON_KEY}${accountId}`, 86400 * 30); // 30 days
    
    await multi.exec();
    return true;
  }

  static async unfreezeAccount(accountId: string, unfrozenBy: string): Promise<boolean> {
    const multi = redis.multi();
    multi.del(`${ACCOUNT_FREEZE_KEY}${accountId}`);
    multi.del(`${FROZEN_REASON_KEY}${accountId}`);
    
    await multi.exec();
    return true;
  }

  static async activateSystemWideFreeze(reason: string, frozenBy: string): Promise<boolean> {
    await redis.setex(SYSTEM_STATUS_KEY, 3600, 'frozen'); // Frozen for 1 hour, renewable
    
    // Log the freeze event
    await SecurityMonitor.logEvent(
      SecurityEvent.CRITICAL,
      {
        userId: frozenBy,
        timestamp: new Date(),
        metadata: {
          event: 'system_wide_freeze',
          reason,
          frozenBy
        }
      },
      'SYSTEM WIDE FREEZE ACTIVATED'
    );
    
    return true;
  }
}
```

### CUSTODY LAYER ENFORCEMENT
- All wallet operations check system status before proceeding
- Account-specific freezes prevent new operations to/from frozen accounts
- Balance queries may continue in read-only mode during freezes

### OPERATION ENGINE ENFORCEMENT
- Operation validation checks both system and account freeze status
- Failed operations due to freeze are blocked permanently
- Operation processing halts entirely during system-wide freeze

### WITHDRAWAL/WALLET PATH ENFORCEMENT
- All wallet endpoints check freeze status first
- Wallet operations blocked for frozen accounts
- System-wide freeze blocks all wallet operations regardless of account status

## FREEZE LIFECYCLE MANAGEMENT

### HOW FREEZES ARE LIFTED

#### ACCOUNT-LEVEL FREEZE
- **Required Proofs**: Identity verification and account ownership proof
- **Required Verification**: Balance verification and operation history review
- **Required Human Approvals**: Single approver from security team minimum

#### SYSTEM-WIDE FREEZE
- **Required Proofs**: Complete system health checks and security validation
- **Required Verification**: Full integrity checks and balance verification
- **Required Human Approvals**: Dual approval from operations and security leads

#### EMERGENCY FREEZE
- **Required Proofs**: Forensic analysis completion and remediation validation
- **Required Verification**: Complete data integrity verification
- **Required Human Approvals**: Executive committee approval required

### FREEZE DURATION POLICIES

#### AUTOMATIC FREEZES
- Initial duration: 1 hour (renewable)
- Maximum duration: 24 hours without manual extension
- Automatic renewal possible based on continued risk indicators

#### MANUAL FREEZES
- Duration determined by authorizing party
- Must specify expected thaw time
- Can be indefinite until manually lifted

#### EMERGENCY FREEZES
- Duration by executive decision
- Daily review required for freezes >24 hours
- Mandatory incident response team involvement

## FAIL-SAFE REQUIREMENTS

### KILL-SWITCH OPERABILITY DURING FAILURES
- Kill-switch must work when SIEM is down
- Kill-switch must work when Redis is partially down
- Kill-switch must work when one service is compromised
- Kill-switch must work when primary authentication is compromised

### REDUNDANCY REQUIREMENTS
- At least 3 independent kill-switch endpoints
- Hardware-level kill capability (separate from software)
- Physical security controls for emergency switches
- Geographic distribution of kill-switch capabilities

### AUDIT TRAIL REQUIREMENTS
- All freeze/unfreeze actions must be logged
- Immutable audit trail of all freeze decisions
- Timestamp-verified freeze actions
- Chain of custody for all freeze authorizations