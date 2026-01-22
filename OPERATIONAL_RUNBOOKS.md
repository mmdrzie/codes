# OPERATIONAL RUNBOOKS - CUSTODIAL SECURITY SYSTEM

## 1. CUSTODY OPERATION VIOLATION

**Detection Trigger:** Wallet operation violation detected during transaction recording or integrity validation

**Signal Source:** 
- Application logs: "Wallet operation violation" 
- SIEM: SecurityEvent.SUSPICIOUS_ACTIVITY with violation: 'wallet_operation_violation'
- Metrics: custody_validation_errors_total counter

**Severity Classification:** CRITICAL (P0)

**Immediate Automated Action:**
- Operation recording fails and returns false
- Suspicious activity logged to SIEM
- Operation state set to FAILED

**Human Escalation Path:**
- On-call engineer paged immediately
- Operations team notified via Slack webhook
- Security team alerted for investigation

**Time Limits:**
- T+1m: Automatic alert sent to on-call
- T+5m: Incident commander contacted if no acknowledgment
- T+15m: Executive team notified if unresolved

**Rollback or Freeze Behavior:**
- Operation rejected and marked as failed
- No wallet operations occur
- System continues processing other operations

**Post-Incident Integrity Validation Steps:**
- Manual review of all operations in affected batch
- Identify root cause of violation
- Run custody integrity validation report
- Verify all wallet balances match expected values

## 2. INTEGRITY VALIDATION MISMATCH

**Detection Trigger:** Discrepancy found during custody integrity validation process

**Signal Source:**
- Application logs: "Custody integrity validation found issues"
- SIEM: SecurityEvent.CRITICAL with event: 'custody_integrity_issues'
- Metrics: custody_integrity_failures_total

**Severity Classification:** CRITICAL (P0)

**Immediate Automated Action:**
- Integrity validation process returns failure status
- CRITICAL SIEM event emitted
- Detailed discrepancy report generated

**Human Escalation Path:**
- Production engineering team paged
- Security operations team notified
- Compliance team informed

**Time Limits:**
- T+1m: Alert sent to all relevant teams
- T+5m: Technical lead contacted if no response
- T+15m: CTO and compliance officer notified

**Rollback or Freeze Behavior:**
- NEW operations suspended until resolution
- Read-only mode activated for balance queries
- Manual intervention required to resume operations

**Post-Incident Integrity Validation Steps:**
- Complete manual validation of all wallets
- Identify all affected operations
- Correct any identified discrepancies
- Resume normal operations after validation

## 3. DUPLICATE OPERATION DETECTION

**Detection Trigger:** Same operation ID processed multiple times with different parameters

**Signal Source:**
- Application logs: "Duplicate operation" entries
- SIEM: SecurityEvent.SUSPICIOUS_ACTIVITY with type: 'duplicate_operation'
- Metrics: duplicate_operation_attempts_total

**Severity Classification:** CRITICAL (P0)

**Immediate Automated Action:**
- Second operation attempt rejected
- Suspicious activity logged
- Operation processing locked for affected wallets temporarily

**Human Escalation Path:**
- Fraud detection team notified
- Security team alerted
- Customer support prepared for potential inquiries

**Time Limits:**
- T+1m: Fraud team contacted
- T+5m: Security investigation initiated
- T+15m: Legal team informed if necessary

**Rollback or Freeze Behavior:**
- Suspicious operations blocked
- Affected wallets placed on temporary hold
- Manual review required before resuming

**Post-Incident Integrity Validation Steps:**
- Investigation of how duplicate was allowed
- Verification of all affected wallets
- Compensation process initiated if needed
- System hardening to prevent recurrence

## 4. REDIS PARTIAL OUTAGE

**Detection Trigger:** Redis connection errors or timeouts during operations

**Signal Source:**
- Application logs: "Redis connection failed" or timeout errors
- Health checks failing
- Metrics: redis_connection_errors_total, redis_latency_seconds

**Severity Classification:** HIGH (P1)

**Immediate Automated Action:**
- Connection pooling activated
- Retry mechanisms engaged with exponential backoff
- Circuit breaker potentially opened

**Human Escalation Path:**
- Infrastructure team notified
- DevOps team contacted for remediation
- Platform team informed

**Time Limits:**
- T+1m: Infrastructure team contacted
- T+5m: Remediation steps initiated
- T+15m: Failover to backup Redis cluster if needed

**Rollback or Freeze Behavior:**
- Read-only mode activated for balance queries
- New transactions queued for later processing
- Service degradation with fallback mechanisms

**Post-Incident Reconciliation Steps:**
- Process all queued transactions
- Verify data consistency after recovery
- Performance metrics reviewed
- Capacity planning updated

## 5. FULL REDIS OUTAGE

**Detection Trigger:** Complete inability to connect to Redis cluster

**Signal Source:**
- Multiple consecutive Redis connection failures
- Health checks completely failing
- Metrics showing 100% failure rate

**Severity Classification:** CRITICAL (P0)

**Immediate Automated Action:**
- Emergency shutdown procedure initiated
- All transaction processing halted
- Kill-switch activated automatically

**Human Escalation Path:**
- Entire engineering team paged
- Management notified immediately
- Emergency response team activated

**Time Limits:**
- T+1m: All teams contacted
- T+5m: Emergency procedures executed
- T+15m: Executive leadership informed

**Rollback or Freeze Behavior:**
- System enters complete freeze mode
- All wallet operations suspended
- Read-only API maintained for status checks
- Manual override required to resume operations

**Post-Incident Integrity Validation Steps:**
- Complete custody validation after Redis recovery
- Verify all pending operations
- Process backlog systematically
- Full system health checks performed

## 6. DATABASE CORRUPTION DETECTED

**Detection Trigger:** Data integrity checks fail or checksum mismatches detected

**Signal Source:**
- Application logs: "Data integrity check failed"
- SIEM: SecurityEvent.CRITICAL with details about corruption
- Custom data validation alerts

**Severity Classification:** CRITICAL (P0)

**Immediate Automated Action:**
- All write operations suspended
- Data validation processes initiated
- Backup restoration procedures triggered

**Human Escalation Path:**
- Database administrators paged
- Security team notified for forensics
- Legal/compliance team informed

**Time Limits:**
- T+1m: DBA team contacted immediately
- T+5m: Data recovery procedures initiated
- T+15m: Executive team notified of scope

**Rollback or Freeze Behavior:**
- System enters read-only mode
- All transaction processing stopped
- Manual approval required for any writes
- Complete system freeze if corruption severe

**Post-Incident Reconciliation Steps:**
- Restore from known good backup
- Cross-validate with external records
- Identify root cause of corruption
- Implement additional validation checks

## 7. SIEM BLACKHOLE

**Detection Trigger:** No security events received by SIEM system for extended period

**Signal Source:**
- SIEM system monitoring
- Lack of expected security event flow
- Heartbeat/keepalive mechanism failures

**Severity Classification:** CRITICAL (P0)

**Immediate Automated Action:**
- Local security event logging activated
- Internal alert system triggered
- Backup SIEM destination checked

**Human Escalation Path:**
- Security operations team paged
- Infrastructure team contacted
- Compliance officer notified

**Time Limits:**
- T+1m: Security team contacted
- T+5m: Alternative SIEM channels activated
- T+15m: Management informed of security gap

**Rollback or Freeze Behavior:**
- Continue operation with internal logging
- Increase local security monitoring
- Potentially suspend non-critical operations if prolonged

**Post-Incident Reconciliation Steps:**
- Reconcile locally stored events with SIEM
- Investigate root cause of SIEM failure
- Implement redundancy measures
- Review all security events missed during downtime

## 8. UNAUTHORIZED PRIVILEGE ESCALATION

**Detection Trigger:** User attempting to access resources beyond their permission level

**Signal Source:**
- Application logs: "Unauthorized access attempt"
- SIEM: SecurityEventType.UNAUTHORIZED_ACCESS
- Metrics: unauthorized_access_attempts_total

**Severity Classification:** CRITICAL (P0)

**Immediate Automated Action:**
- Access immediately denied
- Suspicious activity logged to SIEM
- User session terminated

**Human Escalation Path:**
- Security team paged immediately
- Identity management team contacted
- Legal team potentially notified

**Time Limits:**
- T+1m: Security team contacted
- T+5m: Account access revoked
- T+15m: Forensic investigation initiated

**Rollback or Freeze Behavior:**
- Offending account immediately locked
- Related accounts potentially reviewed
- System access patterns analyzed

**Post-Incident Reconciliation Steps:**
- Complete forensic analysis of account
- Identify all unauthorized accesses
- Revoke escalated privileges
- Implement additional access controls

## 9. TOKEN FORGERY OR REPLAY ATTEMPT

**Detection Trigger:** Invalid JWT signature, reused nonce, or expired token

**Signal Source:**
- Application logs: "Invalid token signature" or "Nonce reuse attempt"
- SIEM: SecurityEventType.TOKEN_REUSE or REPLAY_ATTACK
- Metrics: invalid_token_attempts_total

**Severity Classification:** CRITICAL (P0)

**Immediate Automated Action:**
- Request immediately blocked
- Security event logged to SIEM
- User account potentially locked temporarily

**Human Escalation Path:**
- Security team notified
- Identity team contacted
- Customer support prepared

**Time Limits:**
- T+1m: Security team contacted
- T+5m: Account access reviewed
- T+15m: Forensic investigation started

**Rollback or Freeze Behavior:**
- Offending session terminated
- User account temporarily suspended
- Device binding potentially invalidated

**Post-Incident Reconciliation Steps:**
- Investigate token forgery vector
- Rotate compromised keys if needed
- Enhance token validation
- Notify affected users if necessary

## 10. UNKNOWN SYSTEM STATE

**Detection Trigger:** System in inconsistent or unexpected state

**Signal Source:**
- Application logs: "Unknown system state" or "Inconsistent state detected"
- Health checks returning unexpected responses
- Unexpected error conditions

**Severity Classification:** CRITICAL (P0)

**Immediate Automated Action:**
- System enters safe mode
- All operations suspended
- Emergency shutdown procedures initiated

**Human Escalation Path:**
- All engineering teams paged
- Management contacted immediately
- Emergency response team activated

**Time Limits:**
- T+1m: All teams contacted
- T+5m: Safe mode procedures executed
- T+15m: Executive leadership informed

**Rollback or Freeze Behavior:**
- Complete system freeze
- All services suspended
- Manual intervention required for recovery

**Post-Incident Reconciliation Steps:**
- Complete system state analysis
- Root cause identification
- Recovery procedures validated
- System restored from known good state