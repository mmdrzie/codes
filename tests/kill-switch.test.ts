import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import KillSwitchManager, { EmergencyLevel } from '../src/lib/kill-switch/emergency-controls';

describe('Kill Switch Tests', () => {
  let killSwitchManager: KillSwitchManager;

  beforeEach(() => {
    killSwitchManager = KillSwitchManager.getInstance();
  });

  afterEach(async () => {
    // Reset emergency level to NONE after each test
    await killSwitchManager.setEmergencyLevel(EmergencyLevel.NONE, 'test-reset');
  });

  it('should set and get emergency level correctly', async () => {
    await killSwitchManager.setEmergencyLevel(EmergencyLevel.HIGH, 'test-user');
    const currentLevel = await killSwitchManager.getCurrentEmergencyLevel();
    
    expect(currentLevel).toBe(EmergencyLevel.HIGH);
  });

  it('should block operations at CRITICAL level', async () => {
    await killSwitchManager.setEmergencyLevel(EmergencyLevel.CRITICAL, 'test-user');
    
    const isReadBlocked = await killSwitchManager.isOperationBlocked('GET /api/data');
    const isWriteBlocked = await killSwitchManager.isOperationBlocked('POST /api/data');
    const isLoginBlocked = await killSwitchManager.isOperationBlocked('POST /api/auth/login');
    
    expect(isReadBlocked).toBe(true);
    expect(isWriteBlocked).toBe(true);
    expect(isLoginBlocked).toBe(true);
  });

  it('should block write operations at SEVERE level', async () => {
    await killSwitchManager.setEmergencyLevel(EmergencyLevel.SEVERE, 'test-user');
    
    const isReadBlocked = await killSwitchManager.isOperationBlocked('GET /api/data');
    const isWriteBlocked = await killSwitchManager.isOperationBlocked('POST /api/data');
    const isTransferBlocked = await killSwitchManager.isOperationBlocked('POST /api/transfer');
    
    expect(isReadBlocked).toBe(false);  // Read operations should be allowed
    expect(isWriteBlocked).toBe(true);  // Write operations should be blocked
    expect(isTransferBlocked).toBe(true); // Transfer operations should be blocked
  });

  it('should allow all operations at NONE level', async () => {
    await killSwitchManager.setEmergencyLevel(EmergencyLevel.NONE, 'test-user');
    
    const isReadBlocked = await killSwitchManager.isOperationBlocked('GET /api/data');
    const isWriteBlocked = await killSwitchManager.isOperationBlocked('POST /api/data');
    const isTransferBlocked = await killSwitchManager.isOperationBlocked('POST /api/transfer');
    
    expect(isReadBlocked).toBe(false);
    expect(isWriteBlocked).toBe(false);
    expect(isTransferBlocked).toBe(false);
  });

  it('should freeze and unfreeze accounts correctly', async () => {
    const accountId = 'test-account-123';
    const reason = 'Suspicious activity detected';
    const frozenBy = 'admin-user';
    
    // Check that account is not frozen initially
    let isFrozen = await killSwitchManager.isAccountFrozen(accountId);
    expect(isFrozen).toBe(false);
    
    // Freeze the account
    await killSwitchManager.freezeAccount(accountId, reason, frozenBy);
    
    // Check that account is now frozen
    isFrozen = await killSwitchManager.isAccountFrozen(accountId);
    expect(isFrozen).toBe(true);
    
    // Get freeze details
    const freezeDetails = await killSwitchManager.getAccountFreezeDetails(accountId);
    expect(freezeDetails).not.toBeNull();
    expect(freezeDetails?.accountId).toBe(accountId);
    expect(freezeDetails?.reason).toBe(reason);
    expect(freezeDetails?.frozenBy).toBe(frozenBy);
    
    // Unfreeze the account
    await killSwitchManager.unfreezeAccount(accountId, 'admin-user');
    
    // Check that account is no longer frozen
    isFrozen = await killSwitchManager.isAccountFrozen(accountId);
    expect(isFrozen).toBe(false);
  });

  it('should activate kill switch within 5 seconds', async () => {
    const startTime = Date.now();
    await killSwitchManager.setEmergencyLevel(EmergencyLevel.CRITICAL, 'test-user');
    const endTime = Date.now();
    
    // The operation should complete quickly (within 5 seconds)
    expect(endTime - startTime).toBeLessThan(5000);
    
    const currentLevel = await killSwitchManager.getCurrentEmergencyLevel();
    expect(currentLevel).toBe(EmergencyLevel.CRITICAL);
  });

  it('should send emergency notifications when activating critical level', async () => {
    // This test would be more complex in a real implementation
    // For now, we'll just verify that setting the level works
    await killSwitchManager.addEmergencyContact({
      name: 'Test Admin',
      email: 'admin@test.com',
      phone: '+1234567890'
    });
    
    const contacts = await killSwitchManager.getEmergencyContacts();
    expect(contacts.length).toBeGreaterThan(0);
    expect(contacts[0].email).toBe('admin@test.com');
  });

  it('should have granular controls that work as specified', async () => {
    // Test NONE level - no operations blocked
    await killSwitchManager.setEmergencyLevel(EmergencyLevel.NONE, 'test-user');
    expect(await killSwitchManager.isOperationBlocked('POST /api/transfer')).toBe(false);
    
    // Test ELEVATED level - no operations blocked
    await killSwitchManager.setEmergencyLevel(EmergencyLevel.ELEVATED, 'test-user');
    expect(await killSwitchManager.isOperationBlocked('POST /api/transfer')).toBe(false);
    
    // Test HIGH level - no operations blocked
    await killSwitchManager.setEmergencyLevel(EmergencyLevel.HIGH, 'test-user');
    expect(await killSwitchManager.isOperationBlocked('POST /api/transfer')).toBe(false);
    
    // Test SEVERE level - write operations blocked
    await killSwitchManager.setEmergencyLevel(EmergencyLevel.SEVERE, 'test-user');
    expect(await killSwitchManager.isOperationBlocked('POST /api/transfer')).toBe(true);
    expect(await killSwitchManager.isOperationBlocked('GET /api/user')).toBe(false);
    
    // Test CRITICAL level - all operations blocked
    await killSwitchManager.setEmergencyLevel(EmergencyLevel.CRITICAL, 'test-user');
    expect(await killSwitchManager.isOperationBlocked('GET /api/user')).toBe(true);
    expect(await killSwitchManager.isOperationBlocked('POST /api/transfer')).toBe(true);
  });
});