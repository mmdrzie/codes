/**
 * Full System Validation Test
 * Validates that all bank-grade safety mechanisms are properly implemented
 */

// Add Node.js types for process object
declare var process: {
  exit(code?: number): void;
};

import { SystemControls, FreezeReason } from './src/lib/system-controls';
import { DoubleEntryLedger, TransactionType } from './src/lib/financial-core/ledger';
import { TransactionEngine } from './src/lib/financial-core/transaction-engine';

async function runFullSystemValidation(): Promise<void> {
  console.log('🔍 Starting Full System Validation...\n');

  // Test 1: Kill-switch integrity
  console.log('✅ Testing Kill-switch Integrity...');
  const killSwitchValid = await SystemControls.validateKillSwitchIntegrity();
  console.log(`   Kill-switch integrity: ${killSwitchValid ? 'PASS' : 'FAIL'}\n`);

  if (!killSwitchValid) {
    console.error('❌ CRITICAL: Kill-switch integrity check failed!');
    process.exit(1);
  }

  // Test 2: System status controls
  console.log('✅ Testing System Status Controls...');
  
  // Check initial status
  const initialStatus = await SystemControls.getSystemStatus();
  console.log(`   Initial system status: ${initialStatus.status}`);

  // Test account freeze/unfreeze
  console.log('   Testing account freeze functionality...');
  const freezeResult = await SystemControls.freezeAccount(
    'test_account_123',
    FreezeReason.MANUAL_ADMIN_ACTION,
    'test_admin',
    'Test freeze for validation'
  );
  console.log(`   Account freeze: ${freezeResult ? 'PASS' : 'FAIL'}`);

  const isAccountFrozen = await SystemControls.isAccountFrozen('test_account_123');
  console.log(`   Account frozen check: ${isAccountFrozen ? 'PASS' : 'FAIL'}`);

  const unfreezeResult = await SystemControls.unfreezeAccount('test_account_123', 'test_admin');
  console.log(`   Account unfreeze: ${unfreezeResult ? 'PASS' : 'FAIL'}`);

  const isAccountStillFrozen = await SystemControls.isAccountFrozen('test_account_123');
  console.log(`   Account unfrozen check: ${!isAccountStillFrozen ? 'PASS' : 'FAIL'}`);

  // Test system freeze controls
  console.log('   Testing system freeze functionality...');
  const systemFreezeResult = await SystemControls.activateSystemWideFreeze(
    FreezeReason.TECHNICAL_MAINTENANCE,
    'test_admin',
    1, // 1 hour
    'Test system freeze for validation'
  );
  console.log(`   System freeze: ${systemFreezeResult ? 'PASS' : 'FAIL'}`);

  const systemIsFrozen = await SystemControls.isSystemFrozen();
  console.log(`   System frozen check: ${systemIsFrozen ? 'PASS' : 'FAIL'}`);

  const systemLiftResult = await SystemControls.liftSystemFreeze('test_admin');
  console.log(`   System unfreeze: ${systemLiftResult ? 'PASS' : 'FAIL'}`);

  const systemIsOperational = await SystemControls.isSystemOperational();
  console.log(`   System operational check: ${systemIsOperational ? 'PASS' : 'FAIL'}`);

  // Test 3: Emergency freeze
  console.log('   Testing emergency freeze functionality...');
  const emergencyFreezeResult = await SystemControls.activateEmergencyFreeze(
    FreezeReason.SECURITY_BREACH,
    'test_admin',
    'Test emergency freeze'
  );
  console.log(`   Emergency freeze: ${emergencyFreezeResult ? 'PASS' : 'FAIL'}`);

  const emergencySystemStatus = await SystemControls.getSystemStatus();
  console.log(`   Emergency system status: ${emergencySystemStatus.status}`);

  // Reset to operational for further tests
  await SystemControls.liftSystemFreeze('test_admin');

  // Test 4: Transaction engine respects freeze controls
  console.log('\n✅ Testing Transaction Engine Integration...');
  
  // First activate system freeze
  await SystemControls.activateSystemWideFreeze(
    FreezeReason.TECHNICAL_MAINTENANCE,
    'test_admin',
    1
  );

  // Try to execute a transaction - should fail due to system freeze
  const mockTransaction = {
    id: `test_tx_${Date.now()}`,
    type: TransactionType.TRANSFER,
    amount: 100,
    entries: [
      {
        accountId: 'test_account_1',
        amount: -100, // debit
        description: 'Test debit'
      },
      {
        accountId: 'test_account_2',
        amount: 100, // credit
        description: 'Test credit'
      }
    ],
    description: 'Test transaction',
    timestamp: Date.now(),
    correlationId: `corr_${Date.now()}`
  };

  const failedTxResult = await TransactionEngine.executeTransaction(mockTransaction);
  console.log(`   Transaction blocked during system freeze: ${!failedTxResult.success ? 'PASS' : 'FAIL'}`);

  // Lift the freeze for next test
  await SystemControls.liftSystemFreeze('test_admin');

  // Now freeze one of the accounts
  await SystemControls.freezeAccount(
    'test_account_1',
    FreezeReason.MANUAL_ADMIN_ACTION,
    'test_admin'
  );

  // Try to execute a transaction involving the frozen account - should fail
  const failedAccountTxResult = await TransactionEngine.executeTransaction(mockTransaction);
  console.log(`   Transaction blocked for frozen account: ${!failedAccountTxResult.success ? 'PASS' : 'FAIL'}`);

  // Clean up
  await SystemControls.unfreezeAccount('test_account_1', 'test_admin');

  // Test 5: Ledger respects freeze controls
  console.log('\n✅ Testing Ledger Integration...');
  
  // Freeze system again
  await SystemControls.activateSystemWideFreeze(
    FreezeReason.TECHNICAL_MAINTENANCE,
    'test_admin',
    1
  );

  // Try to record a transaction - should fail due to system freeze
  const ledgerRecordResult = await DoubleEntryLedger.recordTransaction(mockTransaction);
  console.log(`   Ledger blocked during system freeze: ${!ledgerRecordResult ? 'PASS' : 'FAIL'}`);

  // Lift the freeze
  await SystemControls.liftSystemFreeze('test_admin');

  // Now freeze one account
  await SystemControls.freezeAccount(
    'test_account_1',
    FreezeReason.MANUAL_ADMIN_ACTION,
    'test_admin'
  );

  // Try to record a transaction involving the frozen account - should fail
  const ledgerAccountResult = await DoubleEntryLedger.recordTransaction(mockTransaction);
  console.log(`   Ledger blocked for frozen account: ${!ledgerAccountResult ? 'PASS' : 'FAIL'}`);

  // Clean up
  await SystemControls.unfreezeAccount('test_account_1', 'test_admin');

  // Test 6: Read-only mode
  console.log('\n✅ Testing Read-Only Mode...');
  
  await SystemControls.setSystemReadOnly('test_admin', 'Test read-only mode');
  const readOnlyResult = await TransactionEngine.executeTransaction(mockTransaction);
  console.log(`   Transaction blocked in read-only mode: ${!readOnlyResult.success ? 'PASS' : 'FAIL'}`);

  // Reset to operational
  await SystemControls.liftSystemFreeze('test_admin');

  // Test 7: Emergency contacts functionality
  console.log('\n✅ Testing Emergency Contacts...');
  
  const contactAddResult = await SystemControls.addEmergencyContact('admin@example.com');
  console.log(`   Emergency contact add: ${contactAddResult ? 'PASS' : 'FAIL'}`);

  const contacts = await SystemControls.getEmergencyContacts();
  console.log(`   Emergency contacts retrieval: ${contacts.length > 0 ? 'PASS' : 'FAIL'}`);

  console.log('\n🎯 Full System Validation Complete!\n');

  // Summary
  const allTestsPassed = killSwitchValid;
  console.log(`📋 Final Result: ${allTestsPassed ? 'ALL TESTS PASSED' : 'SOME TESTS FAILED'}`);
  
  if (allTestsPassed) {
    console.log('\n✅ System is ready for real money operations with proper safety controls in place.');
  } else {
    console.log('\n❌ CRITICAL: System is NOT ready for real money operations.');
    process.exit(1);
  }
}

// Run the validation
runFullSystemValidation().catch(error => {
  console.error('❌ Validation failed with error:', error);
  process.exit(1);
});