#!/usr/bin/env node

import { KeyRotationManager } from '../lib/crypto/key-rotation-manager';

/**
 * CLI tool for manual key rotation
 */

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  
  if (args.length === 0) {
    console.log('Usage:');
    console.log('  npm run rotate-keys -- <key-type>');
    console.log('  npm run rotate-keys -- --dry-run <key-type>');
    console.log('  npm run rotate-keys -- --list');
    console.log('');
    console.log('Key types: session, jwt, api, database');
    return;
  }

  const keyRotationManager = new KeyRotationManager();

  // Handle --list flag
  if (args.includes('--list')) {
    console.log('Available key types:');
    console.log('  - session');
    console.log('  - jwt');
    console.log('  - api');
    console.log('  - database');
    return;
  }

  // Check for dry-run flag
  const dryRunIndex = args.indexOf('--dry-run');
  const isDryRun = dryRunIndex !== -1;

  // Extract key type (remove --dry-run if present)
  let keyType = '';
  if (isDryRun) {
    args.splice(dryRunIndex, 1); // Remove --dry-run
    keyType = args[0];
  } else {
    keyType = args[0];
  }

  if (!keyType) {
    console.error('Error: Missing key type');
    process.exit(1);
  }

  // Validate key type
  const validKeyTypes = ['session', 'jwt', 'api', 'database'];
  if (!validKeyTypes.includes(keyType)) {
    console.error(`Error: Invalid key type. Valid types are: ${validKeyTypes.join(', ')}`);
    process.exit(1);
  }

  console.log(`Starting key rotation for type: ${keyType}`);
  console.log(`Mode: ${isDryRun ? 'DRY RUN' : 'LIVE ROTATION'}`);
  console.log('');

  try {
    if (isDryRun) {
      console.log('[DRY RUN] Would rotate key for type:', keyType);
      console.log('[DRY RUN] Would update key version tracking');
      console.log('[DRY RUN] Would ensure old keys remain available for decryption');
      console.log('[DRY RUN] Completed successfully');
    } else {
      console.log('Rotating key...');
      const success = await keyRotationManager.manualRotate(keyType);
      
      if (success) {
        console.log(`✅ Key rotation for ${keyType} completed successfully`);
      } else {
        console.error(`❌ Key rotation for ${keyType} failed`);
        process.exit(1);
      }
    }
  } catch (error) {
    console.error('Error during key rotation:', error);
    process.exit(1);
  }
}

// Run the main function
main().catch(error => {
  console.error('Unhandled error:', error);
  process.exit(1);
});