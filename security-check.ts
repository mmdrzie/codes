#!/usr/bin/env node
/**
 * Security Check Script
 * Runs a comprehensive security audit of the application
 */

import { SecurityAudit } from './src/lib/security-audit';
import { SecurityInitializer } from './src/lib/security-init';

async function runSecurityCheck() {
  console.log('🔍 Running Security Audit...\n');

  try {
    // Initialize security components
    console.log('🔐 Initializing security components...');
    await SecurityInitializer.initialize();
    console.log('✅ Security components initialized\n');

    // Run comprehensive audit
    console.log('📋 Performing security audit...');
    const auditResult = await SecurityAudit.performAudit();

    console.log('\n📊 Audit Results:');
    console.log(`   Status: ${auditResult.passed ? '✅ PASSED' : '❌ FAILED'}`);
    console.log(`   Total Issues: ${auditResult.issues.length}`);
    console.log(`   Critical: ${auditResult.issues.filter(i => i.severity === 'critical').length}`);
    console.log(`   High: ${auditResult.issues.filter(i => i.severity === 'high').length}`);
    console.log(`   Medium: ${auditResult.issues.filter(i => i.severity === 'medium').length}`);
    console.log(`   Low: ${auditResult.issues.filter(i => i.severity === 'low').length}`);

    if (auditResult.issues.length > 0) {
      console.log('\n⚠️  Issues Found:');
      for (const issue of auditResult.issues) {
        const severitySymbol = 
          issue.severity === 'critical' ? '🔴' :
          issue.severity === 'high' ? '🟠' :
          issue.severity === 'medium' ? '🟡' : '🔵';
          
        console.log(`   ${severitySymbol} [${issue.severity.toUpperCase()}] ${issue.category}: ${issue.description}`);
        console.log(`      Impact: ${issue.impact}`);
        console.log(`      Recommendation: ${issue.recommendation}\n`);
      }
    }

    if (auditResult.recommendations.length > 0) {
      console.log('💡 Recommendations:');
      for (const rec of auditResult.recommendations) {
        console.log(`   • ${rec}`);
      }
      console.log('');
    }

    // Check overall result
    if (!auditResult.passed) {
      console.log('❌ Security audit failed - critical or high severity issues detected!');
      console.log('⚠️  Do not deploy to production until these issues are resolved.');
      process.exit(1);
    } else {
      console.log('✅ Security audit passed - system is ready for production!');
      process.exit(0);
    }
  } catch (error) {
    console.error('💥 Security check failed with error:', error);
    process.exit(1);
  }
}

// Run the security check
runSecurityCheck().catch(error => {
  console.error('Fatal error running security check:', error);
  process.exit(1);
});