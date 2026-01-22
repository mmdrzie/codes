#!/usr/bin/env node

/**
 * Automated Security Validation Script
 * Performs comprehensive security checks and vulnerability scanning
 */

import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { logger } from '../src/lib/logger';
import { SecurityEnhancements } from '../src/lib/security-enhancements';
import { PQCValidator } from '../src/lib/pqc-validator';
import { SecretsManager } from '../src/lib/secrets-manager';

class SecurityValidationScript {
  private results: {
    timestamp: string;
    environment: string;
    checks: Array<{
      name: string;
      status: 'pass' | 'fail' | 'warning';
      details: string;
      severity?: 'low' | 'medium' | 'high' | 'critical';
    }>;
  };

  constructor() {
    this.results = {
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      checks: []
    };
  }

  /**
   * Runs all security validation checks
   */
  async runValidation(): Promise<void> {
    logger.info('Starting automated security validation');

    try {
      // Run dependency vulnerability scan
      await this.runDependencyScan();

      // Run secrets validation
      await this.runSecretsValidation();

      // Run PQC validation
      await this.runPQCValidation();

      // Run configuration validation
      await this.runConfigurationValidation();

      // Run security posture assessment
      await this.runSecurityPostureAssessment();

      // Generate report
      this.generateReport();

      // Determine if validation passed
      const failedChecks = this.results.checks.filter(check => check.status === 'fail');
      if (failedChecks.length > 0) {
        logger.error(`Security validation failed with ${failedChecks.length} critical issues`);
        
        // Exit with error code if in production or if specifically requested
        if (process.env.NODE_ENV === 'production' || process.env.FAIL_ON_SECURITY_ISSUES === 'true') {
          process.exit(1);
        }
      } else {
        logger.info('Security validation passed successfully');
      }
    } catch (error) {
      logger.error('Security validation script failed', { error: (error as Error).message });
      process.exit(1);
    }
  }

  /**
   * Runs dependency vulnerability scanning
   */
  private async runDependencyScan(): Promise<void> {
    logger.info('Running dependency vulnerability scan');

    try {
      // Run npm audit
      const npmAuditOutput = execSync('npm audit --json', { encoding: 'utf8' });
      const npmAudit = JSON.parse(npmAuditOutput);

      if (npmAudit.metadata && npmAudit.metadata.vulnerabilities) {
        const vulnerabilities = npmAudit.metadata.vulnerabilities;
        const totalVulns = vulnerabilities.total;
        const criticalVulns = vulnerabilities.critical || 0;
        const highVulns = vulnerabilities.high || 0;

        if (totalVulns > 0) {
          this.results.checks.push({
            name: 'Dependency Vulnerability Scan',
            status: criticalVulns > 0 || highVulns > 0 ? 'fail' : 'warning',
            details: `Found ${totalVulns} vulnerabilities (${criticalVulns} critical, ${highVulns} high)`,
            severity: criticalVulns > 0 ? 'critical' : highVulns > 0 ? 'high' : 'medium'
          });
        } else {
          this.results.checks.push({
            name: 'Dependency Vulnerability Scan',
            status: 'pass',
            details: 'No vulnerabilities found in dependencies'
          });
        }
      } else {
        this.results.checks.push({
          name: 'Dependency Vulnerability Scan',
          status: 'pass',
          details: 'No vulnerabilities found in dependencies'
        });
      }
    } catch (error) {
      // npm audit might fail if there are vulnerabilities, which is expected
      // Parse the error output to get vulnerability info
      try {
        const errorMessage = (error as any).stdout || (error as any).stderr || (error as Error).message;
        if (errorMessage.includes('vulnerabilities')) {
          // Try to parse the JSON output even when npm audit exits with error code
          const startIndex = errorMessage.indexOf('{');
          if (startIndex !== -1) {
            const jsonStr = errorMessage.substring(startIndex);
            const npmAudit = JSON.parse(jsonStr);
            
            if (npmAudit.metadata && npmAudit.metadata.vulnerabilities) {
              const vulnerabilities = npmAudit.metadata.vulnerabilities;
              const totalVulns = vulnerabilities.total;
              const criticalVulns = vulnerabilities.critical || 0;
              const highVulns = vulnerabilities.high || 0;

              this.results.checks.push({
                name: 'Dependency Vulnerability Scan',
                status: criticalVulns > 0 || highVulns > 0 ? 'fail' : 'warning',
                details: `Found ${totalVulns} vulnerabilities (${criticalVulns} critical, ${highVulns} high)`,
                severity: criticalVulns > 0 ? 'critical' : highVulns > 0 ? 'high' : 'medium'
              });
              return;
            }
          }
        }
      } catch (parseError) {
        // If parsing fails, just report the general error
      }

      this.results.checks.push({
        name: 'Dependency Vulnerability Scan',
        status: 'warning',
        details: 'Could not complete dependency vulnerability scan: ' + (error as Error).message
      });
    }
  }

  /**
   * Runs secrets validation
   */
  private async runSecretsValidation(): Promise<void> {
    logger.info('Running secrets validation');

    try {
      const auditResult = await SecretsManager.audit();
      
      if (auditResult.passed) {
        this.results.checks.push({
          name: 'Secrets Configuration Validation',
          status: 'pass',
          details: 'All secrets properly configured and validated'
        });
      } else {
        const criticalIssues = auditResult.issues.filter(i => i.severity === 'critical');
        const highIssues = auditResult.issues.filter(i => i.severity === 'high');
        
        if (criticalIssues.length > 0 || highIssues.length > 0) {
          this.results.checks.push({
            name: 'Secrets Configuration Validation',
            status: 'fail',
            details: `Secrets validation failed: ${criticalIssues.concat(highIssues).map(i => i.description).join('; ')}`,
            severity: criticalIssues.length > 0 ? 'critical' : 'high'
          });
        } else {
          this.results.checks.push({
            name: 'Secrets Configuration Validation',
            status: 'warning',
            details: `Secrets validation has non-critical issues: ${auditResult.issues.map(i => i.description).join('; ')}`
          });
        }
      }
    } catch (error) {
      this.results.checks.push({
        name: 'Secrets Configuration Validation',
        status: 'fail',
        details: 'Secrets validation failed: ' + (error as Error).message,
        severity: 'critical'
      });
    }
  }

  /**
   * Runs Post-Quantum Cryptography validation
   */
  private async runPQCValidation(): Promise<void> {
    logger.info('Running Post-Quantum Cryptography validation');

    try {
      const status = PQCValidator.getPQCStatus();
      
      if (status.valid) {
        this.results.checks.push({
          name: 'Post-Quantum Cryptography Validation',
          status: 'pass',
          details: 'PQC libraries available and validated'
        });
      } else {
        this.results.checks.push({
          name: 'Post-Quantum Cryptography Validation',
          status: 'fail',
          details: 'PQC validation failed - libraries not available',
          severity: 'critical'
        });
      }
    } catch (error) {
      this.results.checks.push({
        name: 'Post-Quantum Cryptography Validation',
        status: 'fail',
        details: 'PQC validation error: ' + (error as Error).message,
        severity: 'critical'
      });
    }
  }

  /**
   * Runs configuration validation
   */
  private async runConfigurationValidation(): Promise<void> {
    logger.info('Running configuration validation');

    // Check for common security misconfigurations
    const checks = [
      {
        name: 'Environment Variables',
        condition: !!process.env.NODE_ENV,
        details: process.env.NODE_ENV ? 'NODE_ENV is set' : 'NODE_ENV is not set',
        severity: 'high'
      },
      {
        name: 'Production Security Headers',
        condition: process.env.NODE_ENV !== 'production' || !!process.env.CSP_ENABLED,
        details: process.env.NODE_ENV !== 'production' || process.env.CSP_ENABLED 
          ? 'Security headers properly configured for production' 
          : 'Security headers not configured for production',
        severity: 'medium'
      },
      {
        name: 'Rate Limiting Configuration',
        condition: !!process.env.RATE_LIMIT_WINDOW && !!process.env.RATE_LIMIT_MAX,
        details: process.env.RATE_LIMIT_WINDOW && process.env.RATE_LIMIT_MAX
          ? 'Rate limiting properly configured'
          : 'Rate limiting not properly configured',
        severity: 'medium'
      },
      {
        name: 'Debug Mode',
        condition: process.env.NODE_ENV !== 'production' || process.env.DEBUG !== 'true',
        details: process.env.NODE_ENV !== 'production' || process.env.DEBUG !== 'true'
          ? 'Debug mode properly disabled in production'
          : 'Debug mode enabled in production - potential security risk',
        severity: 'high'
      }
    ];

    checks.forEach(check => {
      this.results.checks.push({
        name: check.name,
        status: check.condition ? 'pass' : 'fail',
        details: check.details,
        ...(check.condition ? {} : { severity: check.severity })
      });
    });
  }

  /**
   * Runs security posture assessment
   */
  private async runSecurityPostureAssessment(): Promise<void> {
    logger.info('Running security posture assessment');

    try {
      const posture = SecurityEnhancements.getSecurityPosture();
      
      // Assess overall security posture
      const issues = [];
      
      if (!posture.pqcStatus.valid) {
        issues.push('PQC not validated');
      }
      
      if (!posture.secretsStatus.secretsValidated) {
        issues.push('Secrets not validated');
      }
      
      if (!posture.securityFeatures.cspEnabled) {
        issues.push('CSP not enabled');
      }
      
      if (!posture.securityFeatures.hstsEnabled) {
        issues.push('HSTS not enabled');
      }
      
      if (issues.length > 0) {
        this.results.checks.push({
          name: 'Security Posture Assessment',
          status: 'fail',
          details: `Security posture issues: ${issues.join(', ')}`,
          severity: 'high'
        });
      } else {
        this.results.checks.push({
          name: 'Security Posture Assessment',
          status: 'pass',
          details: 'Security posture is strong and properly configured'
        });
      }
    } catch (error) {
      this.results.checks.push({
        name: 'Security Posture Assessment',
        status: 'fail',
        details: 'Could not assess security posture: ' + (error as Error).message,
        severity: 'critical'
      });
    }
  }

  /**
   * Generates a security validation report
   */
  private generateReport(): void {
    logger.info('Generating security validation report');

    // Create reports directory if it doesn't exist
    const reportsDir = path.join(process.cwd(), 'reports');
    if (!fs.existsSync(reportsDir)) {
      fs.mkdirSync(reportsDir, { recursive: true });
    }

    // Generate detailed report
    const reportPath = path.join(reportsDir, `security-validation-report-${this.results.timestamp}.json`);
    
    const report = {
      ...this.results,
      summary: {
        totalChecks: this.results.checks.length,
        passedChecks: this.results.checks.filter(c => c.status === 'pass').length,
        failedChecks: this.results.checks.filter(c => c.status === 'fail').length,
        warningChecks: this.results.checks.filter(c => c.status === 'warning').length,
        criticalIssues: this.results.checks.filter(c => c.severity === 'critical').length,
        highIssues: this.results.checks.filter(c => c.severity === 'high').length
      }
    };

    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    logger.info(`Security validation report saved to: ${reportPath}`);

    // Print summary to console
    console.log('\n=== SECURITY VALIDATION SUMMARY ===');
    console.log(`Total checks: ${report.summary.totalChecks}`);
    console.log(`Passed: ${report.summary.passedChecks}`);
    console.log(`Failed: ${report.summary.failedChecks}`);
    console.log(`Warnings: ${report.summary.warningChecks}`);
    console.log(`Critical issues: ${report.summary.criticalIssues}`);
    console.log(`High issues: ${report.summary.highIssues}`);
    console.log('==================================\n');

    // Print failed checks details
    const failedChecks = this.results.checks.filter(c => c.status === 'fail');
    if (failedChecks.length > 0) {
      console.log('FAILED CHECKS:');
      failedChecks.forEach(check => {
        console.log(`- ${check.name}: ${check.details}`);
      });
      console.log('');
    }

    // Print high/critical issues
    const highCriticalIssues = this.results.checks.filter(c => c.severity === 'high' || c.severity === 'critical');
    if (highCriticalIssues.length > 0) {
      console.log('HIGH/CRITICAL ISSUES:');
      highCriticalIssues.forEach(check => {
        console.log(`- [${check.severity.toUpperCase()}] ${check.name}: ${check.details}`);
      });
      console.log('');
    }
  }
}

// Run the validation if this script is executed directly
if (require.main === module) {
  const validator = new SecurityValidationScript();
  validator.runValidation().catch(error => {
    logger.error('Security validation script error', { error: (error as Error).message });
    process.exit(1);
  });
}

export { SecurityValidationScript };