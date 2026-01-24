/**
 * Security Initialization Module
 * Ensures all security components are properly initialized before application startup
 */

import { logger } from './logger';
import { SecurityMonitor } from './security-monitoring';
import { siemService } from './siem-integration';
import { SecurityAudit } from './security-audit';
import { KeyManager } from './tokenUtils';
import { SecurityEnhancements } from './security-enhancements';
import { PQCValidator } from './pqc-validator';
import { SecretsManager } from './secrets-manager';

export class SecurityInitializer {
  private static initialized = false;

  /**
   * Initialize all security components
   */
  static async initialize(): Promise<void> {
    if (this.initialized) {
      logger.info('Security already initialized');
      return;
    }

    logger.info('Starting security initialization');

    try {
      // 1. Initialize comprehensive security enhancements (includes PQC and secrets validation)
      await SecurityEnhancements.initialize();
      
      // 2. Initialize cryptographic keys
      await this.initializeCryptoKeys();
      
      // 3. Validate environment configuration
      await this.validateEnvironment();
      
      // 4. Test SIEM connectivity
      await this.testSIEMConnectivity();
      
      // 5. Run security audit
      await this.runSecurityAudit();
      
      // 6. Initialize security monitoring
      await this.initializeSecurityMonitoring();

      this.initialized = true;
      logger.info('Security initialization completed successfully');
    } catch (error) {
      logger.error('Security initialization failed', { error: (error as Error).message });
      throw new Error(`Security initialization failed: ${(error as Error).message}`);
    }
  }

  /**
   * Initialize cryptographic keys
   */
  private static async initializeCryptoKeys(): Promise<void> {
    logger.info('Initializing cryptographic keys');
    
    try {
      const keyManager = KeyManager.getInstance();
      await keyManager.initializeKeys();
      
      logger.info('Cryptographic keys initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize cryptographic keys', { error: (error as Error).message });
      throw error;
    }
  }

  /**
   * Validate environment configuration
   */
  private static async validateEnvironment(): Promise<void> {
    logger.info('Validating environment configuration');
    
    const requiredEnvVars = [
      'NODE_ENV',
      'NEXT_PUBLIC_BASE_URL'
    ];

    // Only require secrets in production
    if (process.env.NODE_ENV === 'production') {
      requiredEnvVars.push(
        'JWT_ACCESS_SECRET',
        'JWT_REFRESH_SECRET',
        'WALLET_JWT_SECRET'
      );
    }

    const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
    
    if (missingVars.length > 0) {
      logger.error('Missing required environment variables', { missingVars });
      throw new Error(`Missing required environment variables: ${missingVars.join(', ')}`);
    }

    // Validate secret lengths
    const secretsToCheck = [
      { name: 'JWT_ACCESS_SECRET', value: process.env.JWT_ACCESS_SECRET },
      { name: 'JWT_REFRESH_SECRET', value: process.env.JWT_REFRESH_SECRET },
      { name: 'WALLET_JWT_SECRET', value: process.env.WALLET_JWT_SECRET }
    ];

    for (const { name, value } of secretsToCheck) {
      if (value && value.length < 32) {
        logger.error(`${name} is too short (minimum 32 characters)`, { 
          name,
          length: value.length 
        });
        throw new Error(`${name} must be at least 32 characters long`);
      }
    }

    logger.info('Environment configuration validated successfully');
  }

  /**
   * Test SIEM connectivity
   */
  private static async testSIEMConnectivity(): Promise<void> {
    if (process.env.SIEM_ENABLED !== 'true') {
      logger.info('SIEM integration disabled, skipping connectivity test');
      return;
    }

    logger.info('Testing SIEM connectivity');
    
    try {
      await siemService.emitSecurityEvent({
        event_type: 'auth_success',
        severity: 'low',
        ip_address: '127.0.0.1',
        user_agent: 'Security Initialization',
        route: '/init',
        outcome: 'success',
        source: 'application',
        details: { 
          init_test: true,
          timestamp: new Date().toISOString()
        }
      });

      logger.info('SIEM connectivity test successful');
    } catch (error) {
      logger.error('SIEM connectivity test failed', { 
        error: (error as Error).message,
        suggestion: 'Verify SIEM configuration before production deployment'
      });
      
      // CRITICAL: In production, SIEM failure should cause startup failure
      if (process.env.NODE_ENV === 'production') {
        logger.error('CRITICAL: Production environment requires functional SIEM. Returning error.');
        throw new Error('SIEM connectivity test failed: Production environment requires functional SIEM');
      }
      
      throw new Error(`SIEM connectivity test failed: ${(error as Error).message}`);
    }
  }

  /**
   * Run security audit
   */
  private static async runSecurityAudit(): Promise<void> {
    logger.info('Running security audit');
    
    try {
      const auditResult = await SecurityAudit.performAudit();
      
      logger.info('Security audit completed', {
        passed: auditResult.passed,
        issuesFound: auditResult.issues.length,
        criticalIssues: auditResult.issues.filter(i => i.severity === 'critical').length,
        highIssues: auditResult.issues.filter(i => i.severity === 'high').length
      });

      // In production, fail if there are critical or high severity issues
      if (process.env.NODE_ENV === 'production' && 
          (auditResult.issues.filter(i => i.severity === 'critical' || i.severity === 'high').length > 0)) {
        logger.error('Security audit failed - critical or high severity issues found in production');
        
        const criticalIssues = auditResult.issues.filter(i => i.severity === 'critical');
        const highIssues = auditResult.issues.filter(i => i.severity === 'high');
        
        logger.error('Critical issues found:', { criticalIssues: criticalIssues.map(i => i.description) });
        logger.error('High severity issues found:', { highIssues: highIssues.map(i => i.description) });
        
        throw new Error('Security audit failed - critical or high severity issues found in production environment');
      }
    } catch (error) {
      logger.error('Security audit failed', { error: (error as Error).message });
      throw error;
    }
  }

  /**
   * Initialize security monitoring
   */
  private static async initializeSecurityMonitoring(): Promise<void> {
    logger.info('Initializing security monitoring');
    
    // Test that security monitoring can capture events
    try {
      await SecurityMonitor.logAuthSuccess('system-initializer', {
        ipAddress: '127.0.0.1',
        userAgent: 'Security Initialization',
        metadata: { 
          stage: 'startup',
          timestamp: new Date().toISOString()
        }
      });

      logger.info('Security monitoring initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize security monitoring', { error: (error as Error).message });
      throw error;
    }
  }

  /**
   * Check if security has been initialized
   */
  static isInitialized(): boolean {
    return this.initialized;
  }

  /**
   * Perform security health check
   */
  static async healthCheck(): Promise<{
    status: 'healthy' | 'degraded' | 'unhealthy';
    details: Record<string, any>;
  }> {
    if (!this.initialized) {
      return {
        status: 'unhealthy',
        details: { 
          error: 'Security not initialized',
          initialized: false
        }
      };
    }

    // Run a quick health check
    return await SecurityAudit.healthCheck();
  }
}