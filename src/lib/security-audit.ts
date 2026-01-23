/**
 * Security Audit & Hardening Module
 * Validates all security controls and ensures production readiness
 */

import { logger } from './logger';
import { SecurityMonitor } from './security-monitoring';
import { siemService } from './siem-integration';
import { verifyAccessToken, verifyRefreshToken } from './tokenUtils';
import { checkRateLimit } from './rateLimit';

export interface SecurityAuditResult {
  passed: boolean;
  issues: SecurityIssue[];
  recommendations: string[];
  timestamp: Date;
}

export interface SecurityIssue {
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: 'auth' | 'session' | 'token' | 'logging' | 'network' | 'configuration';
  description: string;
  impact: string;
  recommendation: string;
}

export class SecurityAudit {
  /**
   * Perform comprehensive security audit
   */
  static async performAudit(): Promise<SecurityAuditResult> {
    const issues: SecurityIssue[] = [];
    const recommendations: string[] = [];

    logger.info('Starting security audit');

    // Check 1: Environment configuration
    const envIssues = await this.checkEnvironmentSecurity();
    issues.push(...envIssues);

    // Check 2: Token validation mechanisms
    const tokenIssues = await this.checkTokenValidation();
    issues.push(...tokenIssues);

    // Check 3: Logging and monitoring
    const loggingIssues = await this.checkLoggingSecurity();
    issues.push(...loggingIssues);

    // Check 4: Rate limiting
    const rateLimitIssues = await this.checkRateLimiting();
    issues.push(...rateLimitIssues);

    // Check 5: Session security
    const sessionIssues = await this.checkSessionSecurity();
    issues.push(...sessionIssues);

    // Generate recommendations based on findings
    recommendations.push(...this.generateRecommendations(issues));

    const result: SecurityAuditResult = {
      passed: issues.filter(issue => issue.severity === 'critical' || issue.severity === 'high').length === 0,
      issues,
      recommendations,
      timestamp: new Date()
    };

    logger.info('Security audit completed', {
      passed: result.passed,
      criticalIssues: issues.filter(i => i.severity === 'critical').length,
      highIssues: issues.filter(i => i.severity === 'high').length,
      totalIssues: issues.length
    });

    return result;
  }

  /**
   * Check environment security configuration
   */
  private static async checkEnvironmentSecurity(): Promise<SecurityIssue[]> {
    const issues: SecurityIssue[] = [];

    // Check for required environment variables
    const requiredVars = [
      'JWT_ACCESS_SECRET',
      'JWT_REFRESH_SECRET', 
      'WALLET_JWT_SECRET',
      'NEXT_PUBLIC_BASE_URL'
    ];

    for (const varName of requiredVars) {
      if (!process.env[varName]) {
        issues.push({
          severity: 'critical',
          category: 'configuration',
          description: `Missing required environment variable: ${varName}`,
          impact: 'Security tokens cannot be properly signed/verified',
          recommendation: `Set ${varName} environment variable with strong secret`
        });
      }
    }

    // Check secret lengths
    const secretsToCheck = [
      { name: 'JWT_ACCESS_SECRET', value: process.env.JWT_ACCESS_SECRET },
      { name: 'JWT_REFRESH_SECRET', value: process.env.JWT_REFRESH_SECRET },
      { name: 'WALLET_JWT_SECRET', value: process.env.WALLET_JWT_SECRET }
    ];

    for (const { name, value } of secretsToCheck) {
      if (value && value.length < 32) {
        issues.push({
          severity: 'high',
          category: 'configuration',
          description: `${name} is too short (minimum 32 characters)`,
          impact: 'Cryptographic secrets are vulnerable to brute force attacks',
          recommendation: `Increase ${name} to at least 32 random characters`
        });
      }
    }

    // Check for development configurations in production
    if (process.env.NODE_ENV === 'production') {
      if (process.env.JWT_ACCESS_SECRET?.startsWith('default_secret') ||
          process.env.JWT_REFRESH_SECRET?.startsWith('default_secret') ||
          process.env.WALLET_JWT_SECRET?.startsWith('default_secret')) {
        issues.push({
          severity: 'critical',
          category: 'configuration',
          description: 'Using default secrets in production environment',
          impact: 'System is completely insecure with default secrets',
          recommendation: 'Generate and configure strong, unique secrets for production'
        });
      }
    }

    return issues;
  }

  /**
   * Check token validation mechanisms
   */
  private static async checkTokenValidation(): Promise<SecurityIssue[]> {
    const issues: SecurityIssue[] = [];

    // Test token validation with malformed tokens
    try {
      const result = await verifyAccessToken('invalid.token.format');
      if (result !== null) {
        issues.push({
          severity: 'high',
          category: 'token',
          description: 'Token validation accepts malformed tokens',
          impact: 'Potential security bypass with invalid tokens',
          recommendation: 'Ensure token validation properly rejects all malformed tokens'
        });
      }
    } catch (error) {
      // This is expected behavior - validation should handle errors gracefully
    }

    // Test refresh token validation
    try {
      const result = await verifyRefreshToken('invalid.token.format');
      if (result.valid) {
        issues.push({
          severity: 'high',
          category: 'token',
          description: 'Refresh token validation accepts malformed tokens',
          impact: 'Potential refresh token bypass',
          recommendation: 'Ensure refresh token validation properly rejects all malformed tokens'
        });
      }
    } catch (error) {
      // This is expected behavior
    }

    return issues;
  }

  /**
   * Check logging and monitoring security
   */
  private static async checkLoggingSecurity(): Promise<SecurityIssue[]> {
    const issues: SecurityIssue[] = [];

    // Check if SIEM is properly configured
    if (process.env.SIEM_ENABLED === 'true') {
      // Test SIEM connectivity by attempting to emit a test event
      try {
        await siemService.emitSecurityEvent({
          event_type: 'suspicous_activity',
          severity: 'low',
          ip_address: '127.0.0.1',
          user_agent: 'Security Audit',
          route: '/health',
          outcome: 'detected',
          source: 'application',
          details: { audit_test: true }
        });
      } catch (error) {
        issues.push({
          severity: 'high',
          category: 'logging',
          description: 'SIEM service failed to accept security events',
          impact: 'Security events are not being monitored',
          recommendation: 'Verify SIEM configuration and connectivity'
        });
      }
    }

    // Check for sensitive information in logs
    // This would require more sophisticated log analysis in practice
    if (process.env.LOG_LEVEL === 'debug' && process.env.NODE_ENV === 'production') {
      issues.push({
        severity: 'medium',
        category: 'logging',
        description: 'Debug logging enabled in production',
        impact: 'Potential sensitive information leakage in logs',
        recommendation: 'Set LOG_LEVEL to warn or error in production'
      });
    }

    return issues;
  }

  /**
   * Check rate limiting configuration
   */
  private static async checkRateLimiting(): Promise<SecurityIssue[]> {
    const issues: SecurityIssue[] = [];

    // Test rate limiting functionality
    try {
      const mockIdentifier = 'audit-test-' + Date.now();
      
      // Test that rate limiting doesn't throw errors
      const result = await checkRateLimit(mockIdentifier, 'api');
      
      if (typeof result.allowed !== 'boolean') {
        issues.push({
          severity: 'high',
          category: 'network',
          description: 'Rate limiting returns unexpected result format',
          impact: 'Rate limiting may not function properly',
          recommendation: 'Verify rate limiting implementation returns consistent format'
        });
      }
    } catch (error) {
      issues.push({
        severity: 'high',
        category: 'network',
        description: 'Rate limiting throws unhandled exception',
        impact: 'Denial of service through rate limit bypass',
        recommendation: 'Implement proper error handling in rate limiting'
      });
    }

    return issues;
  }

  /**
   * Check session security mechanisms
   */
  private static async checkSessionSecurity(): Promise<SecurityIssue[]> {
    const issues: SecurityIssue[] = [];

    // Check for session binding configuration
    if (process.env.STRICT_SESSION_BINDING === 'false' || !process.env.STRICT_SESSION_BINDING) {
      issues.push({
        severity: 'medium',
        category: 'session',
        description: 'Session binding validation not in strict mode',
        impact: 'Increased risk of session hijacking',
        recommendation: 'Consider enabling strict session binding in production'
      });
    }

    return issues;
  }

  /**
   * Generate security recommendations based on issues found
   */
  private static generateRecommendations(issues: SecurityIssue[]): string[] {
    const recommendations: string[] = [];
    
    const criticalIssues = issues.filter(i => i.severity === 'critical');
    const highIssues = issues.filter(i => i.severity === 'high');
    const mediumIssues = issues.filter(i => i.severity === 'medium');
    
    if (criticalIssues.length > 0) {
      recommendations.push('CRITICAL: Address all critical security issues immediately before production deployment');
    }
    
    if (highIssues.length > 0) {
      recommendations.push('HIGH: Fix all high severity issues before production deployment');
    }
    
    if (mediumIssues.length > 0) {
      recommendations.push('MEDIUM: Review and address medium severity issues for optimal security');
    }
    
    if (issues.length === 0) {
      recommendations.push('No security issues detected - system appears ready for production');
    }
    
    return recommendations;
  }

  /**
   * Run security health check
   */
  static async healthCheck(): Promise<{
    status: 'healthy' | 'degraded' | 'unhealthy';
    details: Record<string, any>;
  }> {
    const details: Record<string, any> = {};
    
    // Check environment
    details.environment = {
      configured: process.env.JWT_ACCESS_SECRET && process.env.JWT_ACCESS_SECRET.length >= 32,
      productionMode: process.env.NODE_ENV === 'production'
    };
    
    // Check SIEM connectivity if enabled
    if (process.env.SIEM_ENABLED === 'true') {
      try {
        await siemService.emitSecurityEvent({
          event_type: 'suspicous_activity',
          severity: 'low',
          ip_address: '127.0.0.1',
          user_agent: 'Health Check',
          route: '/health',
          outcome: 'detected',
          source: 'application',
          details: { health_check: true }
        });
        details.siem = { connected: true };
      } catch (error) {
        details.siem = { connected: false, error: (error as Error).message };
      }
    } else {
      details.siem = { enabled: false };
    }
    
    // Overall health determination
    const isHealthy = 
      details.environment.configured && 
      details.environment.productionMode &&
      (process.env.SIEM_ENABLED !== 'true' || details.siem.connected);
    
    return {
      status: isHealthy ? 'healthy' : 'unhealthy',
      details
    };
  }
}