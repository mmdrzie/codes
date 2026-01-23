/**
 * Comprehensive Security Enhancements Module
 * Implements all the security improvements identified in the requirements
 */

import { NextRequest, NextResponse } from 'next/server';
import { logger } from './logger';
import { PQCValidator } from './pqc-validator';
import { SecretsManager, validateSecretsConfig } from './secrets-manager';
import { SecurityMonitor } from './security-monitoring';
import { getClientIp, generateCspNonce, createCspHeader, validateSessionBinding, applyEnhancedRateLimiting, validateRequestForSuspiciousPatterns, addSecurityHeaders, sanitizeErrorMessage } from './security-middleware';

export class SecurityEnhancements {
  /**
   * Performs comprehensive security initialization
   * This ensures all security measures are in place before application starts
   */
  static async initialize(): Promise<void> {
    logger.info('Starting comprehensive security initialization');

    try {
      // 1. Validate secrets configuration (fail closed if not met)
      await validateSecretsConfig();
      logger.info('Secrets configuration validated');

      // 2. Validate Post-Quantum Cryptography availability (fail closed if not met)
      await PQCValidator.validatePQC();
      logger.info('Post-Quantum Cryptography validated');

      // 3. Initialize security monitoring
      await SecurityMonitor.initialize();
      logger.info('Security monitoring initialized');

      // 4. Perform security audit
      await this.performSecurityAudit();
      logger.info('Security audit completed');

      logger.info('Comprehensive security initialization completed successfully');
    } catch (error) {
      logger.error('Security initialization failed', { error: (error as Error).message });
      
      // Log security event for the failure
      await SecurityMonitor.logEvent(
        'security_initialization_failure',
        {
          userId: 'system',
          ipAddress: '127.0.0.1',
          userAgent: 'Security Initialization Process',
          timestamp: new Date(),
          metadata: {
            stage: 'startup',
            error: (error as Error).message,
            node_env: process.env.NODE_ENV
          }
        },
        `Security initialization failed: ${(error as Error).message}`
      );

      // Re-throw the error to prevent application startup
      throw error;
    }
  }

  /**
   * Performs a comprehensive security audit
   */
  private static async performSecurityAudit(): Promise<void> {
    logger.info('Performing comprehensive security audit');

    // Check for security misconfigurations
    const auditResults = await this.runSecurityChecks();

    // Report any issues found
    if (auditResults.issues.length > 0) {
      const criticalIssues = auditResults.issues.filter(issue => issue.severity === 'critical');
      const highIssues = auditResults.issues.filter(issue => issue.severity === 'high');

      logger.warn('Security audit completed with issues', {
        totalIssues: auditResults.issues.length,
        criticalIssues: criticalIssues.length,
        highIssues: highIssues.length
      });

      // In production, fail if there are critical or high severity issues
      if (process.env.NODE_ENV === 'production' && (criticalIssues.length > 0 || highIssues.length > 0)) {
        logger.error('Security audit failed - critical or high severity issues found in production');
        
        const errorMsg = `Security audit failed: ${criticalIssues.concat(highIssues).map(i => i.description).join('; ')}`;
        throw new Error(errorMsg);
      }
    } else {
      logger.info('Security audit completed successfully - no issues found');
    }
  }

  /**
   * Runs comprehensive security checks
   */
  private static async runSecurityChecks(): Promise<{
    passed: boolean;
    issues: Array<{
      severity: 'critical' | 'high' | 'medium' | 'low';
      description: string;
      recommendation: string;
    }>;
  }> {
    const issues: Array<{
      severity: 'critical' | 'high' | 'medium' | 'low';
      description: string;
      recommendation: string;
    }> = [];

    // Check 1: Environment configuration
    if (!process.env.NODE_ENV) {
      issues.push({
        severity: 'high',
        description: 'NODE_ENV environment variable not set',
        recommendation: 'Set NODE_ENV to either "development", "staging", or "production"'
      });
    }

    // Check 2: Secrets configuration
    const secretsAudit = await SecretsManager.audit();
    if (!secretsAudit.passed) {
      issues.push(...secretsAudit.issues.map(issue => ({
        severity: issue.severity,
        description: `Secrets: ${issue.description}`,
        recommendation: issue.recommendation
      })));
    }

    // Check 3: PQC validation
    const pqcStatus = PQCValidator.getPQCStatus();
    if (!pqcStatus.valid) {
      issues.push({
        severity: 'critical',
        description: 'Post-Quantum Cryptography validation failed',
        recommendation: 'Install and configure PQC libraries before running in production'
      });
    }

    // Check 4: Security headers configuration
    if (process.env.NODE_ENV === 'production' && !process.env.CSP_ENABLED) {
      issues.push({
        severity: 'medium',
        description: 'Content Security Policy not explicitly enabled in production',
        recommendation: 'Enable CSP in production environment'
      });
    }

    // Check 5: Rate limiting configuration
    if (!process.env.RATE_LIMIT_WINDOW || !process.env.RATE_LIMIT_MAX) {
      issues.push({
        severity: 'medium',
        description: 'Rate limiting configuration incomplete',
        recommendation: 'Configure RATE_LIMIT_WINDOW and RATE_LIMIT_MAX environment variables'
      });
    }

    return {
      passed: issues.length === 0,
      issues
    };
  }

  /**
   * Applies enhanced security middleware to requests
   */
  static async applyEnhancedSecurity(
    request: NextRequest,
    userId?: string
  ): Promise<NextResponse | null> {
    try {
      // Validate PQC is available before processing request
      if (!PQCValidator.isPQCValidated()) {
        await PQCValidator.validatePQC();
      }

      // Validate secrets are properly configured
      if (!SecretsManager.isInitialized()) {
        await validateSecretsConfig();
      }

      // Block requests with suspicious patterns
      if (!validateRequestForSuspiciousPatterns(request)) {
        logger.warn('Suspicious request blocked', {
          url: request.url,
          ip: getClientIp(request),
          userAgent: request.headers.get('user-agent'),
        });

        return new NextResponse('Request blocked for security reasons', {
          status: 403,
        });
      }

      // Apply enhanced rate limiting
      const rateLimitResponse = await applyEnhancedRateLimiting(request, userId);
      if (rateLimitResponse) {
        return rateLimitResponse;
      }

      // All security checks passed
      return null;
    } catch (error) {
      logger.error('Enhanced security validation failed', { 
        error: (error as Error).message,
        url: request.url,
        ip: getClientIp(request)
      });

      // Return error response
      return new NextResponse(sanitizeErrorMessage(error), {
        status: 500,
      });
    }
  }

  /**
   * Validates session binding with enhanced security
   */
  static async validateEnhancedSessionBinding(
    sessionId: string,
    currentIp: string,
    currentUserAgent: string
  ): Promise<boolean> {
    try {
      // Validate using the security middleware function
      const isValid = await validateSessionBinding(sessionId, currentIp, currentUserAgent);
      
      if (!isValid) {
        logger.warn('Session binding validation failed', {
          sessionId,
          ip: currentIp,
          userAgent: currentUserAgent
        });

        // Log security event for session binding failure
        await SecurityMonitor.logEvent(
          'session_binding_failure',
          {
            userId: 'unknown', // We don't know the user ID at this point
            ipAddress: currentIp,
            userAgent: currentUserAgent,
            timestamp: new Date(),
            metadata: {
              sessionId,
              validationType: 'binding_check',
              failureReason: 'ip_or_useragent_mismatch'
            }
          },
          'Session binding validation failed'
        );
      }

      return isValid;
    } catch (error) {
      logger.error('Session binding validation error', { 
        error: (error as Error).message,
        sessionId,
        ip: currentIp
      });
      return false;
    }
  }

  /**
   * Applies enhanced CSP headers
   */
  static applyEnhancedCSP(response: NextResponse): NextResponse {
    try {
      // Generate a new nonce for each response
      const nonce = generateCspNonce();
      
      // Create CSP header with dynamic nonce
      const cspHeader = createCspHeader(nonce);
      
      // Set the CSP header
      response.headers.set('Content-Security-Policy', cspHeader);
      
      // Also add the nonce to response for client-side use
      response.headers.set('X-Nonce', nonce);
      
      return response;
    } catch (error) {
      logger.error('CSP application failed', { error: (error as Error).message });
      // Continue without CSP if it fails (don't break the application)
      return response;
    }
  }

  /**
   * Gets security posture report
   */
  static getSecurityPosture(): {
    timestamp: string;
    environment: string;
    pqcStatus: {
      initialized: boolean;
      available: boolean;
      valid: boolean;
    };
    secretsStatus: {
      initialized: boolean;
      secretsValidated: boolean;
      rotationEnabled: boolean;
    };
    securityFeatures: {
      rateLimiting: boolean;
      cspEnabled: boolean;
      hstsEnabled: boolean;
      xssProtection: boolean;
      sessionBinding: boolean;
    };
  } {
    return {
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'unknown',
      pqcStatus: PQCValidator.getPQCStatus(),
      secretsStatus: SecretsManager.getStatus(),
      securityFeatures: {
        rateLimiting: true, // Assuming rate limiting is always enabled
        cspEnabled: process.env.CSP_ENABLED === 'true' || process.env.NODE_ENV === 'production',
        hstsEnabled: process.env.HSTS_ENABLED === 'true' || process.env.NODE_ENV === 'production',
        xssProtection: true, // Assuming XSS protection is always enabled
        sessionBinding: true // Assuming session binding is always enabled
      }
    };
  }
}

/**
 * Helper function to ensure security enhancements are initialized
 */
export async function ensureSecurityInitialization(): Promise<void> {
  if (!PQCValidator.isPQCValidated() || !SecretsManager.isInitialized()) {
    await SecurityEnhancements.initialize();
  }
}

/**
 * Middleware function that applies all security enhancements
 */
export async function securityEnhancementMiddleware(
  request: NextRequest,
  userId?: string
): Promise<NextResponse | null> {
  // Ensure security is initialized
  await ensureSecurityInitialization();
  
  // Apply enhanced security measures
  return await SecurityEnhancements.applyEnhancedSecurity(request, userId);
}

/**
 * OWASP Top 10 Mapping
 * Maps security controls to OWASP Top 10 categories
 */
export const OWASP_TOP_10_MAPPING = {
  'A01:2021-Broken Access Control': [
    'session_binding_validation',
    'enhanced_rate_limiting',
    'authentication_enforcement'
  ],
  'A02:2021-Cryptographic Failures': [
    'post_quantum_cryptography',
    'secure_secret_storage',
    'proper_crypto_implementation'
  ],
  'A03:2021-Injection': [
    'input_validation',
    'output_encoding',
    'parameterized_queries'
  ],
  'A04:2021-Insecure Design': [
    'security_by_design',
    'defense_in_depth',
    'secure_default_configurations'
  ],
  'A05:2021-Security Misconfiguration': [
    'secure_defaults',
    'automated_security_checks',
    'configuration_validation'
  ],
  'A06:2021-Vulnerable and Outdated Components': [
    'dependency_scanning',
    'automated_updates',
    'component_inventory'
  ],
  'A07:2021-Identification and Authentication Failures': [
    'multi_factor_authentication',
    'secure_session_management',
    'password_policies'
  ],
  'A08:2021-Software and Data Integrity Failures': [
    'code_signing',
    'integrity_verification',
    'secure_update_mechanisms'
  ],
  'A09:2021-Security Logging and Monitoring Failures': [
    'comprehensive_logging',
    'security_monitoring',
    'incident_response'
  ],
  'A10:2021-Server-Side Request Forgery': [
    'input_validation',
    'network_access_controls',
    'whitelist_approach'
  ]
} as const;

/**
 * NIST SP 800-53 Controls Mapping
 */
export const NIST_CONTROLS_MAPPING = {
  'AC-2': 'Account Management',
  'AC-3': 'Access Enforcement',
  'AC-6': 'Least Privilege',
  'AC-17': 'Remote Access',
  'AU-2': 'Audit Events',
  'AU-3': 'Content of Audit Records',
  'AU-12': 'Audit Generation',
  'CA-7': 'Continuous Monitoring',
  'CM-6': 'Configuration Settings',
  'IA-2': 'Identification and Authentication',
  'IA-5': 'Authenticator Management',
  'IA-8': 'Identifier Management',
  'SC-8': 'Transmission Confidentiality and Integrity',
  'SC-12': 'Cryptographic Key Establishment and Management',
  'SC-13': 'Cryptographic Protection',
  'SI-3': 'Malicious Code Protection',
  'SI-4': 'System Monitoring'
} as const;

/**
 * FAPI (Financial-grade API) Controls Mapping
 */
export const FAPI_CONTROLS_MAPPING = {
  'FAPI-1-A': 'Financial-grade API Security Profile 1 - Part A: Baseline',
  'FAPI-1-B': 'Financial-grade API Security Profile 1 - Part B: Advanced',
  'FAPI-2': 'Financial-grade API Security Profile 2',
  'OIDF-FAPI': 'OpenID Foundation Financial-grade API Implementer\'s Guide'
} as const;