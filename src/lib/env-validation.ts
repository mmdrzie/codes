/**
 * Environment Validation Utility
 * Validates production security requirements and environment configuration
 */

import { logger } from './logger';

interface EnvValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  securityIssues: string[];
}

export class EnvValidator {
  /**
   * Validate all environment variables and security configurations
   */
  static validateEnvironment(): EnvValidationResult {
    const result: EnvValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
      securityIssues: []
    };

    // Validate required environment variables
    this.validateRequiredVars(result);
    
    // Validate security-sensitive configurations
    this.validateSecurityConfigs(result);
    
    // Validate production-specific settings
    this.validateProductionSettings(result);

    // Log validation results
    this.logValidationResults(result);

    return result;
  }

  /**
   * Check for required environment variables
   */
  private static validateRequiredVars(result: EnvValidationResult): void {
    const requiredVars = [
      'NODE_ENV',
      'REDIS_URL',
      'JWT_SECRET',
      'NEXTAUTH_SECRET',
      'SIEM_ENABLED',
      'SYSLOG_SERVER'
    ];

    for (const varName of requiredVars) {
      const value = process.env[varName];
      if (!value || value.trim() === '') {
        result.errors.push(`Missing required environment variable: ${varName}`);
        result.isValid = false;
      }
    }

    // Special validation for NODE_ENV
    if (process.env.NODE_ENV !== 'production') {
      result.warnings.push('NODE_ENV is not set to "production"');
    }

    // Validate JWT secret strength
    if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32) {
      result.securityIssues.push('JWT_SECRET should be at least 32 characters long');
      result.isValid = false;
    }

    // Validate NEXTAUTH_SECRET strength
    if (process.env.NEXTAUTH_SECRET && process.env.NEXTAUTH_SECRET.length < 32) {
      result.securityIssues.push('NEXTAUTH_SECRET should be at least 32 characters long');
      result.isValid = false;
    }
  }

  /**
   * Validate security-sensitive configurations
   */
  private static validateSecurityConfigs(result: EnvValidationResult): void {
    // Check for development-specific configurations in production
    if (process.env.NODE_ENV === 'production') {
      if (process.env.NEXTAUTH_DEBUG === 'true') {
        result.securityIssues.push('NEXTAUTH_DEBUG should be disabled in production');
        result.isValid = false;
      }

      if (process.env.DEBUG === 'true' || (process.env.DEBUG && process.env.DEBUG.includes('*'))) {
        result.securityIssues.push('DEBUG mode should be disabled in production');
        result.isValid = false;
      }

      if (process.env.REDIS_URL && process.env.REDIS_URL.startsWith('redis://')) {
        result.securityIssues.push('Redis connection should use TLS (rediss://) in production');
        result.isValid = false;
      }

      if (!process.env.REDIS_URL || process.env.REDIS_URL.includes('localhost') || process.env.REDIS_URL.includes('127.0.0.1')) {
        result.securityIssues.push('Redis connection should not use localhost in production');
        result.isValid = false;
      }
    }

    // Validate SIEM configuration
    if (process.env.SIEM_ENABLED === 'true') {
      if (!process.env.SYSLOG_SERVER && !process.env.WEBHOOK_SIEM_URL) {
        result.errors.push('SIEM is enabled but no syslog server or webhook URL configured');
        result.isValid = false;
      }
    }

    // Validate CORS settings
    if (process.env.NODE_ENV === 'production') {
      if (process.env.ALLOWED_ORIGINS === '*') {
        result.securityIssues.push('Wildcard CORS origins (*) not allowed in production');
        result.isValid = false;
      }
    }
  }

  /**
   * Validate production-specific settings
   */
  private static validateProductionSettings(result: EnvValidationResult): void {
    if (process.env.NODE_ENV === 'production') {
      // Validate rate limiting is enabled
      if (!process.env.RATE_LIMIT_ENABLED || process.env.RATE_LIMIT_ENABLED !== 'true') {
        result.warnings.push('Rate limiting should be enabled in production');
      }

      // Validate session timeout settings
      if (!process.env.SESSION_MAX_AGE || parseInt(process.env.SESSION_MAX_AGE) > 86400) { // More than 24 hours
        result.warnings.push('Session timeout should be reasonable in production (<24 hours)');
      }

      // Validate logging level
      if (!process.env.LOG_LEVEL || process.env.LOG_LEVEL.toLowerCase() === 'debug') {
        result.warnings.push('Log level should be INFO or higher in production');
      }

      // Validate crypto settings
      if (!process.env.PQ_CRYPTO_ENABLED || process.env.PQ_CRYPTO_ENABLED !== 'true') {
        result.securityIssues.push('Post-quantum cryptography should be enabled in production');
        result.isValid = false;
      }
    }
  }

  /**
   * Log validation results
   */
  private static logValidationResults(result: EnvValidationResult): void {
    if (result.errors.length > 0) {
      logger.error('Environment validation errors:', { errors: result.errors });
    }

    if (result.securityIssues.length > 0) {
      logger.error('Security configuration issues:', { issues: result.securityIssues });
    }

    if (result.warnings.length > 0) {
      logger.warn('Environment validation warnings:', { warnings: result.warnings });
    }

    if (result.isValid) {
      logger.info('Environment validation passed');
    } else {
      logger.error('Environment validation failed', {
        errorCount: result.errors.length,
        securityIssueCount: result.securityIssues.length
      });
    }
  }

  /**
   * Validate runtime environment conditions
   */
  static validateRuntimeConditions(): boolean {
    // Check if we're running in a secure environment
    const isSecureEnvironment = this.checkSecureEnvironment();
    
    if (!isSecureEnvironment) {
      logger.error('Running in insecure environment');
      return false;
    }

    // Check system resource availability
    const hasResources = this.checkSystemResources();
    if (!hasResources) {
      logger.error('Insufficient system resources');
      return false;
    }

    logger.info('Runtime conditions validated successfully');
    return true;
  }

  /**
   * Check if running in a secure environment
   */
  private static checkSecureEnvironment(): boolean {
    // Check for security-sensitive directories/files
    try {
      // Don't run if in a potentially insecure environment
      // (this is a basic check - production systems should have more sophisticated validation)
      
      // Check if running with elevated privileges (basic check)
      if (typeof process.getuid === 'function') {
        const uid = process.getuid();
        if (uid === 0) { // Running as root
          logger.warn('Running as root user - this is not recommended for production');
        }
      }

      return true;
    } catch (error) {
      logger.error('Error checking secure environment:', { error: (error as Error).message });
      return false;
    }
  }

  /**
   * Check system resource availability
   */
  private static checkSystemResources(): boolean {
    try {
      const memoryUsage = process.memoryUsage();
      const heapUsedPercent = (memoryUsage.heapUsed / memoryUsage.heapTotal) * 100;
      
      if (heapUsedPercent > 90) {
        logger.warn('High memory usage detected', { heapUsedPercent });
      }

      // Check for minimum available memory
      const freeMemory = require('os').freemem();
      const totalMemory = require('os').totalmem();
      const freeMemoryPercent = (freeMemory / totalMemory) * 100;

      if (freeMemoryPercent < 10) { // Less than 10% free memory
        logger.warn('Low system memory available', { freeMemoryPercent });
      }

      return true;
    } catch (error) {
      logger.error('Error checking system resources:', { error: (error as Error).message });
      return false;
    }
  }

  /**
   * Validate that secrets are properly configured
   */
  static validateSecretsConfiguration(): boolean {
    let isValid = true;
    const issues: string[] = [];

    // Check for common weak secrets
    const weakPatterns = [
      'secret',
      'password',
      'admin',
      '123456',
      'qwerty',
      'changeme',
      'letmein'
    ];

    const secretVars = [
      'JWT_SECRET',
      'NEXTAUTH_SECRET',
      'DATABASE_PASSWORD',
      'API_KEY',
      'PRIVATE_KEY'
    ];

    for (const secretVar of secretVars) {
      const value = process.env[secretVar];
      if (value) {
        // Check for weak patterns
        for (const pattern of weakPatterns) {
          if (value.toLowerCase().includes(pattern.toLowerCase())) {
            issues.push(`Weak secret detected in ${secretVar}: contains '${pattern}'`);
            isValid = false;
          }
        }

        // Check for common default values
        if (value === `${secretVar}_PLACEHOLDER` || value === 'YOUR_' + secretVar) {
          issues.push(`Default placeholder value detected in ${secretVar}`);
          isValid = false;
        }

        // Check for minimum length
        if (value.length < 16 && secretVar.includes('SECRET')) {
          issues.push(`Secret ${secretVar} is too short (minimum 16 characters recommended)`);
          isValid = false;
        }
      }
    }

    if (issues.length > 0) {
      logger.error('Secret configuration issues found:', { issues });
    } else {
      logger.info('Secrets configuration validated');
    }

    return isValid;
  }
}

/**
 * Initialize environment validation on module load
 */
export function initializeEnvironmentValidation(): void {
  logger.info('Initializing environment validation...');
  
  const envResult = EnvValidator.validateEnvironment();
  
  if (!envResult.isValid) {
    logger.error('Environment validation failed - application may not be secure for production use');
    
    // In production, we might want to exit if critical security issues are found
    if (process.env.NODE_ENV === 'production') {
      for (const issue of envResult.securityIssues) {
        if (issue.includes('Post-quantum cryptography should be enabled')) {
          logger.critical('CRITICAL: Post-quantum cryptography not enabled in production - exiting');
          process.exit(1);
        }
        
        if (issue.includes('JWT_SECRET should be at least 32 characters')) {
          logger.critical('CRITICAL: Weak JWT secret detected in production - exiting');
          process.exit(1);
        }
      }
    }
  }

  const secretsValid = EnvValidator.validateSecretsConfiguration();
  if (!secretsValid) {
    logger.error('Secrets configuration validation failed');
  }

  const runtimeValid = EnvValidator.validateRuntimeConditions();
  if (!runtimeValid) {
    logger.error('Runtime conditions validation failed');
  }

  logger.info('Environment validation initialization complete');
}