/**
 * Application Startup Security Module
 * Initializes security components before application starts serving requests
 */

import { logger } from './logger';
import { SecurityInitializer } from './security-init';
import { SecurityMonitor } from './security-monitoring';
import { initRedis, redisHealthCheck, performRedisRecovery, configureRedisForProduction } from './redis-config';

export class AppStartup {
  private static started = false;

  /**
   * Initialize application security before startup
   */
  static async initialize(): Promise<void> {
    if (this.started) {
      logger.info('Application startup security already initialized');
      return;
    }

    logger.info('Starting application security initialization', {
      node_env: process.env.NODE_ENV,
      timestamp: new Date().toISOString()
    });

    try {
      // Configure Redis for production use with persistence and failover
      configureRedisForProduction();

      // Initialize Redis with enhanced configuration
      initRedis();
      
      logger.info('Redis initialization completed');

      // Perform Redis health check
      const healthCheck = await redisHealthCheck();
      
      logger.info('Redis health check completed', {
        healthy: healthCheck.healthy,
        details: healthCheck.details
      });

      // Perform Redis recovery if needed
      if (!healthCheck.healthy) {
        logger.warn('Redis is not healthy, performing recovery...');
        const recoveryResult = await performRedisRecovery();
        
        logger.info('Redis recovery completed', {
          success: recoveryResult.success,
          recoveredItems: recoveryResult.recoveredItems,
          errors: recoveryResult.errors
        });
      }

      // Initialize security components
      await SecurityInitializer.initialize();
      
      // Log successful initialization
      await SecurityMonitor.logAuthSuccess('system', {
        ipAddress: '127.0.0.1',
        userAgent: 'App Startup Process',
        metadata: {
          stage: 'startup',
          node_env: process.env.NODE_ENV,
          timestamp: new Date().toISOString()
        }
      });

      logger.info('Application security initialization completed successfully');
      this.started = true;
    } catch (error) {
      logger.error('Application security initialization failed', {
        error: (error as Error).message,
        stack: (error as Error).stack,
        timestamp: new Date().toISOString()
      });

      // Log security event for the failure
      await SecurityMonitor.logEvent(
        'auth_failure',
        {
          userId: 'system',
          ipAddress: '127.0.0.1',
          userAgent: 'App Startup Process',
          timestamp: new Date(),
          metadata: {
            stage: 'startup',
            error: (error as Error).message,
            node_env: process.env.NODE_ENV
          }
        },
        `Application startup failed: ${(error as Error).message}`
      );

      // Rethrow the error to prevent application startup
      throw error;
    }
  }

  /**
   * Check if application has been properly started
   */
  static isStarted(): boolean {
    return this.started;
  }

  /**
   * Graceful shutdown procedure
   */
  static async shutdown(): Promise<void> {
    logger.info('Starting application shutdown', {
      timestamp: new Date().toISOString()
    });

    // Log shutdown event
    await SecurityMonitor.logAuthSuccess('system', {
      ipAddress: '127.0.0.1',
      userAgent: 'App Shutdown Process',
      metadata: {
        stage: 'shutdown',
        node_env: process.env.NODE_ENV,
        timestamp: new Date().toISOString()
      }
    });

    logger.info('Application shutdown completed');
  }
}

// Handle graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('Received SIGTERM, initiating graceful shutdown');
  try {
    await AppStartup.shutdown();
  } catch (error) {
    logger.error('Error during shutdown', { error: (error as Error).message });
  }
  process.exit(0);
});

process.on('SIGINT', async () => {
  logger.info('Received SIGINT, initiating graceful shutdown');
  try {
    await AppStartup.shutdown();
  } catch (error) {
    logger.error('Error during shutdown', { error: (error as Error).message });
  }
  process.exit(0);
});

// Handle uncaught exceptions
process.on('uncaughtException', async (error) => {
  logger.error('Uncaught exception', {
    error: error.message,
    stack: error.stack,
    timestamp: new Date().toISOString()
  });

  try {
    await SecurityMonitor.logEvent(
      'auth_failure',
      {
        userId: 'system',
        ipAddress: '127.0.0.1',
        userAgent: 'Uncaught Exception Handler',
        timestamp: new Date(),
        metadata: {
          stage: 'runtime',
          error: error.message,
          node_env: process.env.NODE_ENV
        }
      },
      `Uncaught exception: ${error.message}`
    );
  } catch (logError) {
    console.error('Failed to log security event for uncaught exception:', logError);
  }

  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', async (reason, promise) => {
  logger.error('Unhandled promise rejection', {
    reason: (reason as Error).message,
    stack: (reason as Error).stack,
    promise: String(promise),
    timestamp: new Date().toISOString()
  });

  try {
    await SecurityMonitor.logEvent(
      'auth_failure',
      {
        userId: 'system',
        ipAddress: '127.0.0.1',
        userAgent: 'Unhandled Rejection Handler',
        timestamp: new Date(),
        metadata: {
          stage: 'runtime',
          error: (reason as Error).message,
          promise: String(promise),
          node_env: process.env.NODE_ENV
        }
      },
      `Unhandled promise rejection: ${(reason as Error).message}`
    );
  } catch (logError) {
    console.error('Failed to log security event for unhandled rejection:', logError);
  }

  process.exit(1);
});