import cron from 'node-cron';
import fs from 'fs/promises';
import crypto from 'crypto';
import { logger } from '@/lib/logger';
import { SecurityMonitor } from '@/lib/security-monitoring';
import { SecurityEvent } from '@/lib/security-monitoring';

export class KeyRotationService {
  private static readonly KEY_ROTATION_INTERVAL_DAYS = 30;
  private static readonly ALERT_THRESHOLD_DAYS = 7; // Alert 7 days before expiration
  private static readonly JWT_SECRET_KEY = 'JWT_SECRET';
  private static readonly REFRESH_TOKEN_SECRET_KEY = 'REFRESH_TOKEN_SECRET';
  
  private static job: cron.ScheduledTask | null = null;
  
  /**
   * Initialize the key rotation service
   */
  static async initialize(): Promise<void> {
    try {
      // Schedule key rotation job to run every day at midnight
      this.job = cron.schedule('0 0 * * *', async () => {
        await this.checkAndRotateKeys();
      });
      
      logger.info('Key rotation service initialized successfully');
      
      // Perform initial check
      await this.checkAndRotateKeys();
    } catch (error) {
      logger.error('Failed to initialize key rotation service', { 
        error: (error as Error).message 
      });
      
      await SecurityMonitor.logEvent(
        SecurityEvent.PQ_CRYPTO_ERROR,
        {
          timestamp: new Date(),
          metadata: {
            operation: 'key_rotation_service_init',
            error: (error as Error).message
          }
        },
        'Failed to initialize key rotation service'
      );
    }
  }
  
  /**
   * Check if keys need rotation and rotate if necessary
   */
  static async checkAndRotateKeys(): Promise<void> {
    try {
      const now = new Date();
      const jwtSecret = process.env.JWT_SECRET;
      
      // If JWT secret is not set, generate one
      if (!jwtSecret || jwtSecret.length < 32) {
        await this.rotateJWTSecret();
        return;
      }
      
      // Calculate when the key was last rotated (we'll store this in a file)
      const keyInfoPath = process.env.KEY_INFO_PATH || '/tmp/key_info.json';
      
      let keyInfo: { 
        createdAt: Date; 
        lastRotation: Date; 
        jwtSecretHash: string; 
      } | null = null;
      
      try {
        const keyInfoContent = await fs.readFile(keyInfoPath, 'utf8');
        const parsed = JSON.parse(keyInfoContent);
        keyInfo = {
          ...parsed,
          createdAt: new Date(parsed.createdAt),
          lastRotation: new Date(parsed.lastRotation)
        };
      } catch (error) {
        // If key info file doesn't exist, create it with current date
        logger.info('Key info file not found, creating new one');
        keyInfo = {
          createdAt: new Date(),
          lastRotation: new Date(),
          jwtSecretHash: crypto.createHash('sha256').update(jwtSecret).digest('hex')
        };
      }
      
      // Calculate days since last rotation
      const daysSinceRotation = Math.floor(
        (now.getTime() - keyInfo.lastRotation.getTime()) / (1000 * 60 * 60 * 24)
      );
      
      // Check if we're approaching rotation deadline
      const daysUntilRotation = this.KEY_ROTATION_INTERVAL_DAYS - daysSinceRotation;
      
      if (daysUntilRotation <= this.ALERT_THRESHOLD_DAYS && daysUntilRotation > 0) {
        // Send alert about upcoming rotation
        await this.sendRotationAlert(daysUntilRotation);
      }
      
      // Rotate keys if needed
      if (daysSinceRotation >= this.KEY_ROTATION_INTERVAL_DAYS) {
        logger.info(`Rotating keys: ${daysSinceRotation} days since last rotation`);
        await this.performKeyRotation(keyInfoPath);
      } else {
        logger.debug(`Keys rotation not needed yet: ${daysSinceRotation}/${this.KEY_ROTATION_INTERVAL_DAYS} days`);
      }
    } catch (error) {
      logger.error('Error in key rotation check', { 
        error: (error as Error).message 
      });
      
      await SecurityMonitor.logEvent(
        SecurityEvent.PQ_CRYPTO_ERROR,
        {
          timestamp: new Date(),
          metadata: {
            operation: 'key_rotation_check',
            error: (error as Error).message
          }
        },
        'Error in key rotation check'
      );
    }
  }
  
  /**
   * Perform the actual key rotation
   */
  private static async performKeyRotation(keyInfoPath: string): Promise<void> {
    try {
      logger.info('Starting key rotation process');
      
      // Rotate JWT secret
      await this.rotateJWTSecret();
      
      // Rotate refresh token secret if it exists
      if (process.env.REFRESH_TOKEN_SECRET) {
        await this.rotateRefreshTokenSecret();
      }
      
      // Update key info file
      const newKeyInfo = {
        createdAt: new Date(),
        lastRotation: new Date(),
        jwtSecretHash: crypto.createHash('sha256').update(process.env.JWT_SECRET!).digest('hex')
      };
      
      await fs.writeFile(keyInfoPath, JSON.stringify(newKeyInfo, null, 2));
      
      logger.info('Key rotation completed successfully');
      
      await SecurityMonitor.logEvent(
        SecurityEvent.AUTH_SUCCESS,
        {
          timestamp: new Date(),
          metadata: {
            operation: 'key_rotation',
            rotationIntervalDays: this.KEY_ROTATION_INTERVAL_DAYS
          }
        },
        'Key rotation completed successfully'
      );
      
      // Optionally signal application restart if needed
      this.signalApplicationRestart();
    } catch (error) {
      logger.error('Error during key rotation', { 
        error: (error as Error).message 
      });
      
      await SecurityMonitor.logEvent(
        SecurityEvent.PQ_CRYPTO_ERROR,
        {
          timestamp: new Date(),
          metadata: {
            operation: 'key_rotation',
            error: (error as Error).message
          }
        },
        'Error during key rotation'
      );
      
      throw error;
    }
  }
  
  /**
   * Rotate JWT secret
   */
  private static async rotateJWTSecret(): Promise<void> {
    const newJwtSecret = crypto.randomBytes(64).toString('hex');
    
    // Update environment variable (this won't persist across processes, 
    // but for this demo we'll update the current process)
    process.env.JWT_SECRET = newJwtSecret;
    
    // Update .env file if it exists
    await this.updateEnvFile('JWT_SECRET', newJwtSecret);
    
    logger.info('JWT secret rotated successfully');
  }
  
  /**
   * Rotate refresh token secret
   */
  private static async rotateRefreshTokenSecret(): Promise<void> {
    const newRefreshSecret = crypto.randomBytes(64).toString('hex');
    
    // Update environment variable
    process.env.REFRESH_TOKEN_SECRET = newRefreshSecret;
    
    // Update .env file if it exists
    await this.updateEnvFile('REFRESH_TOKEN_SECRET', newRefreshSecret);
    
    logger.info('Refresh token secret rotated successfully');
  }
  
  /**
   * Update .env file with new value
   */
  private static async updateEnvFile(key: string, value: string): Promise<void> {
    try {
      const envPath = '.env';
      
      let envContent = '';
      try {
        envContent = await fs.readFile(envPath, 'utf8');
      } catch (error) {
        // File doesn't exist, create a new one
        await fs.writeFile(envPath, `${key}=${value}\n`);
        return;
      }
      
      // Check if key exists in file
      const lines = envContent.split('\n');
      const keyExists = lines.some(line => line.trim().startsWith(`${key}=`));
      
      if (keyExists) {
        // Replace existing key
        const updatedLines = lines.map(line => {
          if (line.trim().startsWith(`${key}=`)) {
            return `${key}=${value}`;
          }
          return line;
        });
        
        await fs.writeFile(envPath, updatedLines.join('\n'));
      } else {
        // Add new key
        await fs.appendFile(envPath, `\n${key}=${value}\n`);
      }
    } catch (error) {
      logger.error('Failed to update .env file', { 
        error: (error as Error).message,
        key
      });
    }
  }
  
  /**
   * Send alert about upcoming key rotation
   */
  private static async sendRotationAlert(daysUntilRotation: number): Promise<void> {
    logger.warn(`Key rotation alert: ${daysUntilRotation} days until automatic key rotation`);
    
    await SecurityMonitor.logEvent(
      SecurityEvent.AUTH_SUCCESS,
      {
        timestamp: new Date(),
        metadata: {
          operation: 'key_rotation_alert',
          daysUntilRotation,
          alertThreshold: this.ALERT_THRESHOLD_DAYS
        }
      },
      `Key rotation scheduled in ${daysUntilRotation} days`
    );
    
    // In a real implementation, this would send alerts to a monitoring system
    // For example, send to Slack, email, or SIEM
    console.log(`ALERT: Keys will be rotated in ${daysUntilRotation} days`);
  }
  
  /**
   * Signal application restart if needed after key rotation
   */
  private static signalApplicationRestart(): void {
    // In a real implementation, this would signal the application to reload secrets
    // For example, send a SIGUSR2 signal to trigger a graceful restart
    logger.info('Key rotation completed - consider restarting application to reload secrets');
  }
  
  /**
   * Stop the key rotation service
   */
  static stop(): void {
    if (this.job) {
      this.job.stop();
      logger.info('Key rotation service stopped');
    }
  }
}