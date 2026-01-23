import fs from 'fs/promises';
import path from 'path';
import { createGzip } from 'zlib';
import { pipeline } from 'stream/promises';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { logger } from '../logger';

export class LogRotationManager {
  private logDir: string;
  private maxFileSize: number; // in bytes (default 100MB)
  private retentionDays: number; // default 30 days
  private s3Client?: S3Client;
  private s3Bucket?: string;
  private readonly currentLogFilePattern: RegExp;

  constructor(
    logDir: string,
    maxFileSize: number = 100 * 1024 * 1024, // 100MB
    retentionDays: number = 30
  ) {
    this.logDir = logDir;
    this.maxFileSize = maxFileSize;
    this.retentionDays = retentionDays;
    this.currentLogFilePattern = /^audit-(\d{4}-\d{2}-\d{2})\.log$/;

    // Setup S3 if configured
    if (process.env.S3_LOG_BUCKET) {
      this.s3Bucket = process.env.S3_LOG_BUCKET;
      this.s3Client = new S3Client({
        region: process.env.AWS_REGION || 'us-east-1',
        credentials: {
          accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
          secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!
        }
      });
    }

    // Ensure log directory exists
    this.ensureLogDirectory();
  }

  /**
   * Ensure the log directory exists
   */
  private ensureLogDirectory(): void {
    try {
      fs.mkdirSync(this.logDir, { recursive: true });
    } catch (error) {
      logger.error('Failed to create log directory', { error: (error as Error).message });
    }
  }

  /**
   * Check if rotation is needed and perform rotation if necessary
   */
  async rotateIfNeeded(): Promise<boolean> {
    const today = new Date().toISOString().split('T')[0];
    const currentLogPath = path.join(this.logDir, `audit-${today}.log`);

    try {
      const stats = await fs.stat(currentLogPath);
      if (stats.size >= this.maxFileSize) {
        await this.rotateLog(currentLogPath);
        return true;
      }
    } catch (error) {
      // File doesn't exist, which is fine
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        logger.error('Error checking log file size', { 
          error: (error as Error).message,
          filePath: currentLogPath 
        });
      }
    }

    return false;
  }

  /**
   * Rotate a log file when it reaches the size limit
   */
  private async rotateLog(logPath: string): Promise<void> {
    const fileName = path.basename(logPath);
    const dateMatch = fileName.match(this.currentLogFilePattern);

    if (!dateMatch) {
      throw new Error(`Invalid log file name format: ${fileName}`);
    }

    const date = dateMatch[1];
    const baseName = `audit-${date}`;

    // Compress the current log file
    const compressedPath = path.join(this.logDir, `${baseName}.gz`);
    await this.compressLogFile(logPath, compressedPath);

    // Upload to S3 if configured
    if (this.s3Client && this.s3Bucket) {
      await this.uploadToS3(compressedPath, `${baseName}.gz`);
    }

    // Create a new empty log file
    await fs.writeFile(logPath, '');

    logger.info('Log rotated successfully', {
      originalPath: logPath,
      compressedPath,
      s3Uploaded: !!(this.s3Client && this.s3Bucket)
    });

    // Clean up old log files
    await this.cleanupOldLogs();
  }

  /**
   * Compress a log file using gzip
   */
  private async compressLogFile(inputPath: string, outputPath: string): Promise<void> {
    const input = await fs.open(inputPath, 'r');
    const output = await fs.open(outputPath, 'w');

    try {
      await pipeline(
        input.createReadStream(),
        createGzip(),
        output.createWriteStream()
      );
    } finally {
      await input.close();
      await output.close();
    }
  }

  /**
   * Upload compressed log to S3
   */
  private async uploadToS3(filePath: string, s3Key: string): Promise<void> {
    if (!this.s3Client || !this.s3Bucket) {
      return;
    }

    try {
      const fileContent = await fs.readFile(filePath);

      const command = new PutObjectCommand({
        Bucket: this.s3Bucket,
        Key: `audit-logs/archived/${s3Key}`,
        Body: fileContent,
        ServerSideEncryption: 'AES256',
        StorageClass: 'GLACIER_IR', // Use infrequent access for cost savings
        Metadata: {
          'uploaded-at': new Date().toISOString(),
          'original-size': (await fs.stat(filePath)).size.toString(),
          'compression': 'gzip'
        }
      });

      await this.s3Client.send(command);

      logger.info('Log uploaded to S3', {
        filePath,
        s3Key,
        bucket: this.s3Bucket
      });
    } catch (error) {
      logger.error('Failed to upload log to S3', {
        error: (error as Error).message,
        filePath,
        s3Key
      });
      throw error;
    }
  }

  /**
   * Clean up old log files based on retention policy
   */
  async cleanupOldLogs(): Promise<void> {
    try {
      const files = await fs.readdir(this.logDir);
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - this.retentionDays);

      for (const file of files) {
        const filePath = path.join(this.logDir, file);
        const stat = await fs.stat(filePath);

        // Only delete log and compressed log files older than retention period
        if (
          (file.endsWith('.log') || file.endsWith('.gz')) &&
          stat.mtime < cutoffDate
        ) {
          await fs.unlink(filePath);
          logger.info('Old log file deleted', {
            filePath,
            mtime: stat.mtime
          });
        }
      }
    } catch (error) {
      logger.error('Failed to clean up old logs', { 
        error: (error as Error).message 
      });
    }
  }

  /**
   * Manually rotate logs (can be called by cron job or scheduled task)
   */
  async manualRotate(): Promise<void> {
    try {
      const today = new Date().toISOString().split('T')[0];
      const currentLogPath = path.join(this.logDir, `audit-${today}.log`);

      // Check if file exists and rotate regardless of size
      try {
        await fs.access(currentLogPath);
        await this.rotateLog(currentLogPath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
          logger.error('Error accessing log file for rotation', { 
            error: (error as Error).message,
            filePath: currentLogPath 
          });
        }
      }

      logger.info('Manual log rotation completed');
    } catch (error) {
      logger.error('Manual log rotation failed', { 
        error: (error as Error).message 
      });
    }
  }

  /**
   * Archive logs to long-term storage (like AWS Glacier)
   */
  async archiveLogs(olderThanDays: number = 7): Promise<void> {
    try {
      const files = await fs.readdir(this.logDir);
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - olderThanDays);

      for (const file of files) {
        if (file.endsWith('.gz')) {
          const filePath = path.join(this.logDir, file);
          const stat = await fs.stat(filePath);

          if (stat.mtime < cutoffDate) {
            // For this example, we'll just log the archiving action
            // In a real implementation, this would move files to cold storage
            logger.info('Log file ready for archival', {
              filePath,
              mtime: stat.mtime,
              ageInDays: Math.floor((Date.now() - stat.mtime.getTime()) / (1000 * 60 * 60 * 24))
            });
          }
        }
      }
    } catch (error) {
      logger.error('Failed to archive logs', { 
        error: (error as Error).message 
      });
    }
  }

  /**
   * Get log retention policy information
   */
  getRetentionPolicyInfo(): {
    maxFileSize: number;
    retentionDays: number;
    s3Enabled: boolean;
    logDir: string;
  } {
    return {
      maxFileSize: this.maxFileSize,
      retentionDays: this.retentionDays,
      s3Enabled: !!(this.s3Client && this.s3Bucket),
      logDir: this.logDir
    };
  }

  /**
   * Get statistics about log files
   */
  async getLogStats(): Promise<{
    totalFiles: number;
    totalSize: number;
    oldestFileDate?: string;
    newestFileDate?: string;
  }> {
    try {
      const files = await fs.readdir(this.logDir);
      let totalSize = 0;
      let oldestDate: Date | undefined;
      let newestDate: Date | undefined;

      for (const file of files) {
        if (file.endsWith('.log') || file.endsWith('.gz')) {
          const filePath = path.join(this.logDir, file);
          const stat = await fs.stat(filePath);
          totalSize += stat.size;

          // Extract date from filename
          const dateMatch = file.match(/audit-(\d{4}-\d{2}-\d{2})/);
          if (dateMatch) {
            const fileDate = new Date(dateMatch[1]);
            if (!oldestDate || fileDate < oldestDate) {
              oldestDate = fileDate;
            }
            if (!newestDate || fileDate > newestDate) {
              newestDate = fileDate;
            }
          }
        }
      }

      return {
        totalFiles: files.filter(f => f.endsWith('.log') || f.endsWith('.gz')).length,
        totalSize,
        oldestFileDate: oldestDate?.toISOString().split('T')[0],
        newestFileDate: newestDate?.toISOString().split('T')[0]
      };
    } catch (error) {
      logger.error('Failed to get log stats', { 
        error: (error as Error).message 
      });
      return {
        totalFiles: 0,
        totalSize: 0
      };
    }
  }
}