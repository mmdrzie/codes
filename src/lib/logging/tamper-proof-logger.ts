import { createHash, randomBytes } from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { logger } from '../logger';
import { PIIMasker } from './pii-masker';
import { LogRotationManager } from './log-rotation';

export interface LogEntry {
  id: string;
  timestamp: number;
  level: 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'SECURITY' | 'AUDIT';
  message: string;
  data?: any;
  userId?: string;
  ipAddress?: string;
  userAgent?: string;
  previousHash?: string;
  currentHash: string;
  signature?: string;
}

export interface LogVerificationResult {
  isValid: boolean;
  tamperedEntries?: number[];
  error?: string;
}

export class TamperProofLogger {
  private logFilePath: string;
  private s3Client?: S3Client;
  private bucketName?: string;
  private piiMasker: PIIMasker;
  private rotationManager: LogRotationManager;
  private currentPreviousHash: string | null = null;
  private logDir: string;

  constructor(logDir: string = './logs', bucketName?: string) {
    this.logDir = logDir;
    this.logFilePath = path.join(logDir, `audit-${new Date().toISOString().split('T')[0]}.log`);
    this.piiMasker = new PIIMasker();
    this.rotationManager = new LogRotationManager(logDir);
    
    // Setup S3 if configured
    if (bucketName) {
      this.bucketName = bucketName;
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
   * Create a log entry with cryptographic hash chain
   */
  private async createLogEntry(
    level: 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'SECURITY' | 'AUDIT',
    message: string,
    data?: any,
    userId?: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<LogEntry> {
    const logEntry: LogEntry = {
      id: this.generateId(),
      timestamp: Date.now(),
      level,
      message,
      data: this.piiMasker.mask(data),
      userId,
      ipAddress,
      userAgent,
      previousHash: this.currentPreviousHash || undefined,
      currentHash: '' // Will be calculated after populating other fields
    };

    // Calculate the hash of the log entry (excluding the currentHash field)
    const entryWithoutHash = { ...logEntry };
    delete entryWithoutHash.currentHash;
    
    const serialized = JSON.stringify(entryWithoutHash, Object.keys(entryWithoutHash).sort());
    logEntry.currentHash = createHash('sha256').update(serialized).digest('hex');
    
    // Update the previous hash for the next entry
    this.currentPreviousHash = logEntry.currentHash;

    return logEntry;
  }

  /**
   * Generate a unique ID for log entries
   */
  private generateId(): string {
    return `log-${Date.now()}-${randomBytes(8).toString('hex')}`;
  }

  /**
   * Write a log entry to the file with append-only security
   */
  private async writeLogEntry(logEntry: LogEntry): Promise<void> {
    // Ensure log rotation if needed
    await this.rotationManager.rotateIfNeeded();
    
    // Update log file path after rotation check
    this.logFilePath = path.join(this.logDir, `audit-${new Date().toISOString().split('T')[0]}.log`);
    
    const logLine = JSON.stringify(logEntry) + '\n';
    
    try {
      // Write with append-only flag to prevent overwrites
      await fs.appendFile(this.logFilePath, logLine, { 
        encoding: 'utf8',
        flag: 'a' // append only
      });
      
      // Set strict file permissions
      await fs.chmod(this.logFilePath, 0o600); // Read/write for owner only
      
      logger.info('Log entry written successfully', {
        logId: logEntry.id,
        filePath: this.logFilePath
      });
    } catch (error) {
      logger.error('Failed to write log entry', { 
        error: (error as Error).message,
        logId: logEntry.id 
      });
      throw error;
    }
  }

  /**
   * Upload log to S3 for additional security
   */
  private async uploadToS3(logEntry: LogEntry): Promise<void> {
    if (!this.s3Client || !this.bucketName) {
      return;
    }

    try {
      const command = new PutObjectCommand({
        Bucket: this.bucketName,
        Key: `audit-logs/${new Date().toISOString().split('T')[0]}/${logEntry.id}.json`,
        Body: JSON.stringify(logEntry),
        ServerSideEncryption: 'AES256', // Enable server-side encryption
        Metadata: {
          'timestamp': logEntry.timestamp.toString(),
          'level': logEntry.level,
          'userId': logEntry.userId || 'anonymous'
        }
      });

      await this.s3Client.send(command);
      
      logger.info('Log uploaded to S3', {
        logId: logEntry.id,
        bucket: this.bucketName
      });
    } catch (error) {
      logger.error('Failed to upload log to S3', { 
        error: (error as Error).message,
        logId: logEntry.id 
      });
    }
  }

  /**
   * Log an audit entry
   */
  async audit(
    message: string,
    data?: any,
    userId?: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<void> {
    const logEntry = await this.createLogEntry('AUDIT', message, data, userId, ipAddress, userAgent);
    await this.writeLogEntry(logEntry);
    await this.uploadToS3(logEntry);
  }

  /**
   * Log a security event
   */
  async security(
    message: string,
    data?: any,
    userId?: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<void> {
    const logEntry = await this.createLogEntry('SECURITY', message, data, userId, ipAddress, userAgent);
    await this.writeLogEntry(logEntry);
    await this.uploadToS3(logEntry);
  }

  /**
   * Log a general entry
   */
  async log(
    level: 'DEBUG' | 'INFO' | 'WARN' | 'ERROR',
    message: string,
    data?: any,
    userId?: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<void> {
    const logEntry = await this.createLogEntry(level, message, data, userId, ipAddress, userAgent);
    await this.writeLogEntry(logEntry);
    await this.uploadToS3(logEntry);
  }

  /**
   * Verify the integrity of the log chain
   */
  async verifyIntegrity(): Promise<LogVerificationResult> {
    try {
      // Read the current log file
      let logContent: string;
      try {
        logContent = await fs.readFile(this.logFilePath, 'utf8');
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
          // File doesn't exist, which is valid
          return { isValid: true };
        }
        throw error;
      }

      if (!logContent.trim()) {
        return { isValid: true };
      }

      const lines = logContent.trim().split('\n');
      let expectedPreviousHash: string | null = null;
      const tamperedEntries: number[] = [];

      for (let i = 0; i < lines.length; i++) {
        try {
          const logEntry: LogEntry = JSON.parse(lines[i]);
          
          // Verify the hash of this entry
          const entryWithoutCurrentHash = { ...logEntry };
          delete entryWithoutCurrentHash.currentHash;
          
          const serialized = JSON.stringify(entryWithoutCurrentHash, Object.keys(entryWithoutCurrentHash).sort());
          const calculatedHash = createHash('sha256').update(serialized).digest('hex');
          
          if (calculatedHash !== logEntry.currentHash) {
            tamperedEntries.push(i);
            continue;
          }
          
          // Verify the hash chain (previous entry's hash matches current entry's previousHash)
          if (expectedPreviousHash !== logEntry.previousHash) {
            tamperedEntries.push(i);
            continue;
          }
          
          // Update expectedPreviousHash for next iteration
          expectedPreviousHash = logEntry.currentHash;
        } catch (parseError) {
          logger.error('Failed to parse log entry during integrity check', {
            lineNumber: i,
            error: (parseError as Error).message
          });
          tamperedEntries.push(i);
        }
      }

      return {
        isValid: tamperedEntries.length === 0,
        tamperedEntries: tamperedEntries.length > 0 ? tamperedEntries : undefined
      };
    } catch (error) {
      logger.error('Failed to verify log integrity', { 
        error: (error as Error).message 
      });
      return {
        isValid: false,
        error: (error as Error).message
      };
    }
  }

  /**
   * Verify integrity of a specific log file
   */
  async verifyLogFile(filePath: string): Promise<LogVerificationResult> {
    try {
      const logContent = await fs.readFile(filePath, 'utf8');
      
      if (!logContent.trim()) {
        return { isValid: true };
      }

      const lines = logContent.trim().split('\n');
      let expectedPreviousHash: string | null = null;
      const tamperedEntries: number[] = [];

      for (let i = 0; i < lines.length; i++) {
        try {
          const logEntry: LogEntry = JSON.parse(lines[i]);
          
          // Verify the hash of this entry
          const entryWithoutCurrentHash = { ...logEntry };
          delete entryWithoutCurrentHash.currentHash;
          
          const serialized = JSON.stringify(entryWithoutCurrentHash, Object.keys(entryWithoutCurrentHash).sort());
          const calculatedHash = createHash('sha256').update(serialized).digest('hex');
          
          if (calculatedHash !== logEntry.currentHash) {
            tamperedEntries.push(i);
            continue;
          }
          
          // Verify the hash chain (previous entry's hash matches current entry's previousHash)
          if (expectedPreviousHash !== logEntry.previousHash) {
            tamperedEntries.push(i);
            continue;
          }
          
          // Update expectedPreviousHash for next iteration
          expectedPreviousHash = logEntry.currentHash;
        } catch (parseError) {
          logger.error('Failed to parse log entry during integrity check', {
            lineNumber: i,
            filePath,
            error: (parseError as Error).message
          });
          tamperedEntries.push(i);
        }
      }

      return {
        isValid: tamperedEntries.length === 0,
        tamperedEntries: tamperedEntries.length > 0 ? tamperedEntries : undefined
      };
    } catch (error) {
      logger.error('Failed to verify log file integrity', { 
        filePath,
        error: (error as Error).message 
      });
      return {
        isValid: false,
        error: (error as Error).message
      };
    }
  }

  /**
   * Generate a Merkle tree for efficient verification
   */
  async generateMerkleTree(): Promise<{ root: string; tree: string[] }> {
    try {
      const logContent = await fs.readFile(this.logFilePath, 'utf8');
      
      if (!logContent.trim()) {
        return { root: '', tree: [] };
      }

      const lines = logContent.trim().split('\n');
      const hashes = [];

      for (const line of lines) {
        try {
          const logEntry: LogEntry = JSON.parse(line);
          hashes.push(logEntry.currentHash);
        } catch (parseError) {
          logger.error('Failed to parse log entry for Merkle tree', {
            error: (parseError as Error).message
          });
        }
      }

      // Build the Merkle tree
      let currentLevel = hashes;
      
      while (currentLevel.length > 1) {
        const nextLevel = [];
        
        for (let i = 0; i < currentLevel.length; i += 2) {
          const left = currentLevel[i];
          const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : left;
          
          const combinedHash = createHash('sha256')
            .update(left + right)
            .digest('hex');
            
          nextLevel.push(combinedHash);
        }
        
        currentLevel = nextLevel;
      }

      return {
        root: currentLevel[0] || '',
        tree: hashes // Return leaf hashes for reference
      };
    } catch (error) {
      logger.error('Failed to generate Merkle tree', { 
        error: (error as Error).message 
      });
      throw error;
    }
  }

  /**
   * Get recent log entries
   */
  async getRecentLogs(limit: number = 100): Promise<LogEntry[]> {
    try {
      const logContent = await fs.readFile(this.logFilePath, 'utf8');
      
      if (!logContent.trim()) {
        return [];
      }

      const lines = logContent.trim().split('\n');
      const logs: LogEntry[] = [];

      for (let i = Math.max(0, lines.length - limit); i < lines.length; i++) {
        try {
          logs.push(JSON.parse(lines[i]));
        } catch (parseError) {
          logger.error('Failed to parse log entry', {
            lineNumber: i,
            error: (parseError as Error).message
          });
        }
      }

      return logs.reverse(); // Most recent first
    } catch (error) {
      logger.error('Failed to read recent logs', { 
        error: (error as Error).message 
      });
      return [];
    }
  }

  /**
   * Search logs by criteria
   */
  async searchLogs(
    criteria: {
      userId?: string;
      level?: string;
      startDate?: number;
      endDate?: number;
      messageContains?: string;
    }
  ): Promise<LogEntry[]> {
    try {
      const logContent = await fs.readFile(this.logFilePath, 'utf8');
      
      if (!logContent.trim()) {
        return [];
      }

      const lines = logContent.trim().split('\n');
      const logs: LogEntry[] = [];

      for (const line of lines) {
        try {
          const logEntry: LogEntry = JSON.parse(line);
          
          // Apply filters
          if (criteria.userId && logEntry.userId !== criteria.userId) continue;
          if (criteria.level && logEntry.level !== criteria.level) continue;
          if (criteria.startDate && logEntry.timestamp < criteria.startDate) continue;
          if (criteria.endDate && logEntry.timestamp > criteria.endDate) continue;
          if (criteria.messageContains && 
              !logEntry.message.toLowerCase().includes(criteria.messageContains.toLowerCase())) continue;
              
          logs.push(logEntry);
        } catch (parseError) {
          logger.error('Failed to parse log entry during search', {
            error: (parseError as Error).message
          });
        }
      }

      return logs;
    } catch (error) {
      logger.error('Failed to search logs', { 
        error: (error as Error).message 
      });
      return [];
    }
  }
}