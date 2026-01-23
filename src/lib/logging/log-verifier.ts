import fs from 'fs/promises';
import path from 'path';
import { createHash } from 'crypto';
import { TamperProofLogger, LogEntry, LogVerificationResult } from './tamper-proof-logger';
import { logger } from '../logger';

export interface IntegrityCheckResult {
  isValid: boolean;
  tamperedEntries?: number[];
  rootHash?: string;
  merkleTree?: string[];
  error?: string;
  checkedAt: number;
  duration: number;
}

export interface MerkleProof {
  leafIndex: number;
  leafHash: string;
  proof: string[];
  rootHash: string;
}

export class LogVerifier {
  private tamperProofLogger: TamperProofLogger;

  constructor(tamperProofLogger: TamperProofLogger) {
    this.tamperProofLogger = tamperProofLogger;
  }

  /**
   * Perform a comprehensive integrity check on the logs
   */
  async performIntegrityCheck(): Promise<IntegrityCheckResult> {
    const startTime = Date.now();

    try {
      const verificationResult = await this.tamperProofLogger.verifyIntegrity();
      
      // Generate Merkle tree for additional verification
      const merkleResult = await this.tamperProofLogger.generateMerkleTree();
      
      const result: IntegrityCheckResult = {
        isValid: verificationResult.isValid,
        tamperedEntries: verificationResult.tamperedEntries,
        rootHash: merkleResult.root,
        merkleTree: merkleResult.tree,
        checkedAt: Date.now(),
        duration: Date.now() - startTime
      };

      if (!verificationResult.isValid) {
        logger.warn('Log integrity check failed', {
          tamperedEntries: verificationResult.tamperedEntries,
          duration: result.duration
        });
      } else {
        logger.info('Log integrity check passed', {
          duration: result.duration
        });
      }

      return result;
    } catch (error) {
      const result: IntegrityCheckResult = {
        isValid: false,
        error: (error as Error).message,
        checkedAt: Date.now(),
        duration: Date.now() - startTime
      };

      logger.error('Log integrity check error', {
        error: (error as Error).message,
        duration: result.duration
      });

      return result;
    }
  }

  /**
   * Verify a specific log entry against its hash
   */
  async verifyLogEntry(logEntry: LogEntry): Promise<boolean> {
    try {
      // Recreate the hash of the log entry (excluding the currentHash field)
      const entryWithoutHash = { ...logEntry };
      delete entryWithoutHash.currentHash;
      
      const serialized = JSON.stringify(entryWithoutHash, Object.keys(entryWithoutHash).sort());
      const calculatedHash = createHash('sha256').update(serialized).digest('hex');
      
      return calculatedHash === logEntry.currentHash;
    } catch (error) {
      logger.error('Failed to verify log entry', {
        error: (error as Error).message,
        logId: logEntry.id
      });
      return false;
    }
  }

  /**
   * Generate a Merkle proof for a specific log entry
   */
  async generateMerkleProof(logIndex: number): Promise<MerkleProof | null> {
    try {
      // Get all log entries
      const logEntries = await this.getAllLogEntries();
      
      if (logIndex < 0 || logIndex >= logEntries.length) {
        throw new Error(`Invalid log index: ${logIndex}, total entries: ${logEntries.length}`);
      }

      // Calculate hashes for all entries
      const hashes = logEntries.map(entry => entry.currentHash);
      
      // Build the Merkle tree and track the path to the target
      let currentLevel = [...hashes];
      const proof: string[] = [];
      let currentIndex = logIndex;
      
      while (currentLevel.length > 1) {
        const nextLevel = [];
        const newProof = [];
        
        for (let i = 0; i < currentLevel.length; i += 2) {
          const left = currentLevel[i];
          const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : currentLevel[i];
          
          // Add sibling to proof if it's the sibling of our target node
          if (currentIndex === i && i + 1 < currentLevel.length) {
            newProof.push(right);
          } else if (currentIndex === i + 1) {
            newProof.push(left);
          }
          
          const combinedHash = createHash('sha256')
            .update(left + right)
            .digest('hex');
            
          nextLevel.push(combinedHash);
        }
        
        proof.push(...newProof);
        
        // Move to parent level
        currentLevel = nextLevel;
        currentIndex = Math.floor(currentIndex / 2);
      }

      return {
        leafIndex: logIndex,
        leafHash: hashes[logIndex],
        proof,
        rootHash: currentLevel[0] || ''
      };
    } catch (error) {
      logger.error('Failed to generate Merkle proof', {
        error: (error as Error).message,
        logIndex
      });
      return null;
    }
  }

  /**
   * Verify a Merkle proof for a log entry
   */
  verifyMerkleProof(proof: MerkleProof): boolean {
    try {
      let computedHash = proof.leafHash;
      let index = proof.leafIndex;
      
      for (const siblingHash of proof.proof) {
        if (index % 2 === 0) {
          // Current node is left child, sibling is right
          computedHash = createHash('sha256')
            .update(computedHash + siblingHash)
            .digest('hex');
        } else {
          // Current node is right child, sibling is left
          computedHash = createHash('sha256')
            .update(siblingHash + computedHash)
            .digest('hex');
        }
        
        index = Math.floor(index / 2);
      }
      
      return computedHash === proof.rootHash;
    } catch (error) {
      logger.error('Failed to verify Merkle proof', {
        error: (error as Error).message,
        leafIndex: proof.leafIndex
      });
      return false;
    }
  }

  /**
   * Get all log entries from the current log file
   */
  private async getAllLogEntries(): Promise<LogEntry[]> {
    const logDir = './logs'; // Assuming default log directory
    const today = new Date().toISOString().split('T')[0];
    const logFilePath = path.join(logDir, `audit-${today}.log`);

    try {
      const logContent = await fs.readFile(logFilePath, 'utf8');
      
      if (!logContent.trim()) {
        return [];
      }

      const lines = logContent.trim().split('\n');
      const logs: LogEntry[] = [];

      for (const line of lines) {
        try {
          logs.push(JSON.parse(line));
        } catch (parseError) {
          logger.error('Failed to parse log entry', {
            error: (parseError as Error).message,
            line
          });
        }
      }

      return logs;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        // File doesn't exist, which is valid
        return [];
      }
      
      logger.error('Failed to read all log entries', {
        error: (error as Error).message
      });
      throw error;
    }
  }

  /**
   * Schedule periodic integrity checks
   */
  scheduleIntegrityChecks(intervalMinutes: number = 60): NodeJS.Timeout {
    const interval = setInterval(async () => {
      try {
        const result = await this.performIntegrityCheck();
        
        if (!result.isValid) {
          logger.emergency('LOG INTEGRITY VIOLATION DETECTED!', {
            tamperedEntries: result.tamperedEntries,
            error: result.error
          });
          
          // In a real system, this might trigger alerts to security team
          // and possibly initiate incident response procedures
        }
      } catch (error) {
        logger.error('Scheduled integrity check failed', {
          error: (error as Error).message
        });
      }
    }, intervalMinutes * 60 * 1000);

    logger.info('Scheduled integrity checks', {
      intervalMinutes
    });

    return interval;
  }

  /**
   * Perform forensic analysis on logs
   */
  async performForensicAnalysis(criteria: {
    userId?: string;
    startDate?: number;
    endDate?: number;
    level?: string;
    searchTerm?: string;
  }): Promise<{
    totalEntries: number;
    matchingEntries: number;
    tamperedEntries: number[];
    suspiciousPatterns: Array<{ type: string; details: any; entryIndex: number }>;
  }> {
    try {
      // Get all log entries
      const allEntries = await this.getAllLogEntries();
      
      // Filter entries based on criteria
      let filteredEntries = allEntries;
      
      if (criteria.userId) {
        filteredEntries = filteredEntries.filter(entry => entry.userId === criteria.userId);
      }
      
      if (criteria.startDate) {
        filteredEntries = filteredEntries.filter(entry => entry.timestamp >= criteria.startDate!);
      }
      
      if (criteria.endDate) {
        filteredEntries = filteredEntries.filter(entry => entry.timestamp <= criteria.endDate!);
      }
      
      if (criteria.level) {
        filteredEntries = filteredEntries.filter(entry => entry.level === criteria.level);
      }
      
      if (criteria.searchTerm) {
        const term = criteria.searchTerm.toLowerCase();
        filteredEntries = filteredEntries.filter(entry => 
          entry.message.toLowerCase().includes(term) ||
          JSON.stringify(entry.data).toLowerCase().includes(term)
        );
      }

      // Check integrity of filtered entries
      let tamperedCount = 0;
      const tamperedIndices: number[] = [];
      const suspiciousPatterns: Array<{ type: string; details: any; entryIndex: number }> = [];

      // Check for missing entries in sequence
      for (let i = 0; i < filteredEntries.length; i++) {
        if (i > 0) {
          // Check if the previous hash matches
          if (filteredEntries[i].previousHash !== filteredEntries[i - 1].currentHash) {
            tamperedCount++;
            tamperedIndices.push(i);
          }
        }

        // Look for suspicious patterns
        if (filteredEntries[i].level === 'ERROR' && 
            filteredEntries[i].message.includes('SQL') && 
            filteredEntries[i].message.includes('syntax')) {
          suspiciousPatterns.push({
            type: 'SQL_INJECTION_ATTEMPT',
            details: { message: filteredEntries[i].message, userId: filteredEntries[i].userId },
            entryIndex: i
          });
        }

        if (filteredEntries[i].level === 'SECURITY' && 
            filteredEntries[i].message.includes('failed login') &&
            filteredEntries[i].userId) {
          // Check for brute force attempts
          const userFailedLogins = allEntries.filter(
            entry => entry.userId === filteredEntries[i].userId &&
                     entry.message.includes('failed login') &&
                     entry.timestamp > filteredEntries[i].timestamp - (15 * 60 * 1000) // Within 15 minutes
          ).length;

          if (userFailedLogins >= 5) {
            suspiciousPatterns.push({
              type: 'BRUTE_FORCE_ATTEMPT',
              details: { userId: filteredEntries[i].userId, failedAttempts: userFailedLogins },
              entryIndex: i
            });
          }
        }
      }

      return {
        totalEntries: allEntries.length,
        matchingEntries: filteredEntries.length,
        tamperedEntries: tamperedIndices,
        suspiciousPatterns
      };
    } catch (error) {
      logger.error('Forensic analysis failed', {
        error: (error as Error).message
      });
      throw error;
    }
  }

  /**
   * Verify the integrity of logs for a specific time period
   */
  async verifyTimePeriod(
    startDate: number,
    endDate: number
  ): Promise<{ isValid: boolean; tamperedEntries: number[]; error?: string }> {
    try {
      const allEntries = await this.getAllLogEntries();
      const periodEntries = allEntries.filter(
        entry => entry.timestamp >= startDate && entry.timestamp <= endDate
      );

      if (periodEntries.length === 0) {
        return { isValid: true, tamperedEntries: [] };
      }

      // Verify the hash chain for the time period
      const tamperedEntries: number[] = [];
      let expectedPreviousHash: string | null = null;

      // Find the first entry in the period and get its previous hash
      const firstIndex = allEntries.findIndex(entry => 
        entry.timestamp >= startDate && entry.timestamp <= endDate
      );

      if (firstIndex > 0) {
        expectedPreviousHash = allEntries[firstIndex - 1].currentHash;
      }

      for (let i = 0; i < periodEntries.length; i++) {
        const entry = periodEntries[i];

        // Verify the entry's own hash
        const entryWithoutHash = { ...entry };
        delete entryWithoutHash.currentHash;
        
        const serialized = JSON.stringify(entryWithoutHash, Object.keys(entryWithoutHash).sort());
        const calculatedHash = createHash('sha256').update(serialized).digest('hex');

        if (calculatedHash !== entry.currentHash) {
          tamperedEntries.push(i);
          continue;
        }

        // Verify the hash chain
        if (expectedPreviousHash !== entry.previousHash) {
          tamperedEntries.push(i);
          continue;
        }

        // Update expected hash for next iteration
        expectedPreviousHash = entry.currentHash;
      }

      return {
        isValid: tamperedEntries.length === 0,
        tamperedEntries
      };
    } catch (error) {
      logger.error('Time period verification failed', {
        error: (error as Error).message,
        startDate,
        endDate
      });
      return {
        isValid: false,
        tamperedEntries: [],
        error: (error as Error).message
      };
    }
  }
}