/**
 * Anti-Money Laundering (AML) Engine
 * Implements OFAC sanctions screening, transaction monitoring, and regulatory reporting
 */

import { Redis } from '@upstash/redis';
import { TamperProofLogger } from '../logging/tamper-proof-logger';
import { logger } from '../logger';

export interface TransactionRiskScore {
  score: number; // 0-100
  factors: string[];
  recommendation: 'APPROVE' | 'REVIEW' | 'BLOCK';
  flags: string[];
  ofacMatch?: {
    matchedName: string;
    confidence: number;
    listType: 'SDN' | 'EU_SANCTIONS' | 'UN_SANCTIONS';
  };
}

export interface SARReport {
  id: string;
  userId: string;
  transactionIds: string[];
  suspiciousActivity: string[];
  narrativeDescription: string;
  filingDate: number;
  deadline: number;
  status: 'PENDING' | 'FILED' | 'REJECTED';
  fincenForm111: any;
}

export interface TransactionData {
  userId: string;
  amount: number;
  fromAccount: string;
  toAccount: string;
  type: 'DEPOSIT' | 'WITHDRAWAL' | 'TRANSFER';
  ipAddress: string;
  timestamp: number;
  metadata?: any;
}

export class AMLEngine {
  private redis: Redis;
  private auditLogger: TamperProofLogger;
  private ofacList: Set<string> = new Set();
  private sanctionsList: Map<string, any> = new Map(); // Extended sanctions database
  private lastOFACUpdate: number = 0;
  
  // Risk thresholds
  private readonly THRESHOLDS = {
    CTR_AMOUNT: 10000, // $10k CTR threshold
    STRUCTURING_AMOUNT: 9000, // Just below CTR
    DAILY_TRANSACTION_LIMIT: 50,
    VELOCITY_HIGH: 10, // tx per hour
    HIGH_RISK_COUNTRIES: ['AF', 'IR', 'KP', 'MM', 'SY', 'YE', 'RU', 'BY'], // FATF list
  };

  constructor() {
    this.redis = Redis.fromEnv();
    this.auditLogger = new TamperProofLogger('./logs/compliance');
    this.initializeSanctionsLists();
  }

  /**
   * Initialize sanctions lists (in production, this would sync with official sources)
   */
  private async initializeSanctionsLists(): Promise<void> {
    try {
      // Load pre-downloaded sanctions data or initialize with sample data
      // In production, this would call external APIs like OFAC's API
      await this.loadOFACList();
      
      // Schedule daily updates
      setInterval(() => {
        this.loadOFACList().catch(err => {
          logger.error('Failed to update OFAC list', err);
        });
      }, 24 * 60 * 60 * 1000); // 24 hours
      
      logger.info('AML Engine initialized sanctions lists');
    } catch (error) {
      logger.error('Failed to initialize sanctions lists', error);
      throw error;
    }
  }

  /**
   * Load and update OFAC SDN list
   * NOTE: This is a simplified implementation. In production, you would integrate
   * with OFAC's official API or download feeds directly from treasury.gov
   */
  private async loadOFACList(): Promise<void> {
    try {
      const cacheKey = 'aml:ofac:last_update';
      const cachedTime = await this.redis.get<number>(cacheKey);
      
      // Only update if it's been more than 24 hours
      if (cachedTime && (Date.now() - cachedTime) < 24 * 60 * 60 * 1000) {
        return;
      }

      // In a real implementation, this would fetch from:
      // https://www.treasury.gov/ofac/downloads/sdn.xml
      // For this example, we'll simulate loading from a cached dataset
      
      // Sample OFAC entries for demonstration
      const sampleOFACEntries = [
        'JOHN DOE',
        'JANE SMITH',
        'AL QAEDA',
        'HAMAS',
        'HEZBOLLAH',
        'UNITED NATIONS',
        'TALIBAN',
        'ISLAMIC STATE',
        // Add more sample entries
      ];

      // Clear existing list and add new entries
      this.ofacList.clear();
      sampleOFACEntries.forEach(name => {
        this.ofacList.add(name.toUpperCase());
        // Also add common variations
        this.ofacList.add(name.toLowerCase());
        this.ofacList.add(name.replace(/\s+/g, ' ').trim());
      });

      // Update timestamp
      this.lastOFACUpdate = Date.now();
      await this.redis.set(cacheKey, this.lastOFACUpdate);
      
      logger.info('OFAC list updated successfully', {
        entryCount: this.ofacList.size,
        updateTime: new Date(this.lastOFACUpdate).toISOString()
      });
    } catch (error) {
      logger.error('Error updating OFAC list', {
        error: (error as Error).message
      });
      throw error;
    }
  }

  /**
   * Check if entity is on OFAC sanctions list using fuzzy matching
   */
  private async checkOFAC(name: string, accountNumber: string): Promise<{ isMatch: boolean; matchedEntry?: any; confidence?: number }> {
    const upperName = name.toUpperCase().replace(/\s+/g, ' ').trim();
    
    // Direct exact match
    if (this.ofacList.has(upperName)) {
      const matchedEntry = {
        name: upperName,
        listType: 'SDN',
        sdnType: 'individual',
        title: '',
        remarks: 'Exact match'
      };
      
      return {
        isMatch: true,
        matchedEntry,
        confidence: 100
      };
    }

    // Check for partial/fuzzy matches using simplified approach
    // In production, use proper fuzzy matching algorithms like Levenshtein distance
    for (const entry of this.ofacList) {
      // Check if name contains the entry or vice versa
      if (upperName.includes(entry) || entry.includes(upperName)) {
        // Calculate similarity score (simplified)
        const similarity = this.calculateSimilarity(upperName, entry);
        
        if (similarity > 0.8) { // 80% similarity threshold
          const matchedEntry = {
            name: entry,
            listType: 'SDN',
            sdnType: 'individual',
            title: '',
            remarks: `Fuzzy match (confidence: ${Math.round(similarity * 100)}%)`
          };
          
          return {
            isMatch: true,
            matchedEntry,
            confidence: Math.round(similarity * 100)
          };
        }
      }
    }

    return { isMatch: false };
  }

  /**
   * Calculate similarity between two strings (simplified version)
   */
  private calculateSimilarity(str1: string, str2: string): number {
    const longer = str1.length > str2.length ? str1 : str2;
    const shorter = str1.length > str2.length ? str2 : str1;
    
    if (longer.length === 0) return 1.0;
    
    const editDistance = this.levenshteinDistance(longer, shorter);
    return (longer.length - editDistance) / longer.length;
  }

  /**
   * Calculate Levenshtein distance between two strings
   */
  private levenshteinDistance(str1: string, str2: string): number {
    const matrix = [];
    
    if (str1.length === 0) return str2.length;
    if (str2.length === 0) return str1.length;

    // Initialize matrix
    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }

    // Fill matrix
    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // substitution
            matrix[i][j - 1] + 1,     // insertion
            matrix[i - 1][j] + 1      // deletion
          );
        }
      }
    }

    return matrix[str2.length][str1.length];
  }

  /**
   * Assess transaction for AML/fraud risk
   */
  async assessTransaction(transaction: TransactionData): Promise<TransactionRiskScore> {
    try {
      const riskFactors: string[] = [];
      const riskFlags: string[] = [];
      let totalRiskScore = 0;

      // 1. OFAC screening
      const ofacResult = await this.checkOFAC(transaction.toAccount, transaction.toAccount);
      if (ofacResult.isMatch) {
        riskFactors.push(`OFAC_MATCH: ${ofacResult.matchedEntry?.name}`);
        totalRiskScore += 100; // Maximum risk for OFAC match
        riskFlags.push('OFAC_MATCH');
        
        return {
          score: 100,
          factors: riskFactors,
          recommendation: 'BLOCK',
          flags: riskFlags,
          ofacMatch: {
            matchedName: ofacResult.matchedEntry!.name,
            confidence: ofacResult.confidence!,
            listType: 'SDN'
          }
        };
      }

      // 2. CTR threshold check (Currency Transaction Report)
      if (transaction.amount >= this.THRESHOLDS.CTR_AMOUNT) {
        riskFactors.push(`CTR_THRESHOLD_EXCEEDED: $${transaction.amount.toFixed(2)}`);
        totalRiskScore += 20;
        riskFlags.push('CTR_THRESHOLD');
      }

      // 3. Structuring detection (amounts just under CTR threshold)
      if (transaction.amount >= this.THRESHOLDS.STRUCTURING_AMOUNT && 
          transaction.amount < this.THRESHOLDS.CTR_AMOUNT) {
        riskFactors.push(`STRUCTURING_PATTERN: $${transaction.amount.toFixed(2)} (near CTR threshold)`);
        totalRiskScore += 15;
        riskFlags.push('STRUCTURING');
      }

      // 4. Velocity checks (too many transactions in short period)
      const velocityRisk = await this.checkVelocity(transaction.userId, transaction.timestamp);
      if (velocityRisk > 0) {
        totalRiskScore += velocityRisk;
        riskFactors.push(`HIGH_VELOCITY: ${velocityRisk} risk points`);
        riskFlags.push('VELOCITY');
      }

      // 5. Geographic risk (high-risk countries)
      const geoRisk = this.checkGeographicRisk(transaction.ipAddress);
      if (geoRisk) {
        totalRiskScore += 25;
        riskFactors.push(`GEOGRAPHIC_RISK: ${geoRisk}`);
        riskFlags.push('GEOGRAPHIC_RISK');
      }

      // 6. Account age check (new accounts higher risk)
      const accountAgeRisk = await this.checkAccountAge(transaction.userId);
      if (accountAgeRisk > 0) {
        totalRiskScore += accountAgeRisk;
        riskFactors.push(`ACCOUNT_AGE_RISK: ${accountAgeRisk} risk points`);
        riskFlags.push('NEW_ACCOUNT');
      }

      // 7. Behavioral pattern analysis
      const behavioralRisk = await this.analyzeBehavioralPatterns(transaction);
      if (behavioralRisk > 0) {
        totalRiskScore += behavioralRisk;
        riskFactors.push(`BEHAVIORAL_ANOMALY: ${behavioralRisk} risk points`);
        riskFlags.push('BEHAVIORAL_ANOMALY');
      }

      // 8. Device/IP reputation
      const deviceRisk = await this.checkDeviceReputation(transaction.ipAddress);
      if (deviceRisk > 0) {
        totalRiskScore += deviceRisk;
        riskFactors.push(`DEVICE_REPUTATION: ${deviceRisk} risk points`);
        riskFlags.push('DEVICE_RISK');
      }

      // Cap the risk score at 100
      totalRiskScore = Math.min(totalRiskScore, 100);

      // Determine recommendation based on risk score
      let recommendation: 'APPROVE' | 'REVIEW' | 'BLOCK';
      if (totalRiskScore >= 80) {
        recommendation = 'BLOCK';
      } else if (totalRiskScore >= 40) {
        recommendation = 'REVIEW';
      } else {
        recommendation = 'APPROVE';
      }

      // Log the assessment for audit trail
      await this.auditLogger.log({
        level: 'AUDIT',
        module: 'AML_ENGINE',
        action: 'TRANSACTION_ASSESSMENT',
        userId: transaction.userId,
        details: {
          transactionId: transaction.fromAccount, // Using account as proxy for transaction ID
          amount: transaction.amount,
          riskScore: totalRiskScore,
          recommendation,
          factors: riskFactors,
          flags: riskFlags
        }
      });

      logger.info('Transaction assessed by AML engine', {
        userId: transaction.userId,
        amount: transaction.amount,
        riskScore: totalRiskScore,
        recommendation
      });

      return {
        score: totalRiskScore,
        factors: riskFactors,
        recommendation,
        flags: riskFlags
      };
    } catch (error) {
      logger.error('Error assessing transaction', {
        error: (error as Error).message,
        userId: transaction.userId,
        amount: transaction.amount
      });

      // In case of error, default to conservative approach
      return {
        score: 80, // High risk by default
        factors: ['ASSESSMENT_ERROR'],
        recommendation: 'REVIEW',
        flags: ['ASSESSMENT_ERROR']
      };
    }
  }

  /**
   * Check transaction velocity (frequency-based risk)
   */
  private async checkVelocity(userId: string, timestamp: number): Promise<number> {
    try {
      const now = Date.now();
      const oneHourAgo = now - (60 * 60 * 1000); // 1 hour
      const key = `aml:velocity:${userId}`;
      
      // Add current transaction timestamp
      await this.redis.zadd(key, { score: timestamp, member: `tx_${timestamp}` });
      
      // Remove old entries beyond 1 hour window
      await this.redis.zremrangebyscore(key, 0, oneHourAgo);
      
      // Count recent transactions
      const recentCount = await this.redis.zcard(key);
      
      // Expire the key after 2 hours of inactivity to save memory
      await this.redis.expire(key, 2 * 60 * 60);
      
      // Calculate risk based on velocity
      if (recentCount > this.THRESHOLDS.VELOCITY_HIGH) {
        return 20; // High risk for high velocity
      } else if (recentCount > 5) {
        return 10; // Medium risk
      }
      
      return 0; // No risk
    } catch (error) {
      logger.error('Error checking velocity', { error: (error as Error).message });
      return 0; // Fail safely
    }
  }

  /**
   * Check geographic risk based on IP address
   */
  private checkGeographicRisk(ipAddress: string): string | null {
    // In production, this would use a geolocation service
    // For this example, we'll return null as a placeholder
    // Real implementation would check if IP is from high-risk countries
    
    // This is a simplified check - in reality you'd use a geolocation API
    // and check against FATF grey/black lists
    return null;
  }

  /**
   * Check account age risk
   */
  private async checkAccountAge(userId: string): Promise<number> {
    try {
      const accountCreationKey = `user:created_at:${userId}`;
      const creationTime = await this.redis.get<number>(accountCreationKey);
      
      if (!creationTime) {
        // If we can't find account creation time, assume high risk
        return 15;
      }
      
      const daysOld = (Date.now() - creationTime) / (24 * 60 * 60 * 1000);
      
      if (daysOld < 7) { // Less than 1 week old
        return 15;
      } else if (daysOld < 30) { // Less than 1 month old
        return 8;
      } else {
        return 0; // Mature account has lower risk
      }
    } catch (error) {
      logger.error('Error checking account age', { error: (error as Error).message });
      return 0; // Fail safely
    }
  }

  /**
   * Analyze behavioral patterns
   */
  private async analyzeBehavioralPatterns(transaction: TransactionData): Promise<number> {
    try {
      const key = `aml:behavior:${transaction.userId}`;
      
      // Get historical transaction patterns
      const historical = await this.redis.hgetall(key);
      
      // This is a simplified check - in production you'd implement
      // complex pattern recognition algorithms
      let riskPoints = 0;
      
      // Check for round-tripping (sending money and getting it back)
      // Check for layering (complex transaction chains)
      // Check for structuring (breaking large amounts into smaller ones)
      
      // Placeholder for complex behavioral analysis
      // In a real system, this would use ML models
      
      return riskPoints;
    } catch (error) {
      logger.error('Error analyzing behavioral patterns', { error: (error as Error).message });
      return 0; // Fail safely
    }
  }

  /**
   * Check device/IP reputation
   */
  private async checkDeviceReputation(ipAddress: string): Promise<number> {
    try {
      // In production, this would check against threat intelligence feeds
      // and IP reputation services
      
      // This is a simplified check
      // Real implementation would integrate with services like TOR exit nodes,
      // VPN providers, proxy lists, etc.
      
      // Placeholder - return 0 for now
      return 0;
    } catch (error) {
      logger.error('Error checking device reputation', { error: (error as Error).message });
      return 0; // Fail safely
    }
  }

  /**
   * Generate SAR (Suspicious Activity Report)
   */
  async generateSAR(
    userId: string,
    transactionIds: string[],
    suspiciousActivities: string[],
    narrativeDescription: string = ''
  ): Promise<SARReport> {
    try {
      const sarId = `SAR_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const filingDate = Date.now();
      const deadline = filingDate + (30 * 24 * 60 * 60 * 1000); // 30 days from detection

      // Create the SAR record
      const sarReport: SARReport = {
        id: sarId,
        userId,
        transactionIds,
        suspiciousActivity: suspiciousActivities,
        narrativeDescription,
        filingDate,
        deadline,
        status: 'PENDING',
        fincenForm111: {
          // FinCEN Form 111 fields would go here
          sarId,
          filingDate: new Date(filingDate).toISOString(),
          deadline: new Date(deadline).toISOString(),
          userId,
          transactions: transactionIds,
          suspiciousActivities,
          narrative: narrativeDescription,
          // Additional required fields would be populated here
        }
      };

      // Store in Redis with expiration
      const sarKey = `sar:${sarId}`;
      await this.redis.setex(sarKey, 365 * 24 * 60 * 60, sarReport); // Store for 1 year
      
      // Update user's SAR status
      await this.redis.sadd(`user:sars:${userId}`, sarId);
      
      // Log the SAR generation
      await this.auditLogger.log({
        level: 'AUDIT',
        module: 'AML_ENGINE',
        action: 'SAR_GENERATED',
        userId,
        details: {
          sarId,
          transactionIds,
          suspiciousActivities,
          deadline: new Date(deadline).toISOString()
        }
      });

      logger.info('SAR generated successfully', {
        sarId,
        userId,
        transactionCount: transactionIds.length
      });

      return sarReport;
    } catch (error) {
      logger.error('Error generating SAR', {
        error: (error as Error).message,
        userId
      });
      
      throw new Error('Failed to generate SAR report');
    }
  }

  /**
   * Generate CTR (Currency Transaction Report)
   */
  async generateCTR(
    userId: string,
    transactions: TransactionData[]
  ): Promise<any> {
    try {
      const ctrId = `CTR_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const filingDate = Date.now();
      
      // Calculate total amount for CTR
      const totalAmount = transactions.reduce((sum, tx) => sum + tx.amount, 0);

      // Create the CTR record
      const ctrRecord = {
        id: ctrId,
        userId,
        transactions: transactions.map(tx => ({
          id: tx.fromAccount, // Using account as proxy for transaction ID
          amount: tx.amount,
          timestamp: tx.timestamp,
          type: tx.type
        })),
        totalAmount,
        filingDate,
        status: 'PENDING',
        fincenForm112: {
          // FinCEN Form 112 fields would go here
          ctrId,
          filingDate: new Date(filingDate).toISOString(),
          userId,
          totalAmount,
          transactions: transactions.map(tx => ({
            id: tx.fromAccount,
            amount: tx.amount,
            timestamp: new Date(tx.timestamp).toISOString(),
            type: tx.type
          })),
          // Additional required fields would be populated here
        }
      };

      // Store in Redis with expiration
      const ctrKey = `ctr:${ctrId}`;
      await this.redis.setex(ctrKey, 365 * 24 * 60 * 60, ctrRecord); // Store for 1 year
      
      // Update user's CTR status
      await this.redis.sadd(`user:ctrs:${userId}`, ctrId);
      
      // Log the CTR generation
      await this.auditLogger.log({
        level: 'AUDIT',
        module: 'AML_ENGINE',
        action: 'CTR_GENERATED',
        userId,
        details: {
          ctrId,
          transactionCount: transactions.length,
          totalAmount
        }
      });

      logger.info('CTR generated successfully', {
        ctrId,
        userId,
        transactionCount: transactions.length,
        totalAmount
      });

      return ctrRecord;
    } catch (error) {
      logger.error('Error generating CTR', {
        error: (error as Error).message,
        userId
      });
      
      throw new Error('Failed to generate CTR report');
    }
  }

  /**
   * Check if user has pending SARs that need filing
   */
  async checkPendingSARDeadlines(): Promise<SARReport[]> {
    try {
      // This would scan for SARs approaching their 30-day deadline
      // In production, this would run as a scheduled job
      
      // Placeholder implementation
      return [];
    } catch (error) {
      logger.error('Error checking SAR deadlines', { error: (error as Error).message });
      return [];
    }
  }

  /**
   * Get user's compliance status
   */
  async getUserComplianceStatus(userId: string): Promise<{
    hasActiveSARs: boolean;
    hasPendingCTRs: boolean;
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    lastAssessment: number | null;
  }> {
    try {
      const sarCount = await this.redis.scard(`user:sars:${userId}`);
      const ctrCount = await this.redis.scard(`user:ctrs:${userId}`);
      
      // Get latest risk assessment
      const lastAssessment = await this.redis.get<number>(`aml:last_assessment:${userId}`);
      
      // Determine risk level
      let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
      
      if (sarCount > 0) {
        riskLevel = 'CRITICAL';
      } else if (ctrCount > 0) {
        riskLevel = 'HIGH';
      } else {
        // Check latest risk score
        const lastScore = await this.redis.get<number>(`aml:last_score:${userId}`);
        if (lastScore !== null) {
          if (lastScore >= 80) {
            riskLevel = 'CRITICAL';
          } else if (lastScore >= 40) {
            riskLevel = 'HIGH';
          } else if (lastScore >= 20) {
            riskLevel = 'MEDIUM';
          }
        }
      }

      return {
        hasActiveSARs: sarCount > 0,
        hasPendingCTRs: ctrCount > 0,
        riskLevel,
        lastAssessment
      };
    } catch (error) {
      logger.error('Error getting user compliance status', { 
        error: (error as Error).message, 
        userId 
      });
      
      return {
        hasActiveSARs: false,
        hasPendingCTRs: false,
        riskLevel: 'LOW',
        lastAssessment: null
      };
    }
  }
}