import { Redis } from 'ioredis';
import { RateLimitResult } from './redis-rate-limiter';

export interface VelocityPattern {
  name: string;
  description: string;
  check: (data: VelocityCheckData) => boolean;
}

export interface VelocityCheckData {
  ip: string;
  accountId?: string;
  endpoint: string;
  userAgent?: string;
  timestamp: number;
}

export interface VelocityRiskAssessment {
  isHighRisk: boolean;
  riskScore: number; // 0-100
  detectedPatterns: string[];
  recommendations: string[];
}

export class VelocityChecker {
  private redis: Redis;
  private patterns: VelocityPattern[];

  constructor(redisUrl?: string) {
    this.redis = new Redis(redisUrl || process.env.REDIS_URL || 'redis://localhost:6379');
    this.patterns = this.initializePatterns();
  }

  /**
   * Initializes velocity detection patterns
   */
  private initializePatterns(): VelocityPattern[] {
    return [
      {
        name: 'rapid-fire',
        description: 'More than 10 requests per second from same IP',
        check: (data: VelocityCheckData) => {
          // This would be checked against recent request data
          return false; // Placeholder - actual check happens in analyzeVelocity
        }
      },
      {
        name: 'burst-pattern',
        description: 'Sudden spike in requests (>50 req/min)',
        check: (data: VelocityCheckData) => {
          return false; // Placeholder
        }
      },
      {
        name: 'sustained-high-volume',
        description: 'Consistently high volume (>100 req/hr)',
        check: (data: VelocityCheckData) => {
          return false; // Placeholder
        }
      },
      {
        name: 'credential-stuffing',
        description: 'Many failed login attempts in short time',
        check: (data: VelocityCheckData) => {
          return false; // Placeholder
        }
      },
      {
        name: 'account-enumeration',
        description: 'Sequential requests to user-specific endpoints',
        check: (data: VelocityCheckData) => {
          return false; // Placeholder
        }
      }
    ];
  }

  /**
   * Records a request for velocity analysis
   */
  async recordRequest(data: VelocityCheckData): Promise<void> {
    const now = Date.now();
    const minuteKey = `velocity:${data.ip}:minute:${Math.floor(now / 60000)}`;
    const hourKey = `velocity:${data.ip}:hour:${Math.floor(now / 3600000)}`;
    const dayKey = `velocity:${data.ip}:day:${Math.floor(now / 86400000)}`;
    
    // Use Redis to track requests in different time windows
    const pipeline = this.redis.pipeline();
    
    // Track requests per minute
    pipeline.zadd(minuteKey, now.toString(), `${now}:${Math.random()}`);
    pipeline.expire(minuteKey, 120); // 2 minutes TTL to ensure cleanup
    
    // Track requests per hour
    pipeline.zadd(hourKey, now.toString(), `${now}:${Math.random()}`);
    pipeline.expire(hourKey, 7200); // 2 hours TTL
    
    // Track requests per day
    pipeline.zadd(dayKey, now.toString(), `${now}:${Math.random()}`);
    pipeline.expire(dayKey, 172800); // 2 days TTL
    
    // Also track if this is for a specific account
    if (data.accountId) {
      const accountMinuteKey = `velocity:account:${data.accountId}:minute:${Math.floor(now / 60000)}`;
      pipeline.zadd(accountMinuteKey, now.toString(), `${now}:${Math.random()}`);
      pipeline.expire(accountMinuteKey, 120);
    }
    
    await pipeline.exec();
  }

  /**
   * Analyzes velocity patterns for a given IP or account
   */
  async analyzeVelocity(ip: string, accountId?: string): Promise<VelocityRiskAssessment> {
    const now = Date.now();
    const risks: string[] = [];
    let riskScore = 0;

    // Check requests per minute
    const minuteAgo = now - 60000;
    const minuteKey = `velocity:${ip}:minute:${Math.floor(minuteAgo / 60000)}`;
    const requestsPerMinute = await this.getRequestCount(minuteKey, minuteAgo);
    
    if (requestsPerMinute > 50) {
      risks.push('high-volume-minute');
      riskScore += 40;
    } else if (requestsPerMinute > 20) {
      risks.push('moderate-volume-minute');
      riskScore += 20;
    }

    // Check requests per hour
    const hourAgo = now - 3600000;
    const hourKey = `velocity:${ip}:hour:${Math.floor(hourAgo / 3600000)}`;
    const requestsPerHour = await this.getRequestCount(hourKey, hourAgo);
    
    if (requestsPerHour > 500) {
      risks.push('high-volume-hour');
      riskScore += 30;
    } else if (requestsPerHour > 200) {
      risks.push('moderate-volume-hour');
      riskScore += 15;
    }

    // Check account-specific velocity if provided
    if (accountId) {
      const accountMinuteKey = `velocity:account:${accountId}:minute:${Math.floor(minuteAgo / 60000)}`;
      const accountRequestsPerMinute = await this.getRequestCount(accountMinuteKey, minuteAgo);
      
      if (accountRequestsPerMinute > 30) {
        risks.push('account-targeting');
        riskScore += 35;
      }
    }

    // Additional checks for specific patterns
    const additionalRisks = await this.checkSpecificPatterns(ip, accountId);
    risks.push(...additionalRisks.risks);
    riskScore += additionalRisks.score;

    // Cap risk score at 100
    riskScore = Math.min(riskScore, 100);

    const recommendations: string[] = [];
    if (risks.includes('high-volume-minute') || risks.includes('high-volume-hour')) {
      recommendations.push('Consider temporary IP blocking');
    }
    if (risks.includes('account-targeting')) {
      recommendations.push('Monitor account for suspicious activity');
    }
    if (riskScore > 70) {
      recommendations.push('Escalate to security team');
    }

    return {
      isHighRisk: riskScore > 50,
      riskScore,
      detectedPatterns: risks,
      recommendations
    };
  }

  /**
   * Checks for specific attack patterns
   */
  private async checkSpecificPatterns(ip: string, accountId?: string): Promise<{ risks: string[], score: number }> {
    const now = Date.now();
    const risks: string[] = [];
    let score = 0;

    // Check for rapid-fire pattern (more than 10 requests per second)
    const recentRequests = await this.getRecentRequests(ip, now - 1000); // Last 1 second
    if (recentRequests > 10) {
      risks.push('rapid-fire');
      score += 35;
    }

    // Check for credential stuffing pattern
    // Look for many login attempts with different usernames
    const loginAttempts = await this.getLoginAttempts(ip, now - 300000); // Last 5 minutes
    if (loginAttempts.count > 20 && loginAttempts.uniqueUsers > 15) {
      risks.push('potential-credential-stuffing');
      score += 45;
    }

    // Check for account enumeration
    // Look for sequential user ID requests
    const accountEnumScore = await this.checkAccountEnumeration(ip);
    if (accountEnumScore > 0.7) {
      risks.push('likely-account-enumeration');
      score += 40;
    }

    return { risks, score };
  }

  /**
   * Gets request count for a specific time window
   */
  private async getRequestCount(key: string, startTime: number): Promise<number> {
    try {
      // Clean up old entries and count
      await this.redis.zremrangebyscore(key, 0, startTime);
      return await this.redis.zcard(key);
    } catch (error) {
      console.error(`[VELOCITY] Error getting request count for ${key}:`, error);
      return 0;
    }
  }

  /**
   * Gets number of requests in the last specified milliseconds
   */
  private async getRecentRequests(ip: string, startTime: number): Promise<number> {
    const key = `velocity:${ip}:recent`;
    return this.getRequestCount(key, startTime);
  }

  /**
   * Gets login attempt statistics
   */
  private async getLoginAttempts(ip: string, startTime: number): Promise<{ count: number, uniqueUsers: number }> {
    // This would normally track login attempts specifically
    // For now, returning a mock value
    return { count: 0, uniqueUsers: 0 };
  }

  /**
   * Checks for account enumeration patterns
   */
  private async checkAccountEnumeration(ip: string): Promise<number> {
    // This would analyze access patterns to detect enumeration
    // For now, returning a mock value
    return 0;
  }

  /**
   * Applies graduated responses based on risk level
   */
  async applyGraduatedResponse(assessment: VelocityRiskAssessment): Promise<'allow' | 'warn' | 'throttle' | 'block'> {
    if (assessment.riskScore >= 80) {
      return 'block';
    } else if (assessment.riskScore >= 60) {
      return 'throttle';
    } else if (assessment.riskScore >= 40) {
      return 'warn';
    } else {
      return 'allow';
    }
  }

  /**
   * Clears velocity tracking data for an IP
   */
  async clearVelocityData(ip: string): Promise<void> {
    // In a real implementation, we'd need to scan and delete all velocity keys for this IP
    // For now, this is a placeholder
    console.log(`[VELOCITY] Clearing velocity data for IP: ${ip}`);
  }
}