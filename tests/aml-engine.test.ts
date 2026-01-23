/**
 * AML Engine Unit Tests
 * Comprehensive tests for Anti-Money Laundering functionality
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'assert';
import { AMLEngine, TransactionRiskScore, SARReport } from '../src/lib/compliance/aml-engine';
import { Redis } from '@upstash/redis';
import { TamperProofLogger } from '../src/lib/logging/tamper-proof-logger';

// Mock dependencies for testing
class MockTamperProofLogger {
  async log(logData: any) {
    // Mock implementation
    return Promise.resolve();
  }
}

// Create a test-specific AML engine that doesn't initialize sanctions lists
class TestAMLEngine extends AMLEngine {
  constructor() {
    // @ts-ignore - bypassing private property initialization for testing
    super();
    // Override the constructor logic for testing
    this.redis = Redis.fromEnv();
    // @ts-ignore - mocking the logger for testing
    this.auditLogger = new MockTamperProofLogger();
  }
  
  // Expose private methods for testing
  public async testCheckOFAC(name: string, accountNumber: string) {
    return this.checkOFAC(name, accountNumber);
  }
  
  public async testCheckVelocity(userId: string, timestamp: number) {
    return this.checkVelocity(userId, timestamp);
  }
  
  public testCalculateSimilarity(str1: string, str2: string) {
    return this.calculateSimilarity(str1, str2);
  }
  
  public testLevenshteinDistance(str1: string, str2: string) {
    return this.levenshteinDistance(str1, str2);
  }
}

describe('AMLEngine', () => {
  let amlEngine: TestAMLEngine;
  let testUserId: string;

  beforeEach(async () => {
    amlEngine = new TestAMLEngine();
    testUserId = `test_user_${Date.now()}`;
    
    // Set up test data in Redis
    const redis = Redis.fromEnv();
    await redis.set(`user:created_at:${testUserId}`, Date.now() - (30 * 24 * 60 * 60 * 1000)); // 30 days ago
  });

  afterEach(async () => {
    // Clean up test data
    const redis = Redis.fromEnv();
    await redis.del(`user:created_at:${testUserId}`);
    await redis.del(`aml:velocity:${testUserId}`);
    await redis.del(`aml:behavior:${testUserId}`);
    await redis.del(`user:sars:${testUserId}`);
    await redis.del(`user:ctrs:${testUserId}`);
  });

  describe('OFAC Sanctions Screening', () => {
    it('should detect exact OFAC match', async () => {
      const result = await amlEngine.testCheckOFAC('AL QAEDA', 'test_account');
      assert.strictEqual(result.isMatch, true);
      assert.ok(result.confidence);
      assert.ok(result.matchedEntry);
    });

    it('should detect fuzzy match with high confidence', async () => {
      const result = await amlEngine.testCheckOFAC('Al Qaeda', 'test_account'); // Different capitalization
      assert.strictEqual(result.isMatch, true);
      assert.ok(result.confidence);
      assert.ok(result.matchedEntry);
    });

    it('should return no match for non-sanctioned entity', async () => {
      const result = await amlEngine.testCheckOFAC('JOHN SMITH', 'test_account');
      assert.strictEqual(result.isMatch, false);
    });
  });

  describe('Transaction Assessment', () => {
    it('should block transaction if OFAC match detected', async () => {
      const transaction = {
        userId: testUserId,
        amount: 100,
        fromAccount: 'from_acc',
        toAccount: 'AL QAEDA', // This should trigger OFAC match
        type: 'TRANSFER' as const,
        ipAddress: '192.168.1.1',
        timestamp: Date.now(),
        metadata: {}
      };

      const result = await amlEngine.assessTransaction(transaction);
      
      assert.strictEqual(result.score, 100);
      assert.strictEqual(result.recommendation, 'BLOCK');
      assert.ok(result.ofacMatch);
      assert.strictEqual(result.ofacMatch!.matchedName, 'AL QAEDA');
    });

    it('should flag CTR threshold violations', async () => {
      const transaction = {
        userId: testUserId,
        amount: 15000, // Over $10k threshold
        fromAccount: 'from_acc',
        toAccount: 'recipient_acc',
        type: 'TRANSFER' as const,
        ipAddress: '192.168.1.1',
        timestamp: Date.now(),
        metadata: {}
      };

      const result = await amlEngine.assessTransaction(transaction);
      
      assert.ok(result.score >= 20, 'Should have at least 20 risk points for CTR violation');
      assert.ok(result.flags.includes('CTR_THRESHOLD'));
      assert.ok(result.factors.some(factor => factor.includes('CTR_THRESHOLD_EXCEEDED')));
    });

    it('should flag structuring patterns near threshold', async () => {
      const transaction = {
        userId: testUserId,
        amount: 9500, // Near $10k threshold
        fromAccount: 'from_acc',
        toAccount: 'recipient_acc',
        type: 'TRANSFER' as const,
        ipAddress: '192.168.1.1',
        timestamp: Date.now(),
        metadata: {}
      };

      const result = await amlEngine.assessTransaction(transaction);
      
      assert.ok(result.score >= 15, 'Should have at least 15 risk points for structuring');
      assert.ok(result.flags.includes('STRUCTURING'));
      assert.ok(result.factors.some(factor => factor.includes('STRUCTURING_PATTERN')));
    });

    it('should approve low-risk transaction', async () => {
      const transaction = {
        userId: testUserId,
        amount: 100,
        fromAccount: 'from_acc',
        toAccount: 'safe_recipient',
        type: 'TRANSFER' as const,
        ipAddress: '192.168.1.1',
        timestamp: Date.now(),
        metadata: {}
      };

      const result = await amlEngine.assessTransaction(transaction);
      
      assert.ok(result.score < 40, 'Low-risk transaction should have score below 40');
      assert.strictEqual(result.recommendation, 'APPROVE');
    });
  });

  describe('Velocity Checks', () => {
    it('should detect high transaction velocity', async () => {
      const timestamp = Date.now();
      
      // Simulate many transactions in a short time
      for (let i = 0; i < 15; i++) {
        await amlEngine.testCheckVelocity(testUserId, timestamp - (i * 1000)); // Every second
      }

      const risk = await amlEngine.testCheckVelocity(testUserId, timestamp);
      
      // Should have high risk due to velocity
      assert.ok(risk >= 20, 'High velocity should result in significant risk points');
    });

    it('should return no risk for normal velocity', async () => {
      const timestamp = Date.now();
      const risk = await amlEngine.testCheckVelocity(testUserId, timestamp);
      
      assert.strictEqual(risk, 0, 'Normal velocity should have no risk');
    });
  });

  describe('Account Age Risk', () => {
    it('should assign higher risk to newer accounts', async () => {
      const newUserId = `new_user_${Date.now()}`;
      const redis = Redis.fromEnv();
      await redis.set(`user:created_at:${newUserId}`, Date.now() - (3 * 24 * 60 * 60 * 1000)); // 3 days ago
      
      // @ts-ignore - accessing private method for testing
      const risk = await amlEngine.checkAccountAge(newUserId);
      
      assert.ok(risk > 0, 'New accounts should have risk points');
      assert.ok(risk <= 15, 'New account risk should not exceed 15 points');
      
      // Cleanup
      await redis.del(`user:created_at:${newUserId}`);
    });

    it('should assign low risk to mature accounts', async () => {
      const matureUserId = `mature_user_${Date.now()}`;
      const redis = Redis.fromEnv();
      await redis.set(`user:created_at:${matureUserId}`, Date.now() - (100 * 24 * 60 * 60 * 1000)); // 100 days ago
      
      // @ts-ignore - accessing private method for testing
      const risk = await amlEngine.checkAccountAge(matureUserId);
      
      assert.strictEqual(risk, 0, 'Mature accounts should have no age risk');
      
      // Cleanup
      await redis.del(`user:created_at:${matureUserId}`);
    });
  });

  describe('SAR Generation', () => {
    it('should generate SAR report with correct structure', async () => {
      const userId = testUserId;
      const transactionIds = ['tx1', 'tx2', 'tx3'];
      const suspiciousActivities = ['Unusual transaction pattern', 'High velocity'];
      const narrative = 'User showed suspicious behavior with rapid transactions';

      const sarReport = await amlEngine.generateSAR(userId, transactionIds, suspiciousActivities, narrative);

      assert.ok(sarReport.id.startsWith('SAR_'), 'SAR ID should start with SAR_');
      assert.strictEqual(sarReport.userId, userId);
      assert.deepStrictEqual(sarReport.transactionIds, transactionIds);
      assert.deepStrictEqual(sarReport.suspiciousActivity, suspiciousActivities);
      assert.strictEqual(sarReport.narrativeDescription, narrative);
      assert.strictEqual(sarReport.status, 'PENDING');
      assert.ok(sarReport.deadline > sarReport.filingDate);
      assert.ok(sarReport.fincenForm111);
    });

    it('should store SAR report in Redis', async () => {
      const userId = testUserId;
      const sarReport = await amlEngine.generateSAR(userId, ['tx1'], ['test']);

      // Verify it's stored in Redis
      const redis = Redis.fromEnv();
      const storedSar = await redis.get<SARReport>(`sar:${sarReport.id}`);
      
      assert.ok(storedSar, 'SAR should be stored in Redis');
      assert.strictEqual(storedSar!.id, sarReport.id);
    });
  });

  describe('CTR Generation', () => {
    it('should generate CTR report for transactions over threshold', async () => {
      const userId = testUserId;
      const transactions = [
        {
          userId: testUserId,
          amount: 12000,
          fromAccount: 'acc1',
          toAccount: 'acc2',
          type: 'DEPOSIT' as const,
          ipAddress: '192.168.1.1',
          timestamp: Date.now(),
          metadata: {}
        },
        {
          userId: testUserId,
          amount: 8000,
          fromAccount: 'acc3',
          toAccount: 'acc4',
          type: 'DEPOSIT' as const,
          ipAddress: '192.168.1.1',
          timestamp: Date.now(),
          metadata: {}
        }
      ];

      const ctrReport = await amlEngine.generateCTR(userId, transactions);

      assert.ok(ctrReport.id.startsWith('CTR_'), 'CTR ID should start with CTR_');
      assert.strictEqual(ctrReport.userId, userId);
      assert.strictEqual(ctrReport.transactions.length, 2);
      assert.strictEqual(ctrReport.totalAmount, 20000);
      assert.strictEqual(ctrReport.status, 'PENDING');
      assert.ok(ctrReport.fincenForm112);
    });
  });

  describe('User Compliance Status', () => {
    it('should return LOW risk for user with no flags', async () => {
      const status = await amlEngine.getUserComplianceStatus(testUserId);
      
      assert.strictEqual(status.hasActiveSARs, false);
      assert.strictEqual(status.hasPendingCTRs, false);
      assert.strictEqual(status.riskLevel, 'LOW');
    });

    it('should return CRITICAL risk for user with active SAR', async () => {
      // Create a SAR for the user
      await amlEngine.generateSAR(testUserId, ['tx1'], ['test']);
      
      const status = await amlEngine.getUserComplianceStatus(testUserId);
      
      assert.strictEqual(status.hasActiveSARs, true);
      assert.strictEqual(status.riskLevel, 'CRITICAL');
    });

    it('should return HIGH risk for user with pending CTR', async () => {
      // Create a CTR for the user
      const transactions = [{
        userId: testUserId,
        amount: 12000,
        fromAccount: 'acc1',
        toAccount: 'acc2',
        type: 'DEPOSIT' as const,
        ipAddress: '192.168.1.1',
        timestamp: Date.now(),
        metadata: {}
      }];
      await amlEngine.generateCTR(testUserId, transactions);
      
      const status = await amlEngine.getUserComplianceStatus(testUserId);
      
      assert.strictEqual(status.hasPendingCTRs, true);
      assert.strictEqual(status.riskLevel, 'HIGH');
    });
  });

  describe('String Similarity Functions', () => {
    it('should calculate perfect similarity for identical strings', () => {
      const similarity = amlEngine.testCalculateSimilarity('TEST', 'TEST');
      assert.strictEqual(similarity, 1);
    });

    it('should calculate zero similarity for completely different strings', () => {
      const similarity = amlEngine.testCalculateSimilarity('ABC', 'XYZ');
      assert.ok(similarity < 0.1); // Very low similarity
    });

    it('should calculate high similarity for similar strings', () => {
      const similarity = amlEngine.testCalculateSimilarity('JOHN SMITH', 'JOHN SMYTH');
      assert.ok(similarity > 0.8); // High similarity despite typo
    });

    it('should calculate Levenshtein distance correctly', () => {
      // Test basic cases
      assert.strictEqual(amlEngine.testLevenshteinDistance('', ''), 0);
      assert.strictEqual(amlEngine.testLevenshteinDistance('a', ''), 1);
      assert.strictEqual(amlEngine.testLevenshteinDistance('', 'a'), 1);
      assert.strictEqual(amlEngine.testLevenshteinDistance('a', 'a'), 0);
      assert.strictEqual(amlEngine.testLevenshteinDistance('ab', 'a'), 1);
      assert.strictEqual(amlEngine.testLevenshteinDistance('a', 'ab'), 1);
      
      // Test actual distance
      assert.strictEqual(amlEngine.testLevenshteinDistance('kitten', 'sitting'), 3);
    });
  });

  describe('Error Handling', () => {
    it('should handle assessment errors gracefully', async () => {
      // Test with invalid transaction data
      const badTransaction = {
        userId: testUserId,
        amount: -1000, // Invalid negative amount
        fromAccount: '',
        toAccount: '',
        type: 'TRANSFER' as const,
        ipAddress: 'invalid-ip',
        timestamp: Date.now(),
        metadata: {}
      };

      const result = await amlEngine.assessTransaction(badTransaction);
      
      // Should return safe default values in case of error
      assert.ok(result.score >= 80, 'Errors should default to high risk');
      assert.strictEqual(result.recommendation, 'REVIEW');
      assert.ok(result.flags.includes('ASSESSMENT_ERROR'));
    });
  });
});

// Integration tests
describe('AMLEngine Integration Tests', () => {
  let amlEngine: AMLEngine;

  beforeEach(() => {
    // For integration tests, we'll use a real instance but mock external dependencies
    amlEngine = new TestAMLEngine() as any;
  });

  it('should handle full transaction flow with logging', async () => {
    const transaction = {
      userId: `integration_test_${Date.now()}`,
      amount: 5000,
      fromAccount: 'checking_123',
      toAccount: 'savings_456',
      type: 'TRANSFER' as const,
      ipAddress: '192.168.1.100',
      timestamp: Date.now(),
      metadata: { purpose: 'salary_deposit' }
    };

    const result = await amlEngine.assessTransaction(transaction);
    
    // Should return a proper risk assessment
    assert.ok(typeof result.score === 'number');
    assert.ok(result.score >= 0 && result.score <= 100);
    assert.ok(['APPROVE', 'REVIEW', 'BLOCK'].includes(result.recommendation));
    assert.ok(Array.isArray(result.factors));
    assert.ok(Array.isArray(result.flags));
  });

  it('should maintain consistent risk scoring across multiple assessments', async () => {
    const transaction = {
      userId: `consistency_test_${Date.now()}`,
      amount: 250,
      fromAccount: 'source_acc',
      toAccount: 'target_acc',
      type: 'TRANSFER' as const,
      ipAddress: '10.0.0.1',
      timestamp: Date.now(),
      metadata: {}
    };

    // Run assessment multiple times
    const results = await Promise.all([
      amlEngine.assessTransaction(transaction),
      amlEngine.assessTransaction(transaction),
      amlEngine.assessTransaction(transaction)
    ]);

    // All results should be identical for identical input
    const firstResult = results[0];
    results.forEach(result => {
      assert.strictEqual(result.score, firstResult.score);
      assert.strictEqual(result.recommendation, firstResult.recommendation);
      assert.deepStrictEqual(result.flags, firstResult.flags);
    });
  });
});

// Performance tests
describe('AMLEngine Performance Tests', () => {
  let amlEngine: TestAMLEngine;

  beforeEach(() => {
    amlEngine = new TestAMLEngine();
  });

  it('should assess transactions within performance threshold', async () => {
    const transaction = {
      userId: `perf_test_${Date.now()}`,
      amount: 100,
      fromAccount: 'from_acc',
      toAccount: 'to_acc',
      type: 'TRANSFER' as const,
      ipAddress: '192.168.1.1',
      timestamp: Date.now(),
      metadata: {}
    };

    const startTime = Date.now();
    const result = await amlEngine.assessTransaction(transaction);
    const endTime = Date.now();
    
    const duration = endTime - startTime;
    
    assert.ok(duration < 100, `Transaction assessment took ${duration}ms, which exceeds 100ms threshold`);
    assert.ok(result, 'Should return valid result');
  });

  it('should handle multiple concurrent assessments', async () => {
    const baseUserId = `concurrent_test_${Date.now()}`;
    
    const transactions = Array.from({ length: 10 }, (_, i) => ({
      userId: `${baseUserId}_${i}`,
      amount: 100 + i,
      fromAccount: `from_acc_${i}`,
      toAccount: `to_acc_${i}`,
      type: 'TRANSFER' as const,
      ipAddress: `192.168.1.${i + 1}`,
      timestamp: Date.now(),
      metadata: {}
    }));

    const startTime = Date.now();
    const results = await Promise.all(
      transactions.map(tx => amlEngine.assessTransaction(tx))
    );
    const endTime = Date.now();
    
    const duration = endTime - startTime;
    
    assert.ok(results.length === 10, 'Should process all 10 transactions');
    assert.ok(duration < 1000, `Processing 10 concurrent assessments took ${duration}ms, which seems excessive`);
    
    results.forEach(result => {
      assert.ok(typeof result.score === 'number');
      assert.ok(['APPROVE', 'REVIEW', 'BLOCK'].includes(result.recommendation));
    });
  });
});