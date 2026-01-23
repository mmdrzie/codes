import { randomBytes } from 'crypto';

export class SecureRandom {
  /**
   * Generates a cryptographically secure random session ID
   * @param length Length in bytes (default 32 bytes = 256 bits)
   * @returns Base64URL encoded session ID
   */
  static generateSessionId(length: number = 32): string {
    const bytes = randomBytes(length);
    return bytes.toString('base64url');
  }

  /**
   * Generates a cryptographically secure random nonce
   * @param length Length in bytes (default 16 bytes = 128 bits)
   * @returns Base64URL encoded nonce
   */
  static generateNonce(length: number = 16): string {
    const bytes = randomBytes(length);
    return bytes.toString('base64url');
  }

  /**
   * Generates a cryptographically secure CSRF token
   * @param length Length in bytes (default 32 bytes = 256 bits)
   * @returns Hex-encoded CSRF token
   */
  static generateCsrfToken(length: number = 32): string {
    const bytes = randomBytes(length);
    return bytes.toString('hex');
  }

  /**
   * Generates a cryptographically secure API key
   * @param length Length in bytes (default 32 bytes = 256 bits)
   * @returns Base64URL encoded API key
   */
  static generateApiKey(length: number = 32): string {
    const bytes = randomBytes(length);
    return bytes.toString('base64url');
  }

  /**
   * Generates a UUID v4 using secure random
   * @returns RFC4122 compliant UUID v4
   */
  static generateUUIDv4(): string {
    const bytes = randomBytes(16);
    
    // Set version to 4 (random)
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    // Set variant to 10xxxxxx
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    
    const hex = bytes.toString('hex');
    return [
      hex.substr(0, 8),
      hex.substr(8, 4),
      hex.substr(12, 4),
      hex.substr(16, 4),
      hex.substr(20, 12)
    ].join('-');
  }

  /**
   * Generates a random integer within a range (inclusive)
   * @param min Minimum value (inclusive)
   * @param max Maximum value (inclusive)
   * @returns Random integer in range
   */
  static generateRandomInt(min: number, max: number): number {
    if (min >= max) {
      throw new Error('Min must be less than max');
    }

    const range = max - min + 1;
    const maxUnbiased = 256 - (256 % range);
    let rand;

    // Generate random numbers until we get one in the unbiased range
    do {
      rand = randomBytes(1)[0];
    } while (rand >= maxUnbiased);

    return (rand % range) + min;
  }

  /**
   * Generates a random string with specified character set
   * @param length Length of the string
   * @param charset Character set to use (defaults to alphanumeric)
   * @returns Random string
   */
  static generateRandomString(length: number, charset?: string): string {
    const defaultCharset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const chars = charset || defaultCharset;
    let result = '';
    
    for (let i = 0; i < length; i++) {
      const randomIndex = SecureRandom.generateRandomInt(0, chars.length - 1);
      result += chars[randomIndex];
    }
    
    return result;
  }

  /**
   * Performs statistical tests on random number generators
   * @param generator Function that generates random values
   * @param sampleSize Number of samples to test (default 10000)
   * @returns Statistical test results
   */
  static async performStatisticalTests(
    generator: () => number,
    sampleSize: number = 10000
  ): Promise<{
    mean: number;
    variance: number;
    chiSquare: number;
    pValue: number;
    passed: boolean;
  }> {
    const samples: number[] = [];
    
    // Generate samples
    for (let i = 0; i < sampleSize; i++) {
      samples.push(generator());
    }
    
    // Calculate basic statistics
    const sum = samples.reduce((acc, val) => acc + val, 0);
    const mean = sum / samples.length;
    
    const squaredDiffs = samples.map(val => Math.pow(val - mean, 2));
    const variance = squaredDiffs.reduce((acc, val) => acc + val, 0) / samples.length;
    
    // Chi-square test for uniformity (assuming values are in range 0-1)
    const numBins = Math.min(sampleSize / 10, 100); // At least 10 samples per bin
    const bins = new Array(numBins).fill(0);
    
    for (const sample of samples) {
      const binIndex = Math.min(Math.floor(sample * numBins), numBins - 1);
      bins[binIndex]++;
    }
    
    const expectedCount = sampleSize / numBins;
    const chiSquare = bins.reduce((sum, count) => sum + Math.pow(count - expectedCount, 2) / expectedCount, 0);
    
    // Approximate p-value calculation (simplified)
    // In practice, you'd look this up in a chi-square table
    const degreesOfFreedom = numBins - 1;
    const pValue = this.approximatePValue(chiSquare, degreesOfFreedom);
    
    // Pass if p-value > 0.05 (not significantly different from uniform)
    const passed = pValue > 0.05;
    
    return {
      mean,
      variance,
      chiSquare,
      pValue,
      passed
    };
  }

  /**
   * Approximates p-value for chi-square test
   * This is a simplified approximation - in practice use a proper statistical library
   */
  private static approximatePValue(chiSquare: number, degreesOfFreedom: number): number {
    // Simplified approximation - in real applications use a proper chi-square distribution calculator
    if (chiSquare < degreesOfFreedom) {
      return Math.exp(-chiSquare / 2);
    } else {
      return 1 / (1 + chiSquare / degreesOfFreedom);
    }
  }

  /**
   * Tests uniqueness of generated values
   * @param generator Function that generates random values
   * @param sampleSize Number of samples to test
   * @returns Object with uniqueness statistics
   */
  static async testUniqueness(
    generator: () => string,
    sampleSize: number = 100000
  ): Promise<{
    totalGenerated: number;
    uniqueCount: number;
    duplicateCount: number;
    duplicateRate: number;
    passed: boolean;
  }> {
    const seen = new Set<string>();
    let duplicateCount = 0;
    
    for (let i = 0; i < sampleSize; i++) {
      const value = generator();
      if (seen.has(value)) {
        duplicateCount++;
      } else {
        seen.add(value);
      }
    }
    
    const uniqueCount = seen.size;
    const duplicateRate = duplicateCount / sampleSize;
    
    // Pass if duplicate rate is acceptably low (less than 0.01%)
    const passed = duplicateRate < 0.0001;
    
    return {
      totalGenerated: sampleSize,
      uniqueCount,
      duplicateCount,
      duplicateRate,
      passed
    };
  }
}