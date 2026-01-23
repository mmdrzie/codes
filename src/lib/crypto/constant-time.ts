import { timingSafeEqual } from 'crypto';

export class ConstantTime {
  /**
   * Performs a constant-time string comparison to prevent timing attacks
   */
  static compareStrings(a: string, b: string): boolean {
    // Convert strings to buffers for timingSafeEqual
    const bufA = Buffer.from(a, 'utf8');
    const bufB = Buffer.from(b, 'utf8');

    // Ensure both buffers are the same length to prevent early exits
    const maxLength = Math.max(bufA.length, bufB.length);
    const paddedA = Buffer.alloc(maxLength, 0);
    const paddedB = Buffer.alloc(maxLength, 0);

    bufA.copy(paddedA);
    bufB.copy(paddedB);

    return timingSafeEqual(paddedA, paddedB);
  }

  /**
   * Performs a constant-time buffer comparison
   */
  static compareBuffers(a: Buffer, b: Buffer): boolean {
    // Ensure both buffers are the same length to prevent early exits
    const maxLength = Math.max(a.length, b.length);
    const paddedA = Buffer.alloc(maxLength, 0);
    const paddedB = Buffer.alloc(maxLength, 0);

    a.copy(paddedA);
    b.copy(paddedB);

    return timingSafeEqual(paddedA, paddedB);
  }

  /**
   * Performs a constant-time number comparison
   */
  static compareNumbers(a: number, b: number): boolean {
    // Convert numbers to fixed-length strings to compare
    const strA = a.toString().padStart(20, '0'); // Pad to 20 characters
    const strB = b.toString().padStart(20, '0');

    return this.compareStrings(strA, strB);
  }

  /**
   * Performs constant-time password verification using timing-safe equal
   */
  static verifyPassword(inputPassword: string, storedHash: string, salt: string, hashFunction: (password: string, salt: string) => string): boolean {
    // Hash the input password with the same salt
    const inputHash = hashFunction(inputPassword, salt);

    // Use timing-safe comparison to verify the hashes
    const inputHashBuffer = Buffer.from(inputHash, 'hex');
    const storedHashBuffer = Buffer.from(storedHash, 'hex');

    // Make sure both buffers are the same length
    const maxLength = Math.max(inputHashBuffer.length, storedHashBuffer.length);
    const paddedInput = Buffer.alloc(maxLength, 0);
    const paddedStored = Buffer.alloc(maxLength, 0);

    inputHashBuffer.copy(paddedInput);
    storedHashBuffer.copy(paddedStored);

    return timingSafeEqual(paddedInput, paddedStored);
  }

  /**
   * Performs constant-time MAC (Message Authentication Code) verification
   */
  static verifyMAC(inputMac: string, expectedMac: string): boolean {
    // Use timing-safe comparison for MAC verification
    const inputBuffer = Buffer.from(inputMac, 'hex');
    const expectedBuffer = Buffer.from(expectedMac, 'hex');

    // Make sure both buffers are the same length
    const maxLength = Math.max(inputBuffer.length, expectedBuffer.length);
    const paddedInput = Buffer.alloc(maxLength, 0);
    const paddedExpected = Buffer.alloc(maxLength, 0);

    inputBuffer.copy(paddedInput);
    expectedBuffer.copy(paddedExpected);

    return timingSafeEqual(paddedInput, paddedExpected);
  }

  /**
   * A constant-time alternative to Array.includes() for sensitive comparisons
   */
  static arrayIncludesConstantTime<T extends string | number>(array: T[], searchElement: T): boolean {
    if (array.length === 0) {
      return false;
    }

    // Create a boolean result that starts as false
    let found = false;

    // Iterate through the entire array regardless of whether we find a match
    for (const element of array) {
      // Use constant-time comparison for each element
      let isEqual = false;
      
      if (typeof element === 'string' && typeof searchElement === 'string') {
        isEqual = ConstantTime.compareStrings(element, searchElement);
      } else if (typeof element === 'number' && typeof searchElement === 'number') {
        isEqual = ConstantTime.compareNumbers(element, searchElement);
      } else {
        // For mixed types, convert to string and compare
        isEqual = ConstantTime.compareStrings(String(element), String(searchElement));
      }

      // Use bitwise OR to combine results without branching
      found = found || isEqual;
    }

    return found;
  }

  /**
   * Delays execution for a constant time to obscure processing time differences
   */
  static async constantDelay(minExecutionTimeMs: number, fn: () => Promise<any>): Promise<any> {
    const startTime = process.hrtime.bigint();
    
    try {
      const result = await fn();
      return result;
    } finally {
      const endTime = process.hrtime.bigint();
      const executionTimeNs = Number(endTime - startTime) / 1000000; // Convert to milliseconds
      
      if (executionTimeNs < minExecutionTimeMs) {
        // Delay for the remaining time to reach the minimum
        const remainingTime = minExecutionTimeMs - executionTimeNs;
        await new Promise(resolve => setTimeout(resolve, remainingTime));
      }
    }
  }
}