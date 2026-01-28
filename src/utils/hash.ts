import { createHash } from 'crypto';

/**
 * Generate SHA-256 hash for model output integrity verification
 */
export function generateModelOutputHash(data: any): string {
  const jsonString = JSON.stringify(data);
  return createHash('sha256').update(jsonString).digest('hex');
}

/**
 * Verify the integrity of model output against its stored hash
 */
export function verifyModelOutputHash(data: any, expectedHash: string): boolean {
  const computedHash = generateModelOutputHash(data);
  return computedHash === expectedHash;
}