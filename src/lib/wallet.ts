// src/lib/wallet.ts
import * as jwt from 'jsonwebtoken';
import { Redis } from '@upstash/redis';

// Initialize Redis
const redis = Redis.fromEnv();

// تعریف types
export interface NonceResult {
  nonce: string;
  message: string;
}

export interface WalletToken {
  address: string;
  type: 'wallet';
  tenantId?: string;
  role?: string;
  iat?: number;
  exp?: number;
}

// Constants
function getWalletSecret(): string {
  const secret = process.env.WALLET_JWT_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error('WALLET_JWT_SECRET must be set (min 32 chars)');
  }
  return secret;
}
const NONCE_PREFIX = 'wallet_nonce:';
const NONCE_EXPIRATION = 5 * 60; // 5 minutes in seconds

// توابع export شده
export async function generateNonce(address: string): Promise<NonceResult> {
  const cleanAddress = address.toLowerCase().trim();
  const nonce = Math.random().toString(36).substring(2) + Date.now().toString(36);
  const expiresAt = Date.now() + 5 * 60 * 1000; // 5 دقیقه
  
  // Store nonce in Redis with expiration
  try {
    await redis.setex(`${NONCE_PREFIX}${cleanAddress}`, NONCE_EXPIRATION, nonce);
  } catch (error) {
    console.error('Failed to store nonce in Redis:', error);
    throw new Error('Failed to generate secure nonce');
  }

  return {
    nonce,
    message: `Login to QuantumIQ\n\nAddress: ${cleanAddress}\nNonce: ${nonce}\nExpires: ${new Date(expiresAt).toISOString()}`
  };
}

export async function verifyAndConsumeNonce(address: string, providedNonce: string): Promise<boolean> {
  const cleanAddress = address.toLowerCase().trim();
  
  try {
    // Get and delete nonce atomically using Redis GETDEL (available in newer versions)
    // Or use a transaction to get and delete in one operation
    const storedNonce = await redis.get(`${NONCE_PREFIX}${cleanAddress}`);
    
    if (!storedNonce || storedNonce !== providedNonce) {
      return false;
    }
    
    // Delete the nonce to prevent reuse
    await redis.del(`${NONCE_PREFIX}${cleanAddress}`);
    
    return true;
  } catch (error) {
    console.error('Nonce verification failed:', error);
    return false;
  }
}

export function createWalletJwt(address: string, options?: { tenantId?: string; role?: string }): string {
  const cleanAddress = address.toLowerCase().trim();
  
  return jwt.sign(
    {
      address: cleanAddress,
      type: 'wallet',
      tenantId: options?.tenantId || 'default',
      role: options?.role || 'user'
    } as WalletToken,
    getWalletSecret(),
    { expiresIn: '7d' }
  );
}

export function verifyWalletJwt(token: string): WalletToken | null {
  try {
    return jwt.verify(token, getWalletSecret()) as WalletToken;
  } catch (error) {
    console.error('JWT verification failed:', error);
    return null;
  }
}

// Export default برای compatibility
const walletUtils = {
  generateNonce,
  verifyAndConsumeNonce,
  createWalletJwt,
  verifyWalletJwt
};

export default walletUtils;