// src/lib/wallet.ts
import * as jwt from 'jsonwebtoken';

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
const nonceStore = new Map<string, { nonce: string; expiresAt: number }>();

// توابع export شده
export function generateNonce(address: string): NonceResult {
  const cleanAddress = address.toLowerCase().trim();
  const nonce = Math.random().toString(36).substring(2) + Date.now().toString(36);
  const expiresAt = Date.now() + 5 * 60 * 1000; // 5 دقیقه
  
  nonceStore.set(cleanAddress, { nonce, expiresAt });
  
  // پاک‌سازی اتوماتیک
  setTimeout(() => {
    nonceStore.delete(cleanAddress);
  }, 5 * 60 * 1000);
  
  return {
    nonce,
    message: `Login to QuantumIQ\n\nAddress: ${cleanAddress}\nNonce: ${nonce}\nExpires: ${new Date(expiresAt).toISOString()}`
  };
}

export function verifyAndConsumeNonce(address: string, providedNonce: string): boolean {
  const cleanAddress = address.toLowerCase().trim();
  const stored = nonceStore.get(cleanAddress);
  
  if (!stored || stored.nonce !== providedNonce || stored.expiresAt < Date.now()) {
    return false;
  }
  
  nonceStore.delete(cleanAddress);
  return true;
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