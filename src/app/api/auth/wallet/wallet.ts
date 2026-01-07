import jwt from 'jsonwebtoken';
import { verifyMessage } from 'ethers';
import crypto from 'crypto';

export type WalletPayload = {
  address: string;
};

function getWalletJwtSecret(): string {
  const secret = process.env.WALLET_JWT_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error('WALLET_JWT_SECRET must be at least 32 characters');
  }
  return secret;
}
const JWT_ISSUER = 'quantumiq-wallet';
const JWT_AUDIENCE = 'quantumiq-app';
const JWT_EXPIRES_IN = '30m';

/**
 * In-memory nonce store
 * NOTE: For production scale, replace with Redis or KV
 */
const nonceStore = new Map<string, { nonce: string; expires: number }>();

/**
 * Generate one-time nonce for wallet auth
 */
export function generateWalletNonce(address: string): string {
  const nonce = crypto.randomBytes(16).toString('hex');
  const expires = Date.now() + 60_000; // 60 seconds

  nonceStore.set(address.toLowerCase(), { nonce, expires });
  return nonce;
}

/**
 * Verify signed message from wallet
 */
export function verifyWalletSignature(
  address: string,
  signature: string
): boolean {
  const record = nonceStore.get(address.toLowerCase());
  if (!record) return false;

  if (Date.now() > record.expires) {
    nonceStore.delete(address.toLowerCase());
    return false;
  }

  const recovered = verifyMessage(record.nonce, signature);
  const isValid = recovered.toLowerCase() === address.toLowerCase();

  if (isValid) {
    nonceStore.delete(address.toLowerCase()); // prevent replay
  }

  return isValid;
}

/**
 * Issue JWT for wallet session
 */
export function issueWalletJwt(address: string): string {
  const payload: WalletPayload = {
    address: address.toLowerCase(),
  };

  const JWT_SECRET = getWalletJwtSecret();
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
    algorithm: 'HS256',
  });
}

/**
 * Verify wallet JWT
 */
export function verifyWalletJwt(token: string): WalletPayload | null {
  try {
    const JWT_SECRET = getWalletJwtSecret();
    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
      algorithms: ['HS256'],
    }) as unknown;
    const payload = decoded as WalletPayload;
    if (!payload || typeof payload.address !== 'string') return null;
    return payload;
  } catch {
    return null;
  }
}
