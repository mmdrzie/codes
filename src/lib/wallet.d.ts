// src/lib/wallet.d.ts
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

export declare function generateNonce(address: string): NonceResult;
export declare function verifyAndConsumeNonce(address: string, nonce: string): boolean;
export declare function createWalletJwt(address: string, options?: { tenantId?: string; role?: string }): string;
export declare function verifyWalletJwt(token: string): WalletToken | null;