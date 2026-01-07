import { z } from 'zod';

// User types
export interface FirebaseUser {
  uid: string;
  email?: string;
  displayName?: string;
  photoURL?: string;
  emailVerified: boolean;
  disabled: boolean;
  metadata: {
    creationTime?: string;
    lastSignInTime?: string;
  };
}

export interface Web3User {
  address: string;
  chainId: number;
  nonce: string;
  issuedAt: string;
  expirationTime?: string;
  notBefore?: string;
  requestId?: string;
  resources?: string[];
}

export interface AuthUser {
  id: string;
  type: 'firebase' | 'web3';
  firebaseUser?: FirebaseUser;
  web3User?: Web3User;
  createdAt: Date;
  lastSignInAt: Date;
  isVerified: boolean;
}

// SIWE (Sign-In With Ethereum) types
export interface SiweMessage {
  domain: string;
  address: string;
  statement?: string;
  uri: string;
  version: string;
  chainId: number;
  nonce: string;
  issuedAt: string;
  expirationTime?: string;
  notBefore?: string;
  requestId?: string;
  resources?: string[];
}

export interface SiweVerifyParams {
  message: string;
  signature: string;
}

// Session types
export interface SessionData {
  user: AuthUser;
  expiresAt: Date;
  createdAt: Date;
  csrfToken: string;
}

// Request validation schemas
export const signInSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
});

export const signUpSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  displayName: z.string().optional(),
});

export const siweMessageSchema = z.object({
  domain: z.string(),
  address: z.string().regex(/^0x[a-fA-F0-9]{40}$/, 'Invalid Ethereum address'),
  statement: z.string().optional(),
  uri: z.string(),
  version: z.string().regex(/^1\.\d+$/, 'Invalid SIWE version'),
  chainId: z.number().int().positive(),
  nonce: z.string().min(8),
  issuedAt: z.string().datetime(),
  expirationTime: z.string().datetime().optional(),
  notBefore: z.string().datetime().optional(),
  requestId: z.string().optional(),
  resources: z.array(z.string()).optional(),
});

export const siweVerifySchema = z.object({
  message: z.string(),
  signature: z.string().regex(/^0x[a-fA-F0-9]{130}$/, 'Invalid signature format'),
});

// Post-Quantum crypto types
export interface PQSignature {
  classical: string; // ECDSA signature
  postQuantum: string; // PQ signature (e.g., SPHINCS+ or Dilithium)
}

export interface PQSiweMessage {
  domain: string;
  address: string;
  statement?: string;
  uri: string;
  version: string;
  chainId: number;
  nonce: string;
  issuedAt: string;
  expirationTime?: string;
  notBefore?: string;
  requestId?: string;
  resources?: string[];
  // Post-Quantum specific fields
  pqSignature?: string;
  classicalSignature: string;
}