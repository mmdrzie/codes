import { SiweMessage, SiweVerifyParams, Web3User, AuthUser } from '@/types/auth';
import { SiweResponse, verifySignature } from 'siwe';
import { cookies } from 'next/headers';
import { jwtVerify, SignJWT } from 'jose';
import { nanoid } from 'nanoid';
import { getAddress } from 'viem';

// In-memory store for nonces (in production, use Redis or database)
const nonceStore = new Map<string, { createdAt: Date; used: boolean }>();

export class SiweService {
  /**
   * Generate a new nonce for SIWE authentication
   */
  static generateNonce(): string {
    const nonce = nanoid(12); // Generate a unique nonce
    nonceStore.set(nonce, {
      createdAt: new Date(),
      used: false,
    });
    
    // Clean up expired nonces (older than 10 minutes)
    this.cleanupExpiredNonces();
    
    return nonce;
  }

  /**
   * Clean up expired nonces
   */
  private static cleanupExpiredNonces(): void {
    const now = new Date();
    for (const [nonce, data] of nonceStore.entries()) {
      // Nonces expire after 10 minutes
      if (now.getTime() - data.createdAt.getTime() > 10 * 60 * 1000) {
        nonceStore.delete(nonce);
      }
    }
  }

  /**
   * Create a SIWE message
   */
  static createSiweMessage(address: string, domain: string, nonce: string, chainId: number): SiweMessage {
    const message: SiweMessage = {
      domain,
      address,
      statement: 'Sign-In With Ethereum',
      uri: domain,
      version: '1',
      chainId,
      nonce,
      issuedAt: new Date().toISOString(),
      expirationTime: new Date(Date.now() + 10 * 60 * 1000).toISOString(), // 10 minutes
    };

    return message;
  }

  /**
   * Verify SIWE signature
   */
  static async verifySiweSignature(params: SiweVerifyParams, expectedDomain: string, expectedNonce: string): Promise<Web3User> {
    try {
      // Validate nonce hasn't been used and isn't expired
      const nonceData = nonceStore.get(expectedNonce);
      if (!nonceData) {
        throw new Error('Invalid or expired nonce');
      }
      
      if (nonceData.used) {
        throw new Error('Nonce already used (replay attack)');
      }

      // Parse the SIWE message
      const message = new SiweMessage(params.message);
      
      // Validate message fields
      if (message.nonce !== expectedNonce) {
        throw new Error('Invalid nonce in message');
      }
      
      if (message.domain !== expectedDomain) {
        throw new Error('Domain mismatch');
      }
      
      // Check if message has expired
      if (message.expirationTime && new Date(message.expirationTime) < new Date()) {
        throw new Error('Message has expired');
      }

      // Verify the signature
      const isValid = await verifySignature({
        message: params.message,
        signature: params.signature,
        address: message.address as `0x${string}`,
      });

      if (!isValid) {
        throw new Error('Invalid signature');
      }

      // Mark nonce as used to prevent replay attacks
      nonceData.used = true;

      // Create Web3User object
      const web3User: Web3User = {
        address: message.address,
        chainId: message.chainId,
        nonce: message.nonce,
        issuedAt: message.issuedAt,
        expirationTime: message.expirationTime,
        notBefore: message.notBefore,
        requestId: message.requestId,
        resources: message.resources,
      };

      return web3User;
    } catch (error: any) {
      throw new Error(`SIWE verification failed: ${error.message}`);
    }
  }

  /**
   * Create a secure session token for Web3 user
   */
  static async createSessionToken(user: Web3User, expiresIn: string = '24h'): Promise<string> {
    try {
      const token = await new SignJWT({ 
        address: user.address,
        chainId: user.chainId,
        type: 'web3'
      })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime(expiresIn)
        .setJti(nanoid()) // JWT ID for replay protection
        .sign(new TextEncoder().encode(
          process.env.WEB3_JWT_SECRET || 'default_web3_secret_for_dev'
        ));

      return token;
    } catch (error: any) {
      throw new Error(`Web3 session token creation failed: ${error.message}`);
    }
  }

  /**
   * Verify Web3 session token
   */
  static async verifySessionToken(token: string): Promise<AuthUser> {
    try {
      const secret = new TextEncoder().encode(
        process.env.WEB3_JWT_SECRET || 'default_web3_secret_for_dev'
      );
      const { payload } = await jwtVerify(token, secret);
      
      if (!payload.address) {
        throw new Error('Invalid token: missing address');
      }

      const authUser: AuthUser = {
        id: payload.address as string,
        type: 'web3',
        web3User: {
          address: payload.address as string,
          chainId: payload.chainId as number,
          nonce: '', // Not available from token
          issuedAt: new Date().toISOString(), // Use current time
        },
        createdAt: new Date(), // Use current time
        lastSignInAt: new Date(),
        isVerified: true, // Web3 users are verified by signature
      };

      return authUser;
    } catch (error: any) {
      throw new Error(`Web3 session token verification failed: ${error.message}`);
    }
  }

  /**
   * Set secure session cookie for Web3 user
   */
  static setSessionCookie(token: string): void {
    const cookieStore = cookies();
    cookieStore.set('web3_auth_session', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 24, // 24 hours
      path: '/',
    });
  }

  /**
   * Get Web3 session from cookie
   */
  static getWeb3SessionCookie(): string | undefined {
    const cookieStore = cookies();
    return cookieStore.get('web3_auth_session')?.value;
  }

  /**
   * Validate Ethereum address format
   */
  static validateEthereumAddress(address: string): boolean {
    try {
      const validAddress = getAddress(address as `0x${string}`);
      return validAddress === address;
    } catch {
      return false;
    }
  }

  /**
   * Get user session (either Firebase or Web3)
   */
  static async getUserSession(): Promise<AuthUser | null> {
    // Try Firebase session first
    const firebaseToken = this.getSessionCookie();
    if (firebaseToken) {
      try {
        return await this.verifySessionToken(firebaseToken);
      } catch (error) {
        console.error('Firebase session verification failed:', error);
      }
    }

    // Try Web3 session
    const web3Token = this.getWeb3SessionCookie();
    if (web3Token) {
      try {
        return await this.verifyWeb3SessionToken(web3Token);
      } catch (error) {
        console.error('Web3 session verification failed:', error);
      }
    }

    return null;
  }

  /**
   * Verify either Firebase or Web3 session token
   */
  static async verifySessionToken(token: string): Promise<AuthUser> {
    // Check if it's a Firebase token by trying to decode
    try {
      // Attempt to verify as Firebase token
      const firebaseService = await import('@/services/firebase-auth');
      return await firebaseService.FirebaseAuthService.verifySessionToken(token);
    } catch (firebaseError) {
      // If Firebase verification fails, try Web3 verification
      try {
        return await this.verifyWeb3SessionToken(token);
      } catch (web3Error) {
        throw new Error(`Session verification failed: Firebase - ${(firebaseError as Error).message}, Web3 - ${(web3Error as Error).message}`);
      }
    }
  }

  /**
   * Verify Web3 session token (internal method)
   */
  private static async verifyWeb3SessionToken(token: string): Promise<AuthUser> {
    try {
      const secret = new TextEncoder().encode(
        process.env.WEB3_JWT_SECRET || 'default_web3_secret_for_dev'
      );
      const { payload } = await jwtVerify(token, secret);
      
      if (!payload.address) {
        throw new Error('Invalid token: missing address');
      }

      const authUser: AuthUser = {
        id: payload.address as string,
        type: 'web3',
        web3User: {
          address: payload.address as string,
          chainId: payload.chainId as number,
          nonce: '', // Not available from token
          issuedAt: new Date().toISOString(), // Use current time
        },
        createdAt: new Date(), // Use current time
        lastSignInAt: new Date(),
        isVerified: true, // Web3 users are verified by signature
      };

      return authUser;
    } catch (error: any) {
      throw new Error(`Web3 session token verification failed: ${error.message}`);
    }
  }

  /**
   * Get session cookie (either Firebase or Web3)
   */
  static getSessionCookie(): string | undefined {
    const cookieStore = cookies();
    // Try Firebase session first, then Web3
    return cookieStore.get('auth_session')?.value || cookieStore.get('web3_auth_session')?.value;
  }
}