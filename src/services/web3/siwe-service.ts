import { SiweMessage, SiweVerifyParams, Web3User, AuthUser } from '@/types/auth';
import { verifySignature } from 'siwe';
import { cookies } from 'next/headers';
import { getAddress, toBytes, keccak256 } from 'viem';
import { logger } from '@/lib/logger';
import { generateAccessToken, AppJwtPayload } from '@/lib/tokenUtils';
import { getEnterpriseRedisClient } from '@/infrastructure/redis/enterprise-redis-client';
import { EnterpriseSiweNonceStore } from '@/core/auth/enterprise-siwe-nonce-store';

// Enterprise nonce store instance (Redis-backed, fail-closed)
const redisClient = getEnterpriseRedisClient();
const enterpriseNonceStore = new EnterpriseSiweNonceStore(redisClient);

// Configuration for security
const NONCE_EXPIRY_MINUTES = 10;
const MAX_NONCE_LENGTH = 64;
const MIN_NONCE_LENGTH = 16;

export class SiweService {
  /**
   * Generate a new cryptographically secure nonce for SIWE authentication
   * Uses enterprise Redis-backed nonce store (FAILS CLOSED if Redis unavailable)
   */
  static async generateSecureNonce(address: string): Promise<{ nonce: string; message: string; expiresAt: number }> {
    // Validate address format
    const lowerAddress = address.toLowerCase();
    if (!/^0x[a-fA-F0-9]{40}$/.test(lowerAddress)) {
      throw new Error('Invalid Ethereum address format');
    }

    // Use enterprise nonce store - FAILS CLOSED if Redis unavailable
    const result = await enterpriseNonceStore.generateAndStoreNonce(lowerAddress);

    logger.info('SIWE nonce generated via enterprise store', { 
      address: lowerAddress.slice(0, 8),
      expiresAt: new Date(result.expiresAt).toISOString()
    });

    return result;
  }

  /**
   * Verify and consume nonce atomically (prevents replay attacks)
   * Uses enterprise Redis-backed nonce store with Lua scripts
   */
  static async verifyAndConsumeNonce(address: string, nonce: string): Promise<boolean> {
    const lowerAddress = address.toLowerCase();
    
    // Use enterprise nonce store - atomic verify & consume via Lua script
    const result = await enterpriseNonceStore.verifyAndConsumeNonce(lowerAddress, nonce);
    
    return result.success;
  }

  /**
   * Hash nonce for logging (never log actual nonces)
   */
  private static hashNonce(nonce: string): string {
    return keccak256(toBytes(nonce)).slice(0, 16);
  }

  /**
   * Create a secure SIWE message with proper validation
   */
  static createSecureSiweMessage(
    address: string,
    domain: string,
    nonce: string,
    chainId: number,
    statement?: string
  ): SiweMessage {
    // Validate inputs
    if (!this.validateEthereumAddress(address)) {
      throw new Error('Invalid Ethereum address');
    }

    if (!domain || domain.length < 3 || domain.length > 255) {
      throw new Error('Invalid domain');
    }

    if (nonce.length < MIN_NONCE_LENGTH || nonce.length > MAX_NONCE_LENGTH) {
      throw new Error('Invalid nonce length');
    }

    if (chainId <= 0 || chainId > 999999999) {
      throw new Error('Invalid chain ID');
    }

    const siweMessage: SiweMessage = {
      domain,
      address,
      statement: statement || 'Sign-In With Ethereum to access our service',
      uri: `https://${domain}`,
      version: '1',
      chainId,
      nonce,
      issuedAt: new Date().toISOString(),
      expirationTime: new Date(Date.now() + NONCE_EXPIRY_MINUTES * 60 * 1000).toISOString(),
      notBefore: new Date().toISOString(),
    };

    return siweMessage;
  }

  /**
   * Verify SIWE signature with comprehensive security checks
   */
  static async verifySiweSignature(
    params: SiweVerifyParams,
    expectedDomain: string,
    expectedNonce: string
  ): Promise<Web3User> {
    try {
      // Input validation
      if (!params.message || !params.signature) {
        throw new Error('Missing required SIWE parameters');
      }

      if (!expectedDomain || !expectedNonce) {
        throw new Error('Missing expected domain or nonce');
      }

      // CRITICAL: Verify and consume nonce atomically using enterprise store
      const nonceValid = await this.verifyAndConsumeNonce(
        this.extractAddressFromMessage(params.message) || '',
        expectedNonce
      );

      if (!nonceValid) {
        logger.warn('Invalid or replayed nonce attempt', {
          nonceHash: this.hashNonce(expectedNonce),
          expectedDomain
        });
        throw new Error('Invalid or replayed nonce');
      }

      // Parse the SIWE message
      let message: SiweMessage;
      try {
        message = new SiweMessage(params.message);
      } catch (parseError) {
        logger.warn('Invalid SIWE message format', {
          error: (parseError as Error).message,
          message: params.message
        });
        throw new Error('Invalid SIWE message format');
      }

      // Validate message fields with strict checks
      if (message.nonce !== expectedNonce) {
        logger.warn('Nonce mismatch', {
          expected: expectedNonce,
          actual: message.nonce
        });
        throw new Error('Invalid nonce in message');
      }

      if (message.domain !== expectedDomain) {
        logger.warn('Domain mismatch', {
          expected: expectedDomain,
          actual: message.domain
        });
        throw new Error('Domain mismatch');
      }

      // Validate address format
      if (!this.validateEthereumAddress(message.address)) {
        logger.warn('Invalid address in SIWE message', { address: message.address });
        throw new Error('Invalid Ethereum address in message');
      }

      // Check if message has expired
      if (message.expirationTime && new Date(message.expirationTime) < new Date()) {
        logger.warn('SIWE message expired', {
          expirationTime: message.expirationTime,
          issuedAt: message.issuedAt
        });
        throw new Error('SIWE message has expired');
      }

      // Check if message is not yet valid
      if (message.notBefore && new Date(message.notBefore) > new Date()) {
        logger.warn('SIWE message not yet valid', {
          notBefore: message.notBefore,
          currentTime: new Date().toISOString()
        });
        throw new Error('SIWE message is not yet valid');
      }

      // Verify the signature using the SIWE library
      const isValid = await verifySignature({
        message: params.message,
        signature: params.signature,
        address: message.address as `0x${string}`,
      });

      if (!isValid) {
        logger.warn('Invalid SIWE signature', {
          address: message.address,
          domain: message.domain
        });
        throw new Error('Invalid SIWE signature');
      }

      logger.info('SIWE signature verified successfully', {
        address: message.address,
        domain: message.domain,
        nonceHash: this.hashNonce(expectedNonce)
      });

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
      logger.error('SIWE verification failed', {
        error: error.message,
        stack: error.stack
      });
      throw new Error(`SIWE verification failed: ${error.message}`);
    }
  }

  /**
   * Extract address from SIWE message (helper for logging)
   */
  private static extractAddressFromMessage(message: string): string | null {
    try {
      const lines = message.split('\n');
      for (const line of lines) {
        if (line.startsWith('0x') && line.length === 42) {
          return line;
        }
      }
      return null;
    } catch {
      return null;
    }
  }

  /**
   * Create a secure session token for Web3 user with post-quantum security
   */
  static async createSecureSessionToken(
    user: Web3User,
    deviceFingerprint?: { userAgent?: string; ipAddress?: string; sessionId?: string },
    additionalClaims?: Record<string, any>
  ): Promise<string> {
    try {
      // Validate user data
      if (!this.validateEthereumAddress(user.address)) {
        throw new Error('Invalid user address');
      }

      // Prepare the payload for the new token system
      const tokenPayload = {
        userId: user.address,
        walletAddress: user.address,
        chainId: user.chainId,
        authMethod: 'wallet' as const,
        type: 'access' as const,
        ...additionalClaims
      };

      // Generate access token using post-quantum crypto
      const token = await generateAccessToken(tokenPayload, deviceFingerprint);

      logger.info('Web3 session token created with PQ security', {
        address: user.address,
        chainId: user.chainId
      });

      return token;
    } catch (error: any) {
      logger.error('Web3 session token creation failed', {
        error: error.message,
        address: user.address
      });
      throw new Error(`Web3 session token creation failed: ${error.message}`);
    }
  }

  /**
   * Verify Web3 session token with comprehensive validation
   */
  static async verifySecureSessionToken(token: string): Promise<AuthUser> {
    try {
      const { verifyAccessToken } = await import('@/lib/tokenUtils');
      const payload = await verifyAccessToken(token);

      if (!payload) {
        throw new Error('Invalid token: failed post-quantum verification');
      }

      // Validate required fields
      if (!payload.userId) {
        throw new Error('Invalid token: missing address');
      }

      if (!this.validateEthereumAddress(payload.userId as string)) {
        throw new Error('Invalid token: invalid address format');
      }

      const authUser: AuthUser = {
        id: payload.userId as string,
        type: 'web3',
        web3User: {
          address: payload.userId as string,
          chainId: payload.chainId as number,
          nonce: payload.nonce as string || '',
          issuedAt: payload.issuedAt ? new Date(payload.issuedAt as number * 1000).toISOString() : new Date().toISOString(),
          expirationTime: payload.exp ? new Date(payload.exp as number * 1000).toISOString() : undefined,
        },
        createdAt: new Date(payload.iat ? payload.iat * 1000 : Date.now()),
        lastSignInAt: new Date(),
        isVerified: true,
      };

      logger.info('Web3 session token verified with PQ security', {
        address: payload.userId,
        userId: authUser.id
      });

      return authUser;
    } catch (error: any) {
      logger.error('Web3 session token verification failed', {
        error: error.message,
        stack: error.stack
      });
      throw new Error(`Web3 session token verification failed: ${error.message}`);
    }
  }

  /**
   * Set secure session cookie for Web3 user
   */
  static setSecureSessionCookie(token: string, additionalOptions?: { tenantId?: string }): void {
    const cookieStore = cookies();

    cookieStore.set('web3_auth_session', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60,
      path: '/',
    });

    if (additionalOptions?.tenantId) {
      cookieStore.set('tenant_id', additionalOptions.tenantId, {
        httpOnly: false,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60,
        path: '/',
      });
    }
  }

  /**
   * Get Web3 session from cookie
   */
  static getWeb3SessionCookie(): string | undefined {
    const cookieStore = cookies();
    return cookieStore.get('web3_auth_session')?.value;
  }

  /**
   * Validate Ethereum address format with additional security checks
   */
  static validateEthereumAddress(address: string): boolean {
    try {
      if (!address || typeof address !== 'string') {
        return false;
      }

      if (!address.startsWith('0x') || address.length !== 42) {
        return false;
      }

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
    const web3Token = this.getWeb3SessionCookie();
    if (web3Token) {
      try {
        return await this.verifySecureSessionToken(web3Token);
      } catch (error) {
        logger.warn('Web3 session verification failed', {
          error: (error as Error).message
        });
      }
    }

    return null;
  }

  /**
   * Get session cookie (Web3 only for this service)
   */
  static getSessionCookie(): string | undefined {
    const cookieStore = cookies();
    return cookieStore.get('web3_auth_session')?.value;
  }
}
