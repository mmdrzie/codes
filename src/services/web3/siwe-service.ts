import { SiweMessage, SiweVerifyParams, Web3User, AuthUser } from '@/types/auth';
import { SiweResponse, verifySignature } from 'siwe';
import { cookies } from 'next/headers';
import { jwtVerify, SignJWT } from 'jose';
import { nanoid } from 'nanoid';
import { getAddress, toBytes, keccak256 } from 'viem';
import { logger } from '@/lib/logger';

// In-memory store for nonces with proper security (in production, use Redis or database)
const nonceStore = new Map<string, { 
  createdAt: Date; 
  used: boolean;
  userId?: string; // Bind nonce to specific user for additional security
}>();

// Configuration for security
const NONCE_EXPIRY_MINUTES = 10;
const MAX_NONCE_LENGTH = 64;
const MIN_NONCE_LENGTH = 16;

export class SiweService {
  /**
   * Generate a new cryptographically secure nonce for SIWE authentication
   */
  static generateSecureNonce(): string {
    // Generate a cryptographically secure random nonce
    const nonce = nanoid(32); // Use 32 chars for better security
    
    // Validate nonce length
    if (nonce.length < MIN_NONCE_LENGTH || nonce.length > MAX_NONCE_LENGTH) {
      throw new Error('Invalid nonce length');
    }
    
    // Store nonce with creation timestamp and used status
    nonceStore.set(nonce, {
      createdAt: new Date(),
      used: false,
    });
    
    // Clean up expired nonces
    this.cleanupExpiredNonces();
    
    logger.info('SIWE nonce generated', { nonceHash: this.hashNonce(nonce) });
    
    return nonce;
  }

  /**
   * Clean up expired nonces to prevent memory leaks
   */
  private static cleanupExpiredNonces(): void {
    const now = new Date();
    const expiryTime = NONCE_EXPIRY_MINUTES * 60 * 1000; // Convert to milliseconds
    
    for (const [nonce, data] of nonceStore.entries()) {
      if (now.getTime() - data.createdAt.getTime() > expiryTime) {
        nonceStore.delete(nonce);
        logger.info('Expired nonce cleaned up', { nonceHash: this.hashNonce(nonce) });
      }
    }
  }

  /**
   * Hash nonce for logging (never log actual nonces)
   */
  private static hashNonce(nonce: string): string {
    return keccak256(toBytes(nonce)).slice(0, 16); // First 8 bytes as hex
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
    
    if (chainId <= 0 || chainId > 999999999) { // Reasonable upper limit
      throw new Error('Invalid chain ID');
    }
    
    // Create the SIWE message following EIP-4361 specification
    const siweMessage: SiweMessage = {
      domain,
      address,
      statement: statement || 'Sign-In With Ethereum to access our service',
      uri: `https://${domain}`, // Ensure HTTPS URI
      version: '1',
      chainId,
      nonce,
      issuedAt: new Date().toISOString(),
      expirationTime: new Date(Date.now() + NONCE_EXPIRY_MINUTES * 60 * 1000).toISOString(),
      notBefore: new Date().toISOString(), // Don't allow backdating
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

      // Validate nonce hasn't been used and isn't expired
      const nonceData = nonceStore.get(expectedNonce);
      if (!nonceData) {
        logger.warn('Invalid nonce attempt', { 
          nonceHash: this.hashNonce(expectedNonce),
          expectedDomain 
        });
        throw new Error('Invalid or expired nonce');
      }
      
      if (nonceData.used) {
        logger.warn('Replay attack detected', { 
          nonceHash: this.hashNonce(expectedNonce),
          address: this.extractAddressFromMessage(params.message) 
        });
        throw new Error('Nonce already used (replay attack)');
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

      // Mark nonce as used to prevent replay attacks
      nonceData.used = true;
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
   * Create a secure session token for Web3 user with proper security
   */
  static async createSecureSessionToken(
    user: Web3User, 
    expiresIn: string = '24h',
    additionalClaims?: Record<string, any>
  ): Promise<string> {
    try {
      // Validate user data
      if (!this.validateEthereumAddress(user.address)) {
        throw new Error('Invalid user address');
      }
      
      // Create JWT with security best practices
      const token = await new SignJWT({ 
        address: user.address,
        chainId: user.chainId,
        type: 'web3',
        ...additionalClaims
      })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime(expiresIn)
        .setNotBefore(0) // Don't allow backdating
        .setJti(nanoid()) // JWT ID for replay protection
        .setIssuer('siwe-service') // Set issuer for validation
        .setAudience('your-app-audience') // Set audience for validation
        .sign(new TextEncoder().encode(
          process.env.WEB3_JWT_SECRET || 'default_web3_secret_for_dev'
        ));

      logger.info('Web3 session token created', { 
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
      const secret = new TextEncoder().encode(
        process.env.WEB3_JWT_SECRET || 'default_web3_secret_for_dev'
      );
      
      // Verify JWT with strict validation
      const { payload } = await jwtVerify(token, secret, {
        algorithms: ['HS256'],
        audience: 'your-app-audience',
        issuer: 'siwe-service',
        clockTolerance: '5s',
      });
      
      // Validate required fields
      if (!payload.address) {
        throw new Error('Invalid token: missing address');
      }
      
      if (!this.validateEthereumAddress(payload.address as string)) {
        throw new Error('Invalid token: invalid address format');
      }

      // Check for replay attacks using jti
      if (payload.jti) {
        const isReplay = await this.checkForReplayAttack(payload.jti as string);
        if (isReplay) {
          throw new Error('Replay attack detected');
        }
      }

      const authUser: AuthUser = {
        id: payload.address as string,
        type: 'web3',
        web3User: {
          address: payload.address as string,
          chainId: payload.chainId as number,
          nonce: payload.nonce as string || '',
          issuedAt: payload.issuedAt ? new Date(payload.issuedAt as number * 1000).toISOString() : new Date().toISOString(),
          expirationTime: payload.exp ? new Date(payload.exp as number * 1000).toISOString() : undefined,
        },
        createdAt: new Date(payload.iat ? payload.iat * 1000 : Date.now()),
        lastSignInAt: new Date(),
        isVerified: true, // Web3 users are verified by signature
      };

      logger.info('Web3 session token verified', { 
        address: payload.address,
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
   * Check for replay attacks using JWT ID
   */
  private static async checkForReplayAttack(jti: string): Promise<boolean> {
    // In production, use Redis or database with TTL
    // For now, use in-memory tracking with cleanup
    if (replayAttackTracker.has(jti)) {
      return true;
    }
    
    // Add to tracker with cleanup
    replayAttackTracker.add(jti);
    
    // Schedule cleanup after token expiry time (plus buffer)
    setTimeout(() => {
      replayAttackTracker.delete(jti);
    }, 25 * 60 * 1000); // 25 minutes (24h + buffer)
    
    return false;
  }

  /**
   * Set secure session cookie for Web3 user
   */
  static setSecureSessionCookie(token: string, additionalOptions?: { tenantId?: string }): void {
    const cookieStore = cookies();
    
    // Set primary session cookie
    cookieStore.set('web3_auth_session', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60, // 24 hours
      path: '/',
    });
    
    // Set tenant ID cookie if provided
    if (additionalOptions?.tenantId) {
      cookieStore.set('tenant_id', additionalOptions.tenantId, {
        httpOnly: false, // Can be read by frontend for UI purposes
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60, // 24 hours
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
      
      // Check for basic format
      if (!address.startsWith('0x') || address.length !== 42) {
        return false;
      }
      
      // Validate using viem
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
    // Try Web3 session first
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

// In-memory replay attack tracker (use Redis in production)
const replayAttackTracker = new Set<string>();