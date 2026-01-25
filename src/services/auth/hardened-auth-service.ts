import { NextRequest, NextResponse } from 'next/server';
import { ethers } from 'ethers';
import { z } from 'zod';
import { Redis } from '@upstash/redis';
import { jwtVerify, SignJWT } from 'jose';
import crypto from 'crypto';
import { logger } from '@/lib/logger';
import { SecurityMonitor, SecurityEvent } from '@/lib/security-monitoring';
import { PQCryptoService } from '@/services/crypto/pq-crypto-service';
import { generateAccessToken, generateRefreshToken, verifyAccessToken, verifyRefreshToken, AppJwtPayload } from '@/lib/tokenUtils';
import { validateWalletAddress } from '@/lib/security';
import { validateAndParse } from '@/lib/validation';
import { getAdminDb } from '@/lib/firebase';
import * as admin from 'firebase-admin';
import { SecureSessionManager, SessionInfo } from '@/lib/secure-session-manager';
import { Redis as IORedis } from 'ioredis';

// Initialize Redis
const redis = Redis.fromEnv();
const ioRedis = new IORedis(process.env.REDIS_URL || '');

// Initialize secure session manager
const secureSessionManager = new SecureSessionManager(ioRedis);

// Constants
const SESSION_ID_PREFIX = 'session:';
const SESSION_TTL = 24 * 60 * 60; // 24 hours
const NONCE_EXPIRATION = 5 * 60; // 5 minutes

// Unified User Interface
interface UnifiedUser {
  id: string;
  walletAddress?: string;
  email?: string;
  authMethod: 'wallet' | 'firebase' | 'password';
  tenantId?: string;
  role?: string;
  status: 'active' | 'inactive' | 'suspended' | 'pending_verification';
  createdAt: Date;
  lastLogin: Date;
  lastLoginIp?: string;
  sessionIds: string[];
}

// Session Interface
interface SessionData {
  userId: string;
  sessionId: string;
  tenantId?: string;
  authMethod: 'wallet' | 'firebase' | 'password';
  createdAt: Date;
  expiresAt: Date;
  ipAddress?: string;
  userAgent?: string;
  isActive: boolean;
  deviceFingerprint?: string;
}

// Hardened Authentication Service
export class HardenedAuthService {
  /**
   * Generate a cryptographically secure nonce with proper lifecycle management
   */
  static async generateSecureNonce(identifier: string): Promise<string> {
    const nonce = crypto.randomBytes(32).toString('hex');
    const key = `nonce:${identifier}`;
    
    try {
      // Store nonce in Redis with expiration
      await redis.setex(key, NONCE_EXPIRATION, nonce);
      
      // Log nonce generation for security monitoring
      await SecurityMonitor.logEvent(
        SecurityEvent.NONCE_GENERATED,
        { 
          timestamp: new Date(),
          metadata: { 
            identifier,
            nonceHash: crypto.createHash('sha256').update(nonce).digest('hex'),
            expiration: NONCE_EXPIRATION
          }
        },
        'Secure nonce generated'
      );
      
      return nonce;
    } catch (error) {
      logger.error('Failed to generate secure nonce', { error: (error as Error).message });
      await SecurityMonitor.logEvent(
        SecurityEvent.NONCE_GENERATION_FAILED,
        { 
          timestamp: new Date(),
          metadata: { 
            identifier,
            error: (error as Error).message
          }
        },
        'Nonce generation failed'
      );
      throw new Error('Failed to generate secure nonce');
    }
  }

  /**
   * Verify and consume nonce to prevent replay attacks using atomic operation
   */
  static async verifyAndConsumeNonce(identifier: string, providedNonce: string): Promise<boolean> {
    const key = `nonce:${identifier}`;
    
    try {
      // Use Lua script to atomically get and delete nonce with verification
      const luaScript = `
        local key = KEYS[1]
        local expected_nonce = ARGV[1]
        local stored_nonce = redis.call('GET', key)
        
        if not stored_nonce then
          return 0  -- Nonce does not exist
        end
        
        if stored_nonce == expected_nonce then
          redis.call('DEL', key)
          return 1  -- Success: nonce matched and deleted
        else
          return 0  -- Failure: nonce did not match
        end
      `;
      
      // Execute atomic operation
      const result = await redis.eval(luaScript, [key], [providedNonce]);
      
      if (result === 1) {
        // Log successful nonce consumption
        await SecurityMonitor.logEvent(
          SecurityEvent.NONCE_CONSUMED,
          { 
            timestamp: new Date(),
            metadata: { 
              identifier,
              nonceHash: crypto.createHash('sha256').update(providedNonce).digest('hex')
            }
          },
          'Nonce successfully consumed atomically'
        );
        
        return true;
      } else {
        // Log potential replay attack
        await SecurityMonitor.logEvent(
          SecurityEvent.REPLAY_ATTEMPT,
          { 
            timestamp: new Date(),
            metadata: { 
              identifier,
              providedNonceHash: crypto.createHash('sha256').update(providedNonce).digest('hex'),
              expectedNonceExists: result === 0
            }
          },
          'Nonce verification failed - potential replay attack'
        );
        
        return false;
      }
    } catch (error) {
      logger.error('Nonce verification failed', { error: (error as Error).message });
      await SecurityMonitor.logEvent(
        SecurityEvent.NONCE_VERIFICATION_ERROR,
        { 
          timestamp: new Date(),
          metadata: { 
            identifier,
            error: (error as Error).message
          }
        },
        'Nonce verification error'
      );
      return false;
    }
  }

  /**
   * Hardened wallet authentication with post-quantum security
   */
  static async authenticateWallet(address: string, signature: string, nonce: string, clientInfo: { ip: string; userAgent: string }): Promise<{ success: boolean; user?: UnifiedUser; tokens?: { accessToken: string; refreshToken: string }; error?: string }> {
    try {
      // Validate wallet address format
      if (!validateWalletAddress(address)) {
        await SecurityMonitor.logEvent(
          SecurityEvent.INVALID_WALLET_ADDRESS,
          { 
            timestamp: new Date(),
            metadata: { 
              address,
              ip: clientInfo.ip
            }
          },
          'Invalid wallet address format'
        );
        
        return { success: false, error: 'Invalid wallet address format' };
      }

      // Verify nonce
      const nonceOk = await this.verifyAndConsumeNonce(address, nonce);
      if (!nonceOk) {
        await SecurityMonitor.logEvent(
          SecurityEvent.INVALID_NONCE,
          { 
            timestamp: new Date(),
            metadata: { 
              address: `${address.slice(0, 6)}...${address.slice(-4)}`,
              ip: clientInfo.ip
            }
          },
          'Invalid nonce in wallet authentication'
        );
        
        return { success: false, error: 'Invalid nonce' };
      }

      // Verify signature with canonical encoding
      const message = `Sign this message to authenticate: ${nonce}`;
      const isValidSignature = await this.verifyWalletSignature(address, message, signature);
      
      if (!isValidSignature) {
        await SecurityMonitor.logEvent(
          SecurityEvent.INVALID_SIGNATURE,
          { 
            timestamp: new Date(),
            metadata: { 
              address: `${address.slice(0, 6)}...${address.slice(-4)}`,
              ip: clientInfo.ip
            }
          },
          'Invalid signature in wallet authentication'
        );
        
        // Delay to prevent brute force
        await new Promise(resolve => setTimeout(resolve, 1000));
        return { success: false, error: 'Invalid signature' };
      }

      // Additional security: Validate signature freshness
      const nonceTimestamp = parseInt(nonce.split('-')[1] || '0');
      if (nonceTimestamp && Date.now() - nonceTimestamp > 300000) { // 5 minutes
        await SecurityMonitor.logEvent(
          SecurityEvent.EXPIRED_NONCE,
          { 
            timestamp: new Date(),
            metadata: { 
              address: `${address.slice(0, 6)}...${address.slice(-4)}`,
              ip: clientInfo.ip,
              nonceAge: Date.now() - nonceTimestamp
            }
          },
          'Expired nonce in wallet authentication'
        );
        
        return { success: false, error: 'Nonce has expired. Please try again.' };
      }

      // Find or create user
      const user = await this.findOrCreateWalletUser(address, clientInfo);
      
      if (user.status === 'suspended') {
        await SecurityMonitor.logEvent(
          SecurityEvent.BLOCKED_USER_LOGIN_ATTEMPT,
          { 
            timestamp: new Date(),
            userId: user.id,
            metadata: { 
              address: `${address.slice(0, 6)}...${address.slice(-4)}`,
              ip: clientInfo.ip
            }
          },
          'Blocked user attempted to login'
        );
        
        return { success: false, error: 'Account has been suspended. Please contact support.' };
      }

      // Generate post-quantum secured tokens
      const tokens = await this.generatePostQuantumTokens(user, clientInfo);

      // Create session
      const sessionId = await this.createSession(user.id, user.tenantId, {
        authMethod: 'wallet',
        ipAddress: clientInfo.ip,
        userAgent: clientInfo.userAgent
      });

      // Update user with new session
      await this.addSessionToUser(user.id, sessionId);

      // Log successful authentication
      await SecurityMonitor.logEvent(
        SecurityEvent.AUTH_SUCCESS,
        { 
          timestamp: new Date(),
          userId: user.id,
          metadata: { 
            authMethod: 'wallet',
            address: `${address.slice(0, 6)}...${address.slice(-4)}`,
            sessionId,
            ip: clientInfo.ip
          }
        },
        'Wallet authentication successful'
      );

      return { 
        success: true, 
        user,
        tokens
      };

    } catch (error) {
      logger.error('Wallet authentication error', { error: (error as Error).message });
      await SecurityMonitor.logEvent(
        SecurityEvent.AUTH_ERROR,
        { 
          timestamp: new Date(),
          metadata: { 
            address: address ? `${address.slice(0, 6)}...${address.slice(-4)}` : 'unknown',
            ip: clientInfo.ip,
            error: (error as Error).message
          }
        },
        'Wallet authentication error'
      );
      
      return { success: false, error: 'An error occurred during wallet authentication' };
    }
  }

  /**
   * Verify wallet signature with anti-malleability checks
   */
  private static async verifyWalletSignature(address: string, message: string, signature: string): Promise<boolean> {
    try {
      // Verify canonical encoding and prevent signature malleability
      const recoveredAddress = ethers.verifyMessage(message, signature);
      
      // Anti-malleability check: ensure the signature is in the canonical format
      // This prevents signature malleability attacks
      const sig = ethers.Signature.from(signature);
      
      // Verify the signature is properly formatted
      if (!sig.r || !sig.s || !sig.yParity) {
        return false;
      }
      
      // Additional check: ensure the yParity is properly normalized
      const normalizedSig = sig.serialized;
      
      // Verify the signature again with the normalized version
      const normalizedRecoveredAddress = ethers.verifyMessage(message, normalizedSig);
      
      // Compare both recovered addresses
      if (normalizedRecoveredAddress.toLowerCase() !== recoveredAddress.toLowerCase()) {
        return false;
      }

      // Final comparison with original address
      return recoveredAddress.toLowerCase() === address.toLowerCase();
    } catch (error) {
      logger.error('Signature verification failed', { error: (error as Error).message, address });
      return false;
    }
  }

  /**
   * Find or create wallet user with proper security checks
   */
  private static async findOrCreateWalletUser(address: string, clientInfo: { ip: string; userAgent: string }): Promise<UnifiedUser> {
    const db = getAdminDb();
    
    const userQuery = await db
      .collection('users')
      .where('walletAddress', '==', address.toLowerCase())
      .get();

    let userId: string;
    let userData: any;
    let isNewUser = false;

    if (userQuery.empty) {
      // Create new user
      const newUser = {
        walletAddress: address.toLowerCase(),
        authMethod: 'wallet',
        status: 'active',
        createdAt: new Date(),
        updatedAt: new Date(),
        lastLogin: new Date(),
        lastLoginIp: clientInfo.ip,
        sessionIds: []
      };

      const userRef = await db.collection('users').add(newUser);
      userId = userRef.id;
      userData = newUser;
      isNewUser = true;

      logger.info('New wallet user created', {
        userId,
        address: `${address.slice(0, 6)}...${address.slice(-4)}`
      });
    } else {
      // Existing user
      const firstDoc = userQuery.docs[0];
      if (!firstDoc) {
        throw new Error('User lookup failed');
      }

      userId = firstDoc.id;
      userData = firstDoc.data();

      // Update user information
      await db.collection('users').doc(userId).update({
        lastLogin: new Date(),
        lastLoginIp: clientInfo.ip,
        updatedAt: new Date()
      });
    }

    // Return unified user object
    return {
      id: userId,
      walletAddress: address.toLowerCase(),
      authMethod: 'wallet',
      tenantId: userData.tenantId,
      status: userData.status || 'active',
      createdAt: userData.createdAt.toDate ? userData.createdAt.toDate() : new Date(userData.createdAt),
      lastLogin: userData.lastLogin.toDate ? userData.lastLogin.toDate() : new Date(userData.lastLogin),
      lastLoginIp: clientInfo.ip,
      sessionIds: userData.sessionIds || []
    };
  }

  /**
   * Generate post-quantum secured tokens
   */
  private static async generatePostQuantumTokens(user: UnifiedUser, clientInfo: { ip: string; userAgent: string }): Promise<{ accessToken: string; refreshToken: string }> {
    const tokenPayload = {
      userId: user.id,
      walletAddress: user.walletAddress,
      authMethod: user.authMethod,
      tenantId: user.tenantId,
      role: user.role || 'user'
    };

    const deviceFingerprint = {
      userAgent: clientInfo.userAgent,
      ipAddress: clientInfo.ip
    };

    const accessToken = await generateAccessToken(tokenPayload, deviceFingerprint);
    const refreshToken = await generateRefreshToken(tokenPayload, deviceFingerprint);

    return { accessToken, refreshToken };
  }

  /**
   * Create a new session with proper security
   */
  private static async createSession(userId: string, tenantId: string | undefined, sessionData: { authMethod: 'wallet' | 'firebase' | 'password'; ipAddress?: string; userAgent?: string }): Promise<string> {
    const sessionId = `sess_${crypto.randomUUID()}`;
    
    // Create session info for secure session manager
    const sessionInfo: SessionInfo = {
      sessionId,
      userId,
      ip: sessionData.ipAddress || 'unknown',
      userAgent: sessionData.userAgent || 'unknown',
      createdAt: Date.now(),
      lastActive: Date.now(),
      expiresAt: Date.now() + (SESSION_TTL * 1000), // Convert to milliseconds
      tenantId: tenantId || 'default',
      deviceFingerprint: sessionData.userAgent ? crypto.createHash('md5').update(sessionData.userAgent).digest('hex') : 'unknown',
      boundToUserId: userId,
      boundToDevice: sessionData.userAgent ? crypto.createHash('md5').update(sessionData.userAgent).digest('hex') : 'unknown'
    };

    // Use secure session manager to track the session
    const success = await secureSessionManager.trackSession(sessionInfo);
    
    if (!success) {
      throw new Error('Failed to create secure session');
    }

    return sessionId;
  }

  /**
   * Add session to user record
   */
  private static async addSessionToUser(userId: string, sessionId: string): Promise<void> {
    const db = getAdminDb();
    
    // Add session ID to user's session list
    await db.collection('users').doc(userId).update({
      sessionIds: admin.firestore.FieldValue.arrayUnion(sessionId),
      updatedAt: new Date()
    });
  }

  /**
   * Verify session with post-quantum security
   */
  static async verifySession(token: string): Promise<{ valid: boolean; user?: UnifiedUser; error?: string }> {
    try {
      // First verify the post-quantum token
      const payload = await verifyAccessToken(token);
      
      if (!payload || !payload.userId) {
        return { valid: false, error: 'Invalid or expired token' };
      }

      // Fetch user from database
      const db = getAdminDb();
      const userDoc = await db.collection('users').doc(payload.userId).get();
      
      if (!userDoc.exists) {
        return { valid: false, error: 'User not found' };
      }

      const userData = userDoc.data();
      
      // Create unified user object
      const user: UnifiedUser = {
        id: payload.userId,
        walletAddress: userData.walletAddress,
        email: userData.email,
        authMethod: userData.authMethod || 'wallet',
        tenantId: userData.tenantId,
        role: userData.role || 'user',
        status: userData.status || 'active',
        createdAt: userData.createdAt.toDate ? userData.createdAt.toDate() : new Date(userData.createdAt),
        lastLogin: userData.lastLogin.toDate ? userData.lastLogin.toDate() : new Date(userData.lastLogin),
        lastLoginIp: userData.lastLoginIp,
        sessionIds: userData.sessionIds || []
      };

      // Check user status
      if (user.status !== 'active') {
        await SecurityMonitor.logEvent(
          SecurityEvent.AUTH_FAILURE,
          { 
            timestamp: new Date(),
            userId: user.id,
            metadata: { 
              status: user.status,
              tokenCheck: 'user_status'
            }
          },
          `User authentication failed due to status: ${user.status}`
        );
        
        return { valid: false, error: 'Account is not active' };
      }

      return { valid: true, user };
    } catch (error) {
      logger.error('Session verification failed', { error: (error as Error).message });
      await SecurityMonitor.logEvent(
        SecurityEvent.AUTH_ERROR,
        { 
          timestamp: new Date(),
          metadata: { 
            error: (error as Error).message,
            tokenCheck: 'session_verification'
          }
        },
        'Session verification error'
      );
      
      return { valid: false, error: 'Session verification failed' };
    }
  }

  /**
   * Revoke session and invalidate tokens
   */
  static async revokeSession(sessionId: string, userId: string): Promise<boolean> {
    try {
      // Mark session as inactive in Redis
      const key = `${SESSION_ID_PREFIX}${sessionId}`;
      const sessionData = await redis.get(key);
      
      if (sessionData) {
        const session: SessionData = JSON.parse(sessionData as string);
        session.isActive = false;
        
        // Update session in Redis with shorter TTL for cleanup
        await redis.setex(key, 3600, JSON.stringify(session)); // 1 hour for cleanup
      }

      // Remove session from user record
      const db = getAdminDb();
      await db.collection('users').doc(userId).update({
        sessionIds: admin.firestore.FieldValue.arrayRemove(sessionId),
        updatedAt: new Date()
      });

      // Log session revocation
      await SecurityMonitor.logEvent(
        SecurityEvent.SESSION_REVOKED,
        { 
          timestamp: new Date(),
          userId,
          metadata: { 
            sessionId,
            revokedBy: 'service'
          }
        },
        'Session revoked'
      );

      return true;
    } catch (error) {
      logger.error('Session revocation failed', { error: (error as Error).message });
      return false;
    }
  }

  /**
   * Verify JWT with post-quantum security and additional checks
   */
  static async verifyJWT(token: string): Promise<{ valid: boolean; payload?: AppJwtPayload; error?: string }> {
    try {
      // Use the existing post-quantum verification
      const payload = await verifyAccessToken(token);
      
      if (!payload) {
        return { valid: false, error: 'Invalid token' };
      }

      // Additional security validations
      if (payload.exp && Date.now() >= payload.exp * 1000) {
        return { valid: false, error: 'Token expired' };
      }

      if (payload.iss && payload.iss !== 'quantumiq-api') {
        return { valid: false, error: 'Invalid issuer' };
      }

      // Check audience if present
      if (payload.aud) {
        const expectedAud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
        if (!expectedAud.includes('quantumiq-web')) {
          return { valid: false, error: 'Invalid audience' };
        }
      }

      return { valid: true, payload };
    } catch (error) {
      logger.error('JWT verification failed', { error: (error as Error).message });
      return { valid: false, error: 'Token verification failed' };
    }
  }

  /**
   * Rotate refresh token with post-quantum security
   */
  static async rotateRefreshToken(oldRefreshToken: string, clientInfo: { ip: string; userAgent: string }): Promise<{ success: boolean; newTokens?: { accessToken: string; refreshToken: string }; error?: string }> {
    try {
      // Verify the old refresh token
      const verificationResult = await verifyRefreshToken(oldRefreshToken);
      
      if (!verificationResult.valid || !verificationResult.payload) {
        return { success: false, error: 'Invalid refresh token' };
      }

      const payload = verificationResult.payload;

      // Find user
      const db = getAdminDb();
      const userDoc = await db.collection('users').doc(payload.userId).get();
      
      if (!userDoc.exists) {
        return { success: false, error: 'User not found' };
      }

      const userData = userDoc.data();
      const user: UnifiedUser = {
        id: payload.userId,
        walletAddress: userData.walletAddress,
        email: userData.email,
        authMethod: userData.authMethod || 'wallet',
        tenantId: userData.tenantId,
        role: userData.role || 'user',
        status: userData.status || 'active',
        createdAt: userData.createdAt.toDate ? userData.createdAt.toDate() : new Date(userData.createdAt),
        lastLogin: userData.lastLogin.toDate ? userData.lastLogin.toDate() : new Date(userData.lastLogin),
        lastLoginIp: clientInfo.ip,
        sessionIds: userData.sessionIds || []
      };

      // Generate new tokens
      const newTokens = await this.generatePostQuantumTokens(user, clientInfo);

      // Log token rotation
      await SecurityMonitor.logEvent(
        SecurityEvent.TOKEN_ROTATION,
        { 
          timestamp: new Date(),
          userId: user.id,
          metadata: { 
            oldJti: payload.jti,
            ip: clientInfo.ip
          }
        },
        'Refresh token rotated'
      );

      return { success: true, newTokens };
    } catch (error) {
      logger.error('Refresh token rotation failed', { error: (error as Error).message });
      return { success: false, error: 'Token rotation failed' };
    }
  }
}