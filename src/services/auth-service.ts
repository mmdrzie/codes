import { AuthUser, FirebaseUser, Web3User, SiweVerifyParams } from '@/types/auth';
import { FirebaseAuthService } from './firebase-auth';
import { SiweService } from './web3/siwe-service';
import { z } from 'zod';
import { getEnterpriseRedisClient } from '@/infrastructure/redis/enterprise-redis-client';
import { EnterpriseSessionManager } from '@/core/session/enterprise-session-manager';

// Enterprise session manager instance
const redisClient = getEnterpriseRedisClient();
const sessionManager = new EnterpriseSessionManager(redisClient);

export class AuthService {
  /**
   * Sign in with email and password (Firebase)
   */
  static async signInWithEmailAndPassword(email: string, password: string): Promise<{ user: AuthUser; token: string }> {
    try {
      const validated = z.object({
        email: z.string().email('Invalid email address'),
        password: z.string().min(8, 'Password must be at least 8 characters'),
      }).parse({ email, password });

      const firebaseUser = await FirebaseAuthService.signInWithEmailAndPassword(validated.email, validated.password);
      const token = await FirebaseAuthService.createSessionToken(firebaseUser);
      FirebaseAuthService.setSessionCookie(token);

      const authUser: AuthUser = {
        id: firebaseUser.uid,
        type: 'firebase',
        firebaseUser,
        createdAt: new Date(firebaseUser.metadata.creationTime || Date.now()),
        lastSignInAt: new Date(firebaseUser.metadata.lastSignInTime || Date.now()),
        isVerified: firebaseUser.emailVerified,
      };

      return { user: authUser, token };
    } catch (error: any) {
      throw new Error(`Sign in failed: ${error.message}`);
    }
  }

  /**
   * Sign up with email and password (Firebase)
   */
  static async signUpWithEmailAndPassword(email: string, password: string, displayName?: string): Promise<{ user: AuthUser; token: string }> {
    try {
      const validated = z.object({
        email: z.string().email('Invalid email address'),
        password: z.string().min(8, 'Password must be at least 8 characters'),
        displayName: z.string().optional(),
      }).parse({ email, password, displayName });

      const firebaseUser = await FirebaseAuthService.createUser(validated.email, validated.password, validated.displayName);
      const token = await FirebaseAuthService.createSessionToken(firebaseUser);
      FirebaseAuthService.setSessionCookie(token);

      const authUser: AuthUser = {
        id: firebaseUser.uid,
        type: 'firebase',
        firebaseUser,
        createdAt: new Date(firebaseUser.metadata.creationTime || Date.now()),
        lastSignInAt: new Date(firebaseUser.metadata.lastSignInTime || Date.now()),
        isVerified: firebaseUser.emailVerified,
      };

      return { user: authUser, token };
    } catch (error: any) {
      throw new Error(`Sign up failed: ${error.message}`);
    }
  }

  /**
   * Sign in with Web3 (SIWE) - Uses enterprise nonce store
   */
  static async signInWithWeb3(params: SiweVerifyParams, domain: string): Promise<{ user: AuthUser; token: string }> {
    try {
      // Extract nonce from the message
      const messageLines = params.message.split('\n');
      let nonce = '';
      for (const line of messageLines) {
        if (line.startsWith('Nonce:')) {
          nonce = line.replace('Nonce:', '').trim();
          break;
        }
      }

      if (!nonce) {
        throw new Error('Nonce not found in message');
      }

      // Verify SIWE signature (uses enterprise nonce store internally)
      const web3User = await SiweService.verifySiweSignature(params, domain, nonce);

      // Create session token
      const token = await SiweService.createSecureSessionToken(web3User);

      // Set session cookie
      SiweService.setSecureSessionCookie(token);

      const authUser: AuthUser = {
        id: web3User.address,
        type: 'web3',
        web3User,
        createdAt: new Date(),
        lastSignInAt: new Date(),
        isVerified: true,
      };

      return { user: authUser, token };
    } catch (error: any) {
      throw new Error(`Web3 sign in failed: ${error.message}`);
    }
  }

  /**
   * Get current user session
   */
  static async getCurrentUser(): Promise<AuthUser | null> {
    try {
      const token = SiweService.getSessionCookie();
      if (!token) {
        return null;
      }

      const user = await SiweService.verifySecureSessionToken(token);
      return user;
    } catch (error) {
      console.error('Error getting current user:', error);
      return null;
    }
  }

  /**
   * Generate SIWE nonce using enterprise store
   */
  static async generateSiweNonce(address: string): Promise<{ nonce: string; message: string; expiresAt: number }> {
    if (!SiweService.validateEthereumAddress(address)) {
      throw new Error('Invalid Ethereum address');
    }

    return await SiweService.generateSecureNonce(address);
  }

  /**
   * Logout user (revoke tokens)
   */
  static async logout(): Promise<void> {
    try {
      const user = await this.getCurrentUser();
      if (!user) {
        return;
      }

      if (user.type === 'firebase' && user.firebaseUser) {
        await FirebaseAuthService.revokeTokens(user.firebaseUser.uid);
      }

      const { cookies } = await import('next/headers');
      cookies().delete('auth_session');
      cookies().delete('web3_auth_session');
    } catch (error: any) {
      throw new Error(`Logout failed: ${error.message}`);
    }
  }

  /**
   * Update user profile
   */
  static async updateProfile(updates: Partial<FirebaseUser>): Promise<AuthUser> {
    try {
      const user = await this.getCurrentUser();
      if (!user || user.type !== 'firebase' || !user.firebaseUser) {
        throw new Error('Only Firebase users can update profile');
      }

      const updatedFirebaseUser = await FirebaseAuthService.updateUser(user.firebaseUser.uid, {
        displayName: updates.displayName,
        photoURL: updates.photoURL,
      });

      const authUser: AuthUser = {
        ...user,
        firebaseUser: updatedFirebaseUser,
        lastSignInAt: new Date(),
      };

      return authUser;
    } catch (error: any) {
      throw new Error(`Profile update failed: ${error.message}`);
    }
  }

  /**
   * Verify session token
   */
  static async verifyToken(token: string): Promise<AuthUser> {
    try {
      return await SiweService.verifySecureSessionToken(token);
    } catch (error: any) {
      throw new Error(`Token verification failed: ${error.message}`);
    }
  }
}
