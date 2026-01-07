import { AuthUser, FirebaseUser, Web3User, SiweVerifyParams } from '@/types/auth';
import { FirebaseAuthService } from './firebase-auth';
import { SiweService } from './web3/siwe-service';
import { z } from 'zod';

export class AuthService {
  /**
   * Sign in with email and password (Firebase)
   */
  static async signInWithEmailAndPassword(email: string, password: string): Promise<{ user: AuthUser; token: string }> {
    try {
      // Validate input
      const validated = z.object({
        email: z.string().email('Invalid email address'),
        password: z.string().min(8, 'Password must be at least 8 characters'),
      }).parse({ email, password });

      // Authenticate with Firebase
      const firebaseUser = await FirebaseAuthService.signInWithEmailAndPassword(validated.email, validated.password);
      
      // Create session token
      const token = await FirebaseAuthService.createSessionToken(firebaseUser);
      
      // Set session cookie
      FirebaseAuthService.setSessionCookie(token);
      
      // Create AuthUser object
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
      // Validate input
      const validated = z.object({
        email: z.string().email('Invalid email address'),
        password: z.string().min(8, 'Password must be at least 8 characters'),
        displayName: z.string().optional(),
      }).parse({ email, password, displayName });

      // Create user with Firebase
      const firebaseUser = await FirebaseAuthService.createUser(validated.email, validated.password, validated.displayName);
      
      // Create session token
      const token = await FirebaseAuthService.createSessionToken(firebaseUser);
      
      // Set session cookie
      FirebaseAuthService.setSessionCookie(token);
      
      // Create AuthUser object
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
   * Sign in with Web3 (SIWE)
   */
  static async signInWithWeb3(params: SiweVerifyParams, domain: string): Promise<{ user: AuthUser; token: string }> {
    try {
      // Extract nonce from the message to verify
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

      // Verify SIWE signature
      const web3User = await SiweService.verifySiweSignature(params, domain, nonce);
      
      // Create session token
      const token = await SiweService.createSessionToken(web3User);
      
      // Set session cookie
      SiweService.setSessionCookie(token);
      
      // Create AuthUser object
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
      // Try to get session from cookies
      const token = SiweService.getSessionCookie();
      if (!token) {
        return null;
      }

      // Verify the session token
      const user = await SiweService.verifySessionToken(token);
      return user;
    } catch (error) {
      console.error('Error getting current user:', error);
      return null;
    }
  }

  /**
   * Generate SIWE message for Web3 authentication
   */
  static generateSiweMessage(address: string, domain: string, chainId: number): { message: string; nonce: string } {
    try {
      // Validate address
      if (!SiweService.validateEthereumAddress(address)) {
        throw new Error('Invalid Ethereum address');
      }

      // Generate nonce
      const nonce = SiweService.generateNonce();

      // Create SIWE message
      const siweMessage = SiweService.createSiweMessage(address, domain, nonce, chainId);

      // Format as EIP-4361 compliant message string
      const message = `${siweMessage.domain} wants you to sign in with your Ethereum account:\n${siweMessage.address}\n\n${siweMessage.statement || ''}\n\nURI: ${siweMessage.uri}\nVersion: ${siweMessage.version}\nChain ID: ${siweMessage.chainId}\nNonce: ${siweMessage.nonce}\nIssued At: ${siweMessage.issuedAt}${siweMessage.expirationTime ? `\nExpiration Time: ${siweMessage.expirationTime}` : ''}${siweMessage.notBefore ? `\nNot Before: ${siweMessage.notBefore}` : ''}${siweMessage.requestId ? `\nRequest ID: ${siweMessage.requestId}` : ''}${siweMessage.resources && siweMessage.resources.length > 0 ? `\nResources:\n${siweMessage.resources.join('\n')}` : ''}`;

      return { message, nonce };
    } catch (error: any) {
      throw new Error(`SIWE message generation failed: ${error.message}`);
    }
  }

  /**
   * Logout user (revoke tokens)
   */
  static async logout(): Promise<void> {
    try {
      const user = await this.getCurrentUser();
      if (!user) {
        return; // No user to log out
      }

      if (user.type === 'firebase' && user.firebaseUser) {
        // Revoke Firebase tokens
        await FirebaseAuthService.revokeTokens(user.firebaseUser.uid);
      }

      // Clear session cookies
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
      return await SiweService.verifySessionToken(token);
    } catch (error: any) {
      throw new Error(`Token verification failed: ${error.message}`);
    }
  }
}