import admin from 'firebase-admin';
import { AuthUser, FirebaseUser } from '@/types/auth';
import { cookies } from 'next/headers';
import { jwtVerify, SignJWT } from 'jose';
import { nanoid } from 'nanoid';

// Initialize Firebase Admin SDK if not already initialized
if (!admin.apps.length) {
  try {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
      }),
    });
  } catch (error) {
    console.error('Firebase Admin initialization error:', error);
  }
}

const auth = admin.auth();
const FIREBASE_JWT_SECRET = new TextEncoder().encode(
  process.env.FIREBASE_JWT_SECRET || 'default_secret_for_dev'
);

export class FirebaseAuthService {
  /**
   * Create a new Firebase user
   */
  static async createUser(email: string, password: string, displayName?: string): Promise<FirebaseUser> {
    try {
      const userRecord = await auth.createUser({
        email,
        password,
        displayName,
        emailVerified: false,
      });

      return {
        uid: userRecord.uid,
        email: userRecord.email,
        displayName: userRecord.displayName,
        photoURL: userRecord.photoURL,
        emailVerified: userRecord.emailVerified,
        disabled: userRecord.disabled,
        metadata: {
          creationTime: userRecord.metadata.creationTime,
          lastSignInTime: userRecord.metadata.lastSignInTime,
        },
      };
    } catch (error: any) {
      throw new Error(`Firebase user creation failed: ${error.message}`);
    }
  }

  /**
   * Sign in with email and password
   */
  static async signInWithEmailAndPassword(email: string, password: string): Promise<FirebaseUser> {
    try {
      // Firebase Admin SDK doesn't directly verify passwords
      // In production, use Firebase Auth Client SDK for sign-in
      // Here we'll verify the user exists and return the user data
      const userRecord = await auth.getUserByEmail(email);
      
      // This is a simplified approach - in production, you'd use the client SDK
      // to verify credentials and then use the token with admin SDK
      if (userRecord.disabled) {
        throw new Error('User account is disabled');
      }

      return {
        uid: userRecord.uid,
        email: userRecord.email,
        displayName: userRecord.displayName,
        photoURL: userRecord.photoURL,
        emailVerified: userRecord.emailVerified,
        disabled: userRecord.disabled,
        metadata: {
          creationTime: userRecord.metadata.creationTime,
          lastSignInTime: userRecord.metadata.lastSignInTime,
        },
      };
    } catch (error: any) {
      throw new Error(`Firebase sign-in failed: ${error.message}`);
    }
  }

  /**
   * Verify Firebase ID token
   */
  static async verifyIdToken(idToken: string): Promise<FirebaseUser> {
    try {
      const decodedToken = await auth.verifyIdToken(idToken);
      
      // Get user details
      const userRecord = await auth.getUser(decodedToken.uid);
      
      return {
        uid: userRecord.uid,
        email: userRecord.email,
        displayName: userRecord.displayName,
        photoURL: userRecord.photoURL,
        emailVerified: userRecord.emailVerified,
        disabled: userRecord.disabled,
        metadata: {
          creationTime: userRecord.metadata.creationTime,
          lastSignInTime: userRecord.metadata.lastSignInTime,
        },
      };
    } catch (error: any) {
      throw new Error(`Firebase token verification failed: ${error.message}`);
    }
  }

  /**
   * Create a secure session token for the user
   */
  static async createSessionToken(user: FirebaseUser, expiresIn: string = '24h'): Promise<string> {
    try {
      const token = await new SignJWT({ 
        uid: user.uid,
        email: user.email,
        type: 'firebase'
      })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime(expiresIn)
        .setJti(nanoid()) // JWT ID for replay protection
        .sign(FIREBASE_JWT_SECRET);

      return token;
    } catch (error: any) {
      throw new Error(`Session token creation failed: ${error.message}`);
    }
  }

  /**
   * Verify session token
   */
  static async verifySessionToken(token: string): Promise<AuthUser> {
    try {
      const { payload } = await jwtVerify(token, FIREBASE_JWT_SECRET);
      
      if (!payload.uid) {
        throw new Error('Invalid token: missing user ID');
      }

      // Get fresh user data
      const userRecord = await auth.getUser(payload.uid as string);
      
      const authUser: AuthUser = {
        id: userRecord.uid,
        type: 'firebase',
        firebaseUser: {
          uid: userRecord.uid,
          email: userRecord.email,
          displayName: userRecord.displayName,
          photoURL: userRecord.photoURL,
          emailVerified: userRecord.emailVerified,
          disabled: userRecord.disabled,
          metadata: {
            creationTime: userRecord.metadata.creationTime,
            lastSignInTime: userRecord.metadata.lastSignInTime,
          },
        },
        createdAt: new Date(userRecord.metadata.creationTime || Date.now()),
        lastSignInAt: new Date(userRecord.metadata.lastSignInTime || Date.now()),
        isVerified: userRecord.emailVerified,
      };

      return authUser;
    } catch (error: any) {
      throw new Error(`Session token verification failed: ${error.message}`);
    }
  }

  /**
   * Set secure session cookie
   */
  static setSessionCookie(token: string): void {
    const cookieStore = cookies();
    cookieStore.set('auth_session', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 24, // 24 hours
      path: '/',
    });
  }

  /**
   * Get session from cookie
   */
  static getSessionCookie(): string | undefined {
    const cookieStore = cookies();
    return cookieStore.get('auth_session')?.value;
  }

  /**
   * Revoke user tokens (logout)
   */
  static async revokeTokens(uid: string): Promise<void> {
    try {
      await auth.revokeRefreshTokens(uid);
    } catch (error: any) {
      throw new Error(`Token revocation failed: ${error.message}`);
    }
  }

  /**
   * Update user profile
   */
  static async updateUser(uid: string, updates: Partial<admin.auth.UpdateRequest>): Promise<FirebaseUser> {
    try {
      const userRecord = await auth.updateUser(uid, updates);
      
      return {
        uid: userRecord.uid,
        email: userRecord.email,
        displayName: userRecord.displayName,
        photoURL: userRecord.photoURL,
        emailVerified: userRecord.emailVerified,
        disabled: userRecord.disabled,
        metadata: {
          creationTime: userRecord.metadata.creationTime,
          lastSignInTime: userRecord.metadata.lastSignInTime,
        },
      };
    } catch (error: any) {
      throw new Error(`User update failed: ${error.message}`);
    }
  }

  /**
   * Delete user account
   */
  static async deleteUser(uid: string): Promise<void> {
    try {
      await auth.deleteUser(uid);
    } catch (error: any) {
      throw new Error(`User deletion failed: ${error.message}`);
    }
  }
}