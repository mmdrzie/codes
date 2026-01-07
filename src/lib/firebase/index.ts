// src/lib/firebase/index.ts
/**
 * Firebase Module - Production Export
 * 
 * این فایل به عنوان single point of export برای همه Firebase-related modules استفاده می‌شود
 */

// Admin SDK exports (server only)
export {
  getAdminAuthInstance,
  getAdminFirestoreInstance,
  getAdminStorageInstance,
} from '../firebaseAdmin';

// Client SDK exports (مرورگر فقط)
export {
  default as firebaseClient,
  getFirebaseAuth,
  getFirestoreDb,
  getGoogleAuthProvider,
  getFirebaseStorage,
  initializeFirebaseClient,
  isFirebaseClientInitialized,
} from '../firebase-client';

// Types
export type { Auth as AdminAuth } from 'firebase-admin/auth';
export type { Firestore as AdminFirestore } from 'firebase-admin/firestore';
export type { User as FirebaseUser } from 'firebase/auth';

/**
 * Utility برای تشخیص محیط
 */
export function isClientSide(): boolean {
  return typeof window !== 'undefined';
}

export function isServerSide(): boolean {
  return typeof window === 'undefined';
}

/**
 * Type guard برای بررسی اینکه آیا در مرورگر هستیم
 */
export function assertClientSide(): void {
  if (isServerSide()) {
    throw new Error('This code can only run on the client side');
  }
}

export function assertServerSide(): void {
  if (isClientSide()) {
    throw new Error('This code can only run on the server side');
  }
}

/**
 * Safe Firebase access based on environment
 */
export const firebase = {
  // Admin methods (سرور)
  admin: {
    get auth() {
      assertServerSide();
      return require('../firebaseAdmin').getAdminAuthInstance();
    },
    get db() {
      assertServerSide();
      return require('../firebaseAdmin').getAdminFirestoreInstance();
    },
    get storage() {
      assertServerSide();
      return require('../firebaseAdmin').getAdminStorageInstance();
    }
  },
  
  // Client methods (مرورگر)
  client: {
    get auth() {
      assertClientSide();
      return require('../firebase-client').getFirebaseAuth();
    },
    get db() {
      assertClientSide();
      return require('../firebase-client').getFirestoreDb();
    },
    get storage() {
      assertClientSide();
      return require('../firebase-client').getFirebaseStorage();
    },
  }
};

// Default export برای import راحت
export default firebase;