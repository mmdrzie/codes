import { initializeApp, getApps, getApp, FirebaseApp } from 'firebase/app';
import {
  getAuth,
  Auth,
  GoogleAuthProvider,
  GithubAuthProvider,
  FacebookAuthProvider,
  TwitterAuthProvider,
} from 'firebase/auth';
import { getFirestore, Firestore } from 'firebase/firestore';
import { getStorage } from 'firebase/storage';
import { getAnalytics, Analytics } from 'firebase/analytics';
import { getPerformance } from 'firebase/performance';

const firebaseConfig = {
  apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY || '',
  authDomain: process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN || '',
  projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID || '',
  storageBucket: process.env.NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET || '',
  messagingSenderId: process.env.NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID || '',
  appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID || '',
  measurementId: process.env.NEXT_PUBLIC_FIREBASE_MEASUREMENT_ID || '',
};

let appInstance: FirebaseApp | null = null;
let authInstance: Auth | null = null;
let firestoreInstance: Firestore | null = null;
let storageInstance: any = null;
let analyticsInstance: Analytics | null = null;

let googleProviderInstance: GoogleAuthProvider | null = null;
let githubProviderInstance: GithubAuthProvider | null = null;
let facebookProviderInstance: FacebookAuthProvider | null = null;
let twitterProviderInstance: TwitterAuthProvider | null = null;

function validateFirebaseConfig(): boolean {
  const requiredFields: (keyof typeof firebaseConfig)[] = ['apiKey', 'authDomain', 'projectId', 'appId'];
  const missing = requiredFields.filter((k) => !firebaseConfig[k]);

  if (missing.length) {
    console.error(`Missing Firebase config fields: ${missing.join(', ')}`);
    return false;
  }
  return true;
}

export function initializeFirebaseClient(): boolean {
  if (typeof window === 'undefined') {
    console.warn('Firebase Client SDK can only be initialized in browser');
    return false;
  }

  if (appInstance && authInstance && firestoreInstance) return true;

  if (!validateFirebaseConfig()) {
    console.error('Firebase configuration is invalid');
    return false;
  }

  try {
    // ✅ avoid duplicate app initialization in dev/fast refresh
    appInstance = getApps().length ? getApp() : initializeApp(firebaseConfig);

    authInstance = getAuth(appInstance);
    firestoreInstance = getFirestore(appInstance);
    storageInstance = getStorage(appInstance);

    // providers (create once)
    googleProviderInstance = googleProviderInstance ?? new GoogleAuthProvider();
    githubProviderInstance = githubProviderInstance ?? new GithubAuthProvider();
    facebookProviderInstance = facebookProviderInstance ?? new FacebookAuthProvider();
    twitterProviderInstance = twitterProviderInstance ?? new TwitterAuthProvider();

    // configure provider (once)
    googleProviderInstance.setCustomParameters({
      prompt: 'select_account',
      login_hint: '',
    });

    // analytics/perf only in production + guarded (some envs throw)
    if (process.env.NODE_ENV === 'production') {
      try {
        analyticsInstance = getAnalytics(appInstance);
      } catch (e) {
        console.warn('Analytics init skipped:', e);
      }
      try {
        getPerformance(appInstance);
      } catch (e) {
        console.warn('Performance init skipped:', e);
      }
    }

    console.log('✅ Firebase Client SDK initialized successfully');
    return true;
  } catch (error) {
    console.error('❌ Failed to initialize Firebase Client SDK:', error);
    if (process.env.NODE_ENV === 'production') console.error('Critical: Firebase initialization failed');
    return false;
  }
}

export function getFirebaseAuth(): Auth {
  if (typeof window === 'undefined') throw new Error('Firebase Auth can only be used in browser');

  if (!authInstance) {
    const ok = initializeFirebaseClient();
    if (!ok || !authInstance) {
      throw new Error('Firebase Auth is not initialized. Please check Firebase env vars.');
    }
  }
  return authInstance;
}

export function getFirestoreDb(): Firestore {
  if (typeof window === 'undefined') throw new Error('Firestore can only be used in browser');

  if (!firestoreInstance) {
    const ok = initializeFirebaseClient();
    if (!ok || !firestoreInstance) throw new Error('Firestore is not initialized.');
  }
  return firestoreInstance;
}

export function getGoogleAuthProvider(): GoogleAuthProvider {
  if (typeof window === 'undefined') throw new Error('Google Auth Provider can only be used in browser');

  if (!googleProviderInstance) {
    initializeFirebaseClient();
    if (!googleProviderInstance) throw new Error('Google Auth Provider not initialized');
  }
  return googleProviderInstance;
}

export function getFirebaseStorage() {
  if (typeof window === 'undefined') throw new Error('Firebase Storage can only be used in browser');

  if (!storageInstance) {
    const ok = initializeFirebaseClient();
    if (!ok || !storageInstance) throw new Error('Firebase Storage is not initialized.');
  }
  return storageInstance;
}

export function getFirebaseAnalytics(): Analytics | null {
  if (typeof window === 'undefined') return null;
  if (!analyticsInstance && process.env.NODE_ENV === 'production') initializeFirebaseClient();
  return analyticsInstance;
}

export function isFirebaseClientInitialized(): boolean {
  return !!(appInstance && authInstance && firestoreInstance);
}

export function cleanupFirebaseClient(): void {
  appInstance = null;
  authInstance = null;
  firestoreInstance = null;
  storageInstance = null;
  analyticsInstance = null;

  googleProviderInstance = null;
  githubProviderInstance = null;
  facebookProviderInstance = null;
  twitterProviderInstance = null;
}

export const googleProvider = {
  get instance(): GoogleAuthProvider {
    return getGoogleAuthProvider();
  },
};

export const githubProvider = {
  get instance(): GithubAuthProvider {
    if (!githubProviderInstance) initializeFirebaseClient();
    if (!githubProviderInstance) throw new Error('Github Provider not initialized');
    return githubProviderInstance;
  },
};

export const facebookProvider = {
  get instance(): FacebookAuthProvider {
    if (!facebookProviderInstance) initializeFirebaseClient();
    if (!facebookProviderInstance) throw new Error('Facebook Provider not initialized');
    return facebookProviderInstance;
  },
};

export const twitterProvider = {
  get instance(): TwitterAuthProvider {
    if (!twitterProviderInstance) initializeFirebaseClient();
    if (!twitterProviderInstance) throw new Error('Twitter Provider not initialized');
    return twitterProviderInstance;
  },
};

export const firebaseClient = {
  get auth(): Auth {
    return getFirebaseAuth();
  },
  get db(): Firestore {
    return getFirestoreDb();
  },
  get storage() {
    return getFirebaseStorage();
  },
  get analytics(): Analytics | null {
    return getFirebaseAnalytics();
  },

  get googleProvider(): GoogleAuthProvider {
    return getGoogleAuthProvider();
  },
  get githubProvider(): GithubAuthProvider {
    return githubProvider.instance;
  },
  get facebookProvider(): FacebookAuthProvider {
    return facebookProvider.instance;
  },
  get twitterProvider(): TwitterAuthProvider {
    return twitterProvider.instance;
  },

  initialize: initializeFirebaseClient,
  isInitialized: isFirebaseClientInitialized,
  cleanup: cleanupFirebaseClient,

  get authNullable(): Auth | null {
    return authInstance;
  },
  get dbNullable(): Firestore | null {
    return firestoreInstance;
  },
};

if (typeof window !== 'undefined' && process.env.NODE_ENV === 'production') {
  setTimeout(() => {
    if (!isFirebaseClientInitialized()) initializeFirebaseClient();
  }, 1000);
}

export default firebaseClient;
