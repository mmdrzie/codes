/**
 * src/lib/firebase.ts
 *
 * Central Firebase exports (server + client) with NO eager admin initialization.
 * Call the getter functions inside request handlers.
 */

import {
  getAdminAuthInstance,
  getAdminFirestoreInstance,
  getAdminStorageInstance,
} from './firebaseAdmin';

// Server-side (Admin) getters
export function getAdminDb() {
  return getAdminFirestoreInstance();
}

export function getAdminAuth() {
  return getAdminAuthInstance();
}

export function getAdminStorage() {
  return getAdminStorageInstance();
}

// Client SDK re-exports (tree-shakeable)
export {
  default as firebaseClient,
  initializeFirebaseClient,
  getFirebaseAuth,
  getFirestoreDb,
  getGoogleAuthProvider,
  getFirebaseStorage,
  getFirebaseAnalytics,
  isFirebaseClientInitialized,
} from './firebase-client';
