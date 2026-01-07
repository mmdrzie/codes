import {
  cert,
  getApps,
  initializeApp as initializeAdminApp,
  type App,
} from 'firebase-admin/app';
import { getAuth as getAdminAuth } from 'firebase-admin/auth';
import { getFirestore } from 'firebase-admin/firestore';
import { getStorage } from 'firebase-admin/storage';

let adminApp: App | null = null;

function decodeServiceAccountFromBase64(base64: string): any {
  try {
    const json = Buffer.from(base64, 'base64').toString('utf-8');
    return JSON.parse(json);
  } catch (err: any) {
    throw new Error(
      'FIREBASE_SERVICE_ACCOUNT_BASE64 is not valid base64-encoded JSON. ' +
        `Decode/parse error: ${err?.message || String(err)}`
    );
  }
}

function requireServiceAccount(): any {
  const serviceAccountBase64 = process.env.FIREBASE_SERVICE_ACCOUNT_BASE64;

  if (!serviceAccountBase64) {
    throw new Error(
      'FIREBASE_SERVICE_ACCOUNT_BASE64 is required for Firebase Admin. ' +
        'Provide it as a base64-encoded JSON service account key.'
    );
  }

  const serviceAccount = decodeServiceAccountFromBase64(serviceAccountBase64);

  // حداقل فیلدهای لازم برای cert()
  const requiredFields = ['project_id', 'client_email', 'private_key'];
  const missing = requiredFields.filter((k) => !serviceAccount?.[k]);
  if (missing.length) {
    throw new Error(
      `Service account JSON missing fields: ${missing.join(', ')}`
    );
  }

  // جلوگیری از mismatch پروژه (خیلی مهم برای 401 verifyIdToken)
  const expectedProjectId = process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID;
  if (expectedProjectId && serviceAccount.project_id !== expectedProjectId) {
    throw new Error(
      `Firebase Admin project mismatch. ` +
        `ServiceAccount project_id="${serviceAccount.project_id}" ` +
        `but NEXT_PUBLIC_FIREBASE_PROJECT_ID="${expectedProjectId}". ` +
        `Use a service account from the SAME Firebase project.`
    );
  }

  return serviceAccount;
}

export function getAdminApp(): App {
  if (adminApp) return adminApp;

  const existing = getApps();
  if (existing.length) {
    adminApp = existing[0]!;
    return adminApp;
  }

  const serviceAccount = requireServiceAccount();

  // اگر storageBucket را داری، اینجا ست کن (اختیاری)
  const storageBucket = process.env.FIREBASE_STORAGE_BUCKET || undefined;

  adminApp = initializeAdminApp({
    credential: cert(serviceAccount),
    projectId: serviceAccount.project_id, // کمک می‌کند همه‌چیز دقیق به همان پروژه قفل شود
    ...(storageBucket ? { storageBucket } : {}),
  });

  return adminApp;
}

export function getAdminAuthInstance() {
  return getAdminAuth(getAdminApp());
}

export function getAdminFirestoreInstance() {
  return getFirestore(getAdminApp());
}

export function getAdminStorageInstance() {
  return getStorage(getAdminApp());
}

// Backward-compatible named exports (used in some files)
// Avoid eager initialization at module load time.
// Always call the getter functions above inside request handlers.
