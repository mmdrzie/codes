// src/providers/AuthProvider.tsx
'use client';

import { createContext, useEffect, useState, ReactNode } from 'react';
import { getFirebaseAuth } from '@/lib/firebase-client';
import { onAuthStateChanged, signOut, User as FirebaseUser } from 'firebase/auth';

type CustomUser = {
  uid: string;
  displayName?: string | null;
  email?: string | null;
  type: 'firebase' | 'wallet' | 'session';
  address?: string;
  metadata?: {
    sessionId?: string;
    tenantId?: string;
    createdAt?: string;
    emailVerified?: boolean;
    providerId?: string;
  };
  [key: string]: any;
};

type AuthContextType = {
  user: CustomUser | null;
  loading: boolean;
  logout: () => Promise<void>;
  isAuthenticated: boolean;
  refreshSession: () => Promise<void>;
};

export const AuthContext = createContext<AuthContextType>({
  user: null,
  loading: true,
  logout: async () => {},
  isAuthenticated: false,
  refreshSession: async () => {},
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<CustomUser | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchSession = async (): Promise<CustomUser | null> => {
    try {
      const res = await fetch('/api/auth/session', {
        credentials: 'include', // ✅ مهم برای cookie/session
        headers: {
          'Cache-Control': 'no-cache',
        },
      });

      if (res.ok) {
        const data = await res.json();

        if (data.loggedIn && data.user) {
          return {
            uid: data.user.uid || data.user.id || data.userId || 'unknown',
            displayName: data.user.displayName || data.user.name || data.user.email || data.user.address,
            email: data.user.email,
            type: data.user.type || data.type || 'session',
            address: data.user.address || data.user.walletAddress,
            metadata: {
              sessionId: data.sessionId,
              tenantId: data.tenantId,
              createdAt: data.createdAt,
            },
            ...data.user
          };
        }
      }
      return null;
    } catch (error) {
      console.error('Session fetch error:', error);
      return null;
    }
  };

  useEffect(() => {
    let isMounted = true;
    let unsubscribe: (() => void) | undefined;

    const initializeAuth = async (): Promise<void> => {
      const sessionUser = await fetchSession();

      if (sessionUser) {
        if (isMounted) {
          setUser(sessionUser);
          setLoading(false);
        }
        return;
      }

      try {
        const auth = getFirebaseAuth();
        unsubscribe = onAuthStateChanged(auth, async (firebaseUser: FirebaseUser | null) => {
          if (!isMounted) return;

          if (firebaseUser) {
            const customUser: CustomUser = {
              uid: firebaseUser.uid,
              displayName: firebaseUser.displayName,
              email: firebaseUser.email,
              type: 'firebase',
              metadata: {
                emailVerified: firebaseUser.emailVerified,
                providerId: firebaseUser.providerId,
              }
            };

            // sync با session سرور
            try {
              const idToken = await firebaseUser.getIdToken(true); // ✅ refresh token if needed
              await fetch('/api/auth/sync-firebase', {
                method: 'POST',
                credentials: 'include', // ✅ اجازه بده Set-Cookie session ذخیره بشه
                headers: {
                  'Authorization': `Bearer ${idToken}`,
                  'Content-Type': 'application/json',
                }
              });

              // بعد از sync دوباره session را چک کن تا user.type = session شود
              const refreshed = await fetchSession();
              if (refreshed) {
                setUser(refreshed);
              } else {
                setUser(customUser);
              }
            } catch (error) {
              console.error('Firebase sync error:', error);
              setUser(customUser);
            }
          } else {
            setUser(null);
          }

          setLoading(false);
        });

        return;
      } catch (error) {
        console.warn('Firebase auth init skipped:', error);
        if (isMounted) setLoading(false);
        return;
      }
    };

    void initializeAuth();

    return () => {
      isMounted = false;
      if (unsubscribe) unsubscribe();
    };
  }, []);

  const refreshSession = async () => {
    const sessionUser = await fetchSession();
    setUser(sessionUser);
  };

  const logout = async () => {
    try {
      try {
        const auth = getFirebaseAuth();
        if (auth.currentUser) await signOut(auth);
      } catch {
        // ignore - firebase not initialized
      }

      await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include'
      });

      setUser(null);
      window.location.href = '/login';
    } catch (error) {
      console.error('Logout error:', error);
      window.location.href = '/login';
    }
  };

  const value = {
    user,
    loading,
    logout,
    isAuthenticated: !!user,
    refreshSession
  };

  return (
    <AuthContext.Provider value={value}>
      {!loading && children}
    </AuthContext.Provider>
  );
}
