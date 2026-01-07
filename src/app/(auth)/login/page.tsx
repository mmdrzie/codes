'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { signInWithPopup, getIdToken } from 'firebase/auth';
import { BrowserProvider } from 'ethers';
import { useAuth } from '@/features/auth/hooks/useAuth';

// named import (درست و بدون ارور)
import { firebaseClient } from '@/lib/firebase-client';

export default function LoginPage() {
  const router = useRouter();
  const { user, loading } = useAuth();
  const [isConnecting, setIsConnecting] = useState(false);

  const handleGoogleLogin = async () => {
    if (isConnecting || !firebaseClient.auth || !firebaseClient.googleProvider) return;

    setIsConnecting(true);
    try {
      const result = await signInWithPopup(firebaseClient.auth, firebaseClient.googleProvider);
      const firebaseUser = result.user;
      const idToken = await getIdToken(firebaseUser);

      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ idToken }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || 'Failed to create session');
      }

      router.push('/dashboard');
      router.refresh();
    } catch (err: any) {
      console.error('Google login error:', err);
      alert(err.message || 'Google sign in failed. Please try again.');
    } finally {
      setIsConnecting(false);
    }
  };

  const handleWalletLogin = async () => {
    if (isConnecting) return;

    const eth = typeof window !== 'undefined' ? (window as any).ethereum : null;
    if (!eth) {
      alert('Metamask (or another wallet) is not installed.');
      return;
    }

    setIsConnecting(true);
    try {
      const provider = new BrowserProvider(eth);
      const signer = await provider.getSigner();
      const address = await signer.getAddress();

      // 1) get nonce + message
      const nonceRes = await fetch(`/api/auth/wallet/nonce?address=${encodeURIComponent(address)}`, {
        method: 'GET',
        credentials: 'include',
      });

      if (!nonceRes.ok) {
        const errData = await nonceRes.json().catch(() => ({}));
        throw new Error(errData.error || 'Failed to get wallet nonce');
      }

      const { nonce, message } = await nonceRes.json();

      // 2) sign message
      const signature = await signer.signMessage(message);

      // 3) login
      const res = await fetch('/api/auth/wallet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ address, signature, nonce, message }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || 'Wallet login failed');
      }

      router.push('/dashboard');
      router.refresh();
    } catch (err: any) {
      console.error('Wallet login error:', err);
      alert(err.message || 'Wallet login failed. Please try again.');
    } finally {
      setIsConnecting(false);
    }
  };

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  if (user) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <p className="mb-4 text-gray-700">You are already logged in</p>
          <a
            href="/dashboard"
            className="inline-block px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            Continue to Dashboard
          </a>
        </div>
      </div>
    );
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-gray-50">
      <div className="w-full max-w-md p-8 bg-white rounded-lg shadow-lg">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">Welcome Back</h1>
          <p className="text-gray-600">Sign in to continue to your account</p>
        </div>

        <button
          onClick={handleGoogleLogin}
          disabled={isConnecting}
          className="w-full flex items-center justify-center gap-3 px-6 py-3 bg-white border-2 border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 hover:border-gray-400 transition-all disabled:opacity-50 disabled:cursor-not-allowed font-medium"
        >
          {isConnecting ? (
            <>
              <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-gray-900"></div>
              <span>Signing in...</span>
            </>
          ) : (
            <>
              <svg className="w-5 h-5" viewBox="0 0 24 24" aria-hidden="true">
                <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
                <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
              </svg>
              <span>Sign in with Google</span>
            </>
          )}
        </button>

        <button
          onClick={handleWalletLogin}
          disabled={isConnecting}
          className="mt-4 w-full flex items-center justify-center gap-3 px-6 py-3 bg-black text-white rounded-lg hover:bg-gray-900 transition-all disabled:opacity-50 disabled:cursor-not-allowed font-medium"
        >
          {isConnecting ? (
            <>
              <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
              <span>Connecting...</span>
            </>
          ) : (
            <span>Connect Wallet</span>
          )}
        </button>

        <div className="mt-6 text-center text-sm text-gray-600">
          <p>By signing in, you agree to our</p>
          <a href="/terms" className="text-blue-600 hover:underline">Terms of Service</a>
          {' and '}
          <a href="/privacy" className="text-blue-600 hover:underline">Privacy Policy</a>
        </div>
      </div>
    </main>
  );
}