'use client';

import { useAuth } from '@/features/auth/hooks/useAuth';
import { useRouter } from 'next/navigation';

export default function HomePage() {
  const { user, loading } = useAuth();
  const router = useRouter();

  if (loading) return <p>Loading...</p>;

  const handleGetStarted = () => {
    if (user) {
      router.push('/dashboard');
    } else {
      router.push('/login');
    }
  };

  return (
    <main className="flex min-h-screen flex-col items-center justify-center bg-gray-100">
      <div className="text-center max-w-2xl px-4">
        <h1 className="text-5xl font-bold mb-6">Welcome to QuantumIQ</h1>
        <p className="text-xl mb-10 text-gray-600">Your AI-powered SaaS for [توضیح کوتاه سایت — مثلاً analysis, chat, charts و ...]</p>
        <button
          onClick={handleGetStarted}
          className="px-8 py-4 bg-blue-600 text-white text-lg rounded-lg hover:bg-blue-700 transition"
        >
          Get Started
        </button>
      </div>
    </main>
  );
}