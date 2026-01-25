import Link from 'next/link';
import { redirect } from 'next/navigation';
import { cookies } from 'next/headers';
import { verifySessionCookie, SessionUser } from '@/lib/sessionUtils';
import Hero from '@/components/landing/Hero';
import WhatItDoes from '@/components/landing/WhatItDoes';
import CoreCapabilities from '@/components/landing/CoreCapabilities';
import MultiModelArchitecture from '@/components/landing/MultiModelArchitecture';
import RiskSafety from '@/components/landing/RiskSafety';
import FutureCapabilities from '@/components/landing/FutureCapabilities';
import TrustTransparency from '@/components/landing/TrustTransparency';
import Footer from '@/components/landing/Footer';

// Server-side function to check authentication
async function checkAuthStatus() {
  try {
    // Get session cookie from request headers
    const cookieStore = cookies();
    const sessionCookie = cookieStore.get('__session')?.value || cookieStore.get('access_token')?.value;
    
    if (!sessionCookie) {
      return { authenticated: false, user: null };
    }
    
    // Verify the session cookie using the existing authentication system
    const user = await verifySessionCookie(sessionCookie);
    
    if (user) {
      return { authenticated: true, user };
    } else {
      return { authenticated: false, user: null };
    }
  } catch (error) {
    console.error('Auth check error:', error);
    return { authenticated: false, user: null };
  }
}

export async function generateMetadata() {
  return {
    title: 'QuantumIQ - AI-Driven Trading Intelligence Platform',
    description: 'Advanced multi-model AI architecture providing context-aware market analysis and risk evaluation for informed trading decisions.',
    keywords: 'AI trading, trading intelligence, risk management, decision support, algorithmic trading',
    openGraph: {
      title: 'QuantumIQ - AI-Driven Trading Intelligence',
      description: 'Advanced AI decision support for sophisticated traders',
      type: 'website',
    },
  };
}

export default async function LandingPage() {
  const { authenticated, user } = await checkAuthStatus();
  
  // Redirect authenticated users to dashboard
  if (authenticated && user) {
    redirect('/dashboard');
  }

  return (
    <LandingPageContent />
  );
}

function LandingPageContent() {
  return (
    <main className="min-h-screen bg-black text-white">
      <Hero />
      <WhatItDoes />
      <CoreCapabilities />
      <MultiModelArchitecture />
      <RiskSafety />
      <FutureCapabilities />
      <TrustTransparency />
      <Footer />
    </main>
  );
}

