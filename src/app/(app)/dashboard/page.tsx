'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/providers/AuthProvider'; // Assuming auth provider exists
import AccountIdentity from '@/components/dashboard/AccountIdentity';
import PortfolioOverview from '@/components/dashboard/PortfolioOverview';
import RiskExposure from '@/components/dashboard/RiskExposure';
import ModelStatus from '@/components/dashboard/ModelStatus';
import SystemNotices from '@/components/dashboard/SystemNotices';
import { dashboardService } from '@/services/dashboard.service';
import { DashboardData } from '@/types/dashboard';
import { SectionStatus } from '@/types/dashboard';

// Main Dashboard Page Component
export default function DashboardPage() {
  const router = useRouter();
  const { user, isAuthenticated, isLoading: authLoading } = useAuth(); // Assuming auth provider exists
  
  // State for dashboard data and loading states
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [loadingStates, setLoadingStates] = useState({
    account: SectionStatus.LOADING,
    portfolio: SectionStatus.LOADING,
    risk: SectionStatus.LOADING,
    model: SectionStatus.LOADING,
    notices: SectionStatus.LOADING,
  });
  const [error, setError] = useState<string | null>(null);

  // Check authentication on component mount
  useEffect(() => {
    if (!authLoading) {
      if (!isAuthenticated) {
        // Redirect to login if not authenticated
        router.push('/login');
        return;
      }
      
      // Load dashboard data
      loadDashboardData();
    }
  }, [isAuthenticated, authLoading, router]);

  // Function to load dashboard data
  const loadDashboardData = async () => {
    try {
      setError(null);
      
      // Fetch all dashboard data
      const data = await dashboardService.fetchDashboardData();
      setDashboardData(data);
      
      // Update loading states based on data availability
      setLoadingStates({
        account: data.userAccount ? SectionStatus.LOADED : SectionStatus.EMPTY,
        portfolio: data.portfolio ? SectionStatus.LOADED : SectionStatus.EMPTY,
        risk: data.risk ? SectionStatus.LOADED : SectionStatus.EMPTY,
        model: data.modelStatus ? SectionStatus.LOADED : SectionStatus.EMPTY,
        notices: data.systemNotices.length > 0 ? SectionStatus.LOADED : SectionStatus.EMPTY,
      });
    } catch (err) {
      console.error('Error loading dashboard data:', err);
      setError('Failed to load dashboard data. Please try again later.');
      
      // Set all sections to error state
      setLoadingStates({
        account: SectionStatus.ERROR,
        portfolio: SectionStatus.ERROR,
        risk: SectionStatus.ERROR,
        model: SectionStatus.ERROR,
        notices: SectionStatus.ERROR,
      });
    }
  };

  // Handle refresh action
  const handleRefresh = () => {
    loadDashboardData();
  };

  // Show loading state while checking auth
  if (authLoading) {
    return (
      <div className="min-h-screen bg-black text-white p-6">
        <div className="max-w-7xl mx-auto animate-pulse">
          <div className="h-8 bg-gray-800 rounded w-1/4 mb-8"></div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="h-64 bg-gray-800 rounded-xl"></div>
            <div className="h-64 bg-gray-800 rounded-xl"></div>
            <div className="h-64 bg-gray-800 rounded-xl"></div>
            <div className="h-64 bg-gray-800 rounded-xl"></div>
            <div className="h-64 bg-gray-800 rounded-xl col-span-2"></div>
          </div>
        </div>
      </div>
    );
  }

  // If not authenticated, don't render anything (should be redirected)
  if (!isAuthenticated) {
    return null;
  }

  return (
    <div className="min-h-screen bg-black text-white p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header Section */}
        <header className="mb-8">
          <div className="flex justify-between items-center">
            <div>
              <h1 className="text-3xl font-bold">Dashboard</h1>
              <p className="text-gray-400 mt-1">
                {user ? `Welcome back, ${typeof user === 'object' && user.email ? user.email.split('@')[0] : 'User'}` : 'Your control center'}
              </p>
            </div>
            <button 
              onClick={handleRefresh}
              className="bg-gray-800 hover:bg-gray-700 text-white px-4 py-2 rounded-lg transition-colors"
            >
              Refresh Data
            </button>
          </div>
        </header>

        {/* Error Message */}
        {error && (
          <div className="bg-red-900/30 border border-red-700 rounded-xl p-4 mb-6">
            <p className="text-red-300">{error}</p>
          </div>
        )}

        {/* Main Dashboard Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Account & Identity Section */}
          <AccountIdentity 
            accountData={dashboardData?.userAccount || null} 
            status={loadingStates.account as 'loading' | 'loaded' | 'error' | 'empty'} 
          />

          {/* Portfolio Overview Section */}
          <PortfolioOverview 
            portfolioData={dashboardData?.portfolio || null} 
            status={loadingStates.portfolio as 'loading' | 'loaded' | 'error' | 'empty'} 
          />

          {/* Risk & Exposure Awareness Section */}
          <RiskExposure 
            riskData={dashboardData?.risk || null} 
            status={loadingStates.risk as 'loading' | 'loaded' | 'error' | 'empty'} 
          />

          {/* AI / Model Interaction Status Section */}
          <ModelStatus 
            modelData={dashboardData?.modelStatus || null} 
            status={loadingStates.model as 'loading' | 'loaded' | 'error' | 'empty'} 
          />

          {/* System & Security Notices Section */}
          <div className="lg:col-span-2">
            <SystemNotices 
              notices={dashboardData?.systemNotices || []} 
              status={loadingStates.notices as 'loading' | 'loaded' | 'error' | 'empty'} 
            />
          </div>
        </div>
      </div>

      {/* Technical Explanation Comment Block */}
      {/*
        TECHNICAL EXPLANATION:
        
        How portfolio data will be plugged in:
        - Expected API endpoints structure: /api/dashboard/portfolio, /api/dashboard/positions, /api/dashboard/allocation
        - Data transformation requirements: Raw financial data → PortfolioSummary interface
        - Caching strategy: Client-side cache with configurable TTL, server-side caching for expensive calculations
        - Update frequency considerations: User-triggered refresh, background sync every 5-10 minutes
        - Pagination or data limitation approach: Paginated responses for large portfolios, summary views for overview
        
        How risk data will be sourced:
        - Risk calculation service integration points: Separate microservice or internal API
        - Real-time vs. batch update strategy: Batch processing for daily risk metrics, event-driven for critical alerts
        - Alert threshold configuration: Configurable thresholds per user risk profile
        - Historical data storage approach: Time-series database for risk metrics over time
        
        Why this design avoids future refactors:
        - Separation of concerns: UI components separate from data services
        - Extensibility points: Easy to add new sections without changing existing ones
        - Backward compatibility considerations: Type-safe interfaces that can evolve
        - Migration path from current to future features: Clear abstraction layers
        - Scalability considerations: Individual loading states prevent blocking
        
        Data Flow Architecture:
        - API → Service Layer → React State → UI Components
        - Error propagation: Service errors → Component state → UI error display
        - Loading state coordination: Individual section loading states managed independently
        
        Security Implementation Notes:
        - Auth verification: Performed at page level using AuthProvider context
        - Data sanitization: Assumed to happen at API/service layer
        - Sensitive data handling: Not displayed directly, properly formatted
        - Logging and monitoring: Error boundaries capture and log issues appropriately
      */}
    </div>
  );
}
