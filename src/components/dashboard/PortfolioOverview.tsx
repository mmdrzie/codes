'use client';

import React from 'react';
import { PortfolioSummary } from '@/types/dashboard';

interface PortfolioOverviewProps {
  portfolioData: PortfolioSummary | null;
  status: 'loading' | 'loaded' | 'error' | 'empty';
}

const PortfolioOverview: React.FC<PortfolioOverviewProps> = ({ portfolioData, status }) => {
  if (status === 'loading') {
    return (
      <div className="bg-[#0a0a0a] border border-gray-800 rounded-xl p-6">
        <div className="animate-pulse">
          <div className="h-6 bg-gray-800 rounded w-1/3 mb-4"></div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[...Array(8)].map((_, i) => (
              <div key={i} className="h-16 bg-gray-800 rounded"></div>
            ))}
          </div>
          <div className="mt-6 h-32 bg-gray-800 rounded"></div>
        </div>
      </div>
    );
  }

  if (status === 'error') {
    return (
      <div className="bg-[#0a0a0a] border border-gray-800 rounded-xl p-6">
        <h3 className="text-xl font-semibold text-white mb-4">Portfolio Overview</h3>
        <div className="text-red-500">Failed to load portfolio information</div>
      </div>
    );
  }

  if (status === 'empty' || !portfolioData) {
    return (
      <div className="bg-[#0a0a0a] border border-gray-800 rounded-xl p-6">
        <h3 className="text-xl font-semibold text-white mb-4">Portfolio Overview</h3>
        <div className="text-gray-400">No portfolio information available</div>
      </div>
    );
  }

  // Format currency for display
  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    }).format(value);
  };

  return (
    <div className="bg-[#0a0a0a] border border-gray-800 rounded-xl p-6">
      <h3 className="text-xl font-semibold text-white mb-4">Portfolio Overview</h3>
      
      {/* Key Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-gray-900 p-4 rounded-lg">
          <div className="text-gray-400 text-sm">Positions</div>
          <div className="text-white text-xl font-semibold">{portfolioData.positionCount}</div>
        </div>
        <div className="bg-gray-900 p-4 rounded-lg">
          <div className="text-gray-400 text-sm">Total Value</div>
          <div className="text-white text-xl font-semibold">{formatCurrency(portfolioData.totalValue)}</div>
        </div>
        <div className="bg-gray-900 p-4 rounded-lg">
          <div className="text-gray-400 text-sm">Diversity Score</div>
          <div className="text-white text-xl font-semibold">{portfolioData.diversityScore}/100</div>
        </div>
        <div className="bg-gray-900 p-4 rounded-lg">
          <div className="text-gray-400 text-sm">Asset Exposure</div>
          <div className="text-white text-xl font-semibold">{portfolioData.assetExposure}</div>
        </div>
      </div>

      {/* Allocation Breakdown */}
      <div className="mb-6">
        <h4 className="text-lg font-medium text-white mb-3">Allocation Breakdown</h4>
        <div className="space-y-2">
          {portfolioData.allocationBreakdown.map((item, index) => (
            <div key={index} className="flex justify-between items-center">
              <span className="text-gray-400">{item.category}</span>
              <span className="text-white">{item.percentage}%</span>
            </div>
          ))}
        </div>
      </div>

      {/* Asset Class Distribution */}
      <div className="mb-6">
        <h4 className="text-lg font-medium text-white mb-3">Asset Classes</h4>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
          {portfolioData.assetClassDistribution.map((asset, index) => (
            <div key={index} className="bg-gray-900 p-3 rounded-lg">
              <div className="text-gray-400 text-sm capitalize">{asset.type}</div>
              <div className="text-white font-medium">{asset.percentage}%</div>
            </div>
          ))}
        </div>
      </div>

      {/* Geographic Exposure */}
      <div className="mb-6">
        <h4 className="text-lg font-medium text-white mb-3">Geographic Exposure</h4>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
          {portfolioData.geographicExposure.map((region, index) => (
            <div key={index} className="bg-gray-900 p-3 rounded-lg">
              <div className="text-gray-400 text-sm">{region.region}</div>
              <div className="text-white font-medium">{region.percentage}%</div>
            </div>
          ))}
        </div>
      </div>

      {/* Currency Exposure */}
      <div className="mb-6">
        <h4 className="text-lg font-medium text-white mb-3">Currency Exposure</h4>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
          {portfolioData.currencyExposure.map((currency, index) => (
            <div key={index} className="bg-gray-900 p-3 rounded-lg">
              <div className="text-gray-400 text-sm">{currency.currency}</div>
              <div className="text-white font-medium">{currency.percentage}%</div>
            </div>
          ))}
        </div>
      </div>

      {/* Top Holdings */}
      <div>
        <h4 className="text-lg font-medium text-white mb-3">Top Holdings</h4>
        <div className="space-y-2">
          {portfolioData.topHoldings.slice(0, 5).map((holding, index) => (
            <div key={index} className="flex justify-between items-center bg-gray-900 p-3 rounded-lg">
              <div>
                <div className="text-white font-medium">{holding.name}</div>
                <div className="text-gray-400 text-sm">{holding.symbol}</div>
              </div>
              <div className="text-white">{holding.percentage}%</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default PortfolioOverview;