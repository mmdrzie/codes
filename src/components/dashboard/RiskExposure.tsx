'use client';

import React from 'react';
import { RiskAssessment } from '@/types/dashboard';

interface RiskExposureProps {
  riskData: RiskAssessment | null;
  status: 'loading' | 'loaded' | 'error' | 'empty';
}

const RiskExposure: React.FC<RiskExposureProps> = ({ riskData, status }) => {
  if (status === 'loading') {
    return (
      <div className="bg-[#0a0a0a] border border-gray-800 rounded-xl p-6">
        <div className="animate-pulse">
          <div className="h-6 bg-gray-800 rounded w-1/3 mb-4"></div>
          <div className="space-y-3">
            {[...Array(8)].map((_, i) => (
              <div key={i} className="h-4 bg-gray-800 rounded w-full"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (status === 'error') {
    return (
      <div className="bg-[#0a0a0a] border border-gray-800 rounded-xl p-6">
        <h3 className="text-xl font-semibold text-white mb-4">Risk & Exposure Awareness</h3>
        <div className="text-red-500">Failed to load risk information</div>
      </div>
    );
  }

  if (status === 'empty' || !riskData) {
    return (
      <div className="bg-[#0a0a0a] border border-gray-800 rounded-xl p-6">
        <h3 className="text-xl font-semibold text-white mb-4">Risk & Exposure Awareness</h3>
        <div className="text-gray-400">No risk information available</div>
      </div>
    );
  }

  const getExposureLevelColor = (level: string) => {
    switch (level) {
      case 'low':
        return 'text-green-500';
      case 'moderate':
        return 'text-yellow-500';
      case 'elevated':
        return 'text-orange-500';
      case 'critical':
        return 'text-red-500';
      default:
        return 'text-gray-400';
    }
  };

  const getComplianceStatusColor = (status: string) => {
    switch (status) {
      case 'compliant':
        return 'text-green-500';
      case 'warning':
        return 'text-yellow-500';
      case 'non_compliant':
        return 'text-red-500';
      default:
        return 'text-gray-400';
    }
  };

  const getRiskBarWidth = (value: number) => {
    return `${Math.min(value, 100)}%`;
  };

  return (
    <div className="bg-[#0a0a0a] border border-gray-800 rounded-xl p-6">
      <h3 className="text-xl font-semibold text-white mb-4">Risk & Exposure Awareness</h3>
      
      <div className="space-y-6">
        {/* Current Exposure Level */}
        <div>
          <div className="flex justify-between items-center mb-2">
            <span className="text-gray-400">Current Exposure Level</span>
            <span className={`font-medium ${getExposureLevelColor(riskData.exposureLevel)}`}>
              {riskData.exposureLevel.charAt(0).toUpperCase() + riskData.exposureLevel.slice(1)}
            </span>
          </div>
          <div className="w-full bg-gray-800 rounded-full h-2.5">
            <div 
              className={`h-2.5 rounded-full ${
                riskData.exposureLevel === 'low' ? 'bg-green-500' :
                riskData.exposureLevel === 'moderate' ? 'bg-yellow-500' :
                riskData.exposureLevel === 'elevated' ? 'bg-orange-500' : 'bg-red-500'
              }`}
              style={{ width: getRiskBarWidth(riskData.riskScore) }}
            ></div>
          </div>
        </div>

        {/* Risk Score */}
        <div className="flex justify-between items-center">
          <span className="text-gray-400">Overall Risk Score</span>
          <span className="text-white font-medium">{riskData.riskScore}/100</span>
        </div>

        {/* Risk Tolerance Comparison */}
        <div className="flex justify-between items-center">
          <span className="text-gray-400">Risk Tolerance</span>
          <span className="text-white font-medium">{riskData.riskTolerance}/100</span>
        </div>

        {/* Compliance Status */}
        <div className="flex justify-between items-center">
          <span className="text-gray-400">Compliance Status</span>
          <span className={`font-medium ${getComplianceStatusColor(riskData.complianceStatus)}`}>
            {riskData.complianceStatus.replace('_', ' ').toUpperCase()}
          </span>
        </div>

        {/* Risk Categories */}
        <div className="space-y-4">
          <h4 className="text-lg font-medium text-white">Risk Categories</h4>
          
          <div className="space-y-3">
            <div>
              <div className="flex justify-between mb-1">
                <span className="text-gray-400">Market Risk</span>
                <span className="text-white">{riskData.marketRisk}%</span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-2">
                <div 
                  className="h-2 rounded-full bg-blue-500" 
                  style={{ width: getRiskBarWidth(riskData.marketRisk) }}
                ></div>
              </div>
            </div>

            <div>
              <div className="flex justify-between mb-1">
                <span className="text-gray-400">Volatility Risk</span>
                <span className="text-white">{riskData.volatilityRisk}%</span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-2">
                <div 
                  className="h-2 rounded-full bg-purple-500" 
                  style={{ width: getRiskBarWidth(riskData.volatilityRisk) }}
                ></div>
              </div>
            </div>

            <div>
              <div className="flex justify-between mb-1">
                <span className="text-gray-400">Concentration Risk</span>
                <span className="text-white">{riskData.concentrationRisk}%</span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-2">
                <div 
                  className="h-2 rounded-full bg-yellow-500" 
                  style={{ width: getRiskBarWidth(riskData.concentrationRisk) }}
                ></div>
              </div>
            </div>

            <div>
              <div className="flex justify-between mb-1">
                <span className="text-gray-400">Liquidity Risk</span>
                <span className="text-white">{riskData.liquidityRisk}%</span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-2">
                <div 
                  className="h-2 rounded-full bg-indigo-500" 
                  style={{ width: getRiskBarWidth(riskData.liquidityRisk) }}
                ></div>
              </div>
            </div>

            <div>
              <div className="flex justify-between mb-1">
                <span className="text-gray-400">Currency Risk</span>
                <span className="text-white">{riskData.currencyRisk}%</span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-2">
                <div 
                  className="h-2 rounded-full bg-pink-500" 
                  style={{ width: getRiskBarWidth(riskData.currencyRisk) }}
                ></div>
              </div>
            </div>
          </div>
        </div>

        {/* Additional Risk Indicators */}
        {riskData.marginUsage !== undefined && (
          <div className="flex justify-between items-center">
            <span className="text-gray-400">Margin Usage</span>
            <span className="text-white font-medium">{riskData.marginUsage}%</span>
          </div>
        )}

        {riskData.leverageRatio !== undefined && (
          <div className="flex justify-between items-center">
            <span className="text-gray-400">Leverage Ratio</span>
            <span className="text-white font-medium">{riskData.leverageRatio}x</span>
          </div>
        )}

        {riskData.stopLossCoverage !== undefined && (
          <div className="flex justify-between items-center">
            <span className="text-gray-400">Stop-Loss Coverage</span>
            <span className={`font-medium ${riskData.stopLossCoverage ? 'text-green-500' : 'text-red-500'}`}>
              {riskData.stopLossCoverage ? 'Active' : 'Inactive'}
            </span>
          </div>
        )}
      </div>
    </div>
  );
};

export default RiskExposure;