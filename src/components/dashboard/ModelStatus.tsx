'use client';

import React from 'react';
import { ModelStatus as ModelStatusType } from '@/types/dashboard';

interface ModelStatusProps {
  modelData: ModelStatusType | null;
  status: 'loading' | 'loaded' | 'error' | 'empty';
}

const ModelStatus: React.FC<ModelStatusProps> = ({ modelData, status }) => {
  if (status === 'loading') {
    return (
      <div className="bg-[#0a0a0a] border border-gray-800 rounded-xl p-6">
        <div className="animate-pulse">
          <div className="h-6 bg-gray-800 rounded w-1/3 mb-4"></div>
          <div className="space-y-3">
            {[...Array(6)].map((_, i) => (
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
        <h3 className="text-xl font-semibold text-white mb-4">AI / Model Interaction Status</h3>
        <div className="text-red-500">Failed to load model status information</div>
      </div>
    );
  }

  if (status === 'empty' || !modelData) {
    return (
      <div className="bg-[#0a0a0a] border border-gray-800 rounded-xl p-6">
        <h3 className="text-xl font-semibold text-white mb-4">AI / Model Interaction Status</h3>
        <div className="text-gray-400">No model status information available</div>
      </div>
    );
  }

  const getReadinessColor = (state: string) => {
    switch (state) {
      case 'ready':
        return 'text-green-500';
      case 'training':
        return 'text-yellow-500';
      case 'offline':
        return 'text-red-500';
      case 'maintenance':
        return 'text-orange-500';
      default:
        return 'text-gray-400';
    }
  };

  const getQueueStatusColor = (status: string) => {
    switch (status) {
      case 'idle':
        return 'text-green-500';
      case 'processing':
        return 'text-yellow-500';
      case 'queued':
        return 'text-blue-500';
      default:
        return 'text-gray-400';
    }
  };

  const getSubscriptionStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'text-green-500';
      case 'pending':
        return 'text-yellow-500';
      case 'expired':
        return 'text-red-500';
      default:
        return 'text-gray-400';
    }
  };

  const formatDate = (date: Date | null) => {
    if (!date) return 'Never';
    return new Date(date).toLocaleString();
  };

  return (
    <div className="bg-[#0a0a0a] border border-gray-800 rounded-xl p-6">
      <h3 className="text-xl font-semibold text-white mb-4">AI / Model Interaction Status</h3>
      
      <div className="space-y-4">
        {/* Active Models */}
        <div>
          <h4 className="text-gray-400 text-sm mb-2">Active Models</h4>
          <div className="flex flex-wrap gap-2">
            {modelData.activeModels.length > 0 ? (
              modelData.activeModels.map((model, index) => (
                <span key={index} className="bg-gray-800 text-white px-3 py-1 rounded-full text-sm">
                  {model}
                </span>
              ))
            ) : (
              <span className="text-gray-500 italic">No active models</span>
            )}
          </div>
        </div>

        {/* Readiness State */}
        <div className="flex justify-between items-center">
          <span className="text-gray-400">Readiness State</span>
          <span className={`font-medium ${getReadinessColor(modelData.readinessState)}`}>
            {modelData.readinessState.charAt(0).toUpperCase() + modelData.readinessState.slice(1)}
          </span>
        </div>

        {/* Last Analysis */}
        <div className="flex justify-between items-center">
          <span className="text-gray-400">Last Analysis</span>
          <span className="text-white">{formatDate(modelData.lastAnalysis)}</span>
        </div>

        {/* Decision Support Availability */}
        <div className="flex justify-between items-center">
          <span className="text-gray-400">Decision Support</span>
          <span className={`font-medium ${modelData.decisionSupportAvailable ? 'text-green-500' : 'text-red-500'}`}>
            {modelData.decisionSupportAvailable ? 'Available' : 'Unavailable'}
          </span>
        </div>

        {/* Analysis Queue Status */}
        <div className="flex justify-between items-center">
          <span className="text-gray-400">Analysis Queue</span>
          <span className={`font-medium ${getQueueStatusColor(modelData.analysisQueueStatus)}`}>
            {modelData.analysisQueueStatus.charAt(0).toUpperCase() + modelData.analysisQueueStatus.slice(1)}
          </span>
        </div>

        {/* Model Version */}
        <div className="flex justify-between items-center">
          <span className="text-gray-400">Model Version</span>
          <span className="text-white">{modelData.modelVersion}</span>
        </div>

        {/* Data Freshness */}
        <div className="flex justify-between items-center">
          <span className="text-gray-400">Data Freshness</span>
          <span className="text-white">{modelData.dataFreshness}</span>
        </div>

        {/* Subscription Status */}
        <div className="flex justify-between items-center">
          <span className="text-gray-400">Subscription Status</span>
          <span className={`font-medium ${getSubscriptionStatusColor(modelData.subscriptionStatus)}`}>
            {modelData.subscriptionStatus.charAt(0).toUpperCase() + modelData.subscriptionStatus.slice(1)}
          </span>
        </div>

        {/* API Usage Stats */}
        <div className="pt-2 border-t border-gray-800">
          <h4 className="text-gray-400 text-sm mb-2">API Usage Statistics</h4>
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-gray-900 p-3 rounded-lg">
              <div className="text-gray-400 text-sm">Calls Made</div>
              <div className="text-white font-medium">{modelData.apiUsageStats.callsMade}</div>
            </div>
            <div className="bg-gray-900 p-3 rounded-lg">
              <div className="text-gray-400 text-sm">Remaining Quota</div>
              <div className="text-white font-medium">{modelData.apiUsageStats.remainingQuota}</div>
            </div>
          </div>
        </div>

        {/* Disclaimer */}
        <div className="mt-4 p-3 bg-gray-900 rounded-lg border border-gray-700">
          <p className="text-yellow-400 text-sm italic">
            <strong>Disclaimer:</strong> Model outputs are for informational purposes only and do not constitute financial advice or trading recommendations.
          </p>
        </div>
      </div>
    </div>
  );
};

export default ModelStatus;