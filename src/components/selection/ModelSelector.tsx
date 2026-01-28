'use client';

import React from 'react';
import { AIModel, ModelCostTier, ModelLatencyClass, ModelStatus } from '@/types/selection';

interface ModelSelectorProps {
  title: string;
  description: string;
  currentModelId: string;
  models: AIModel[];
  onModelChange: (modelId: string) => void;
  capability: string;
}

const ModelSelector: React.FC<ModelSelectorProps> = ({
  title,
  description,
  currentModelId,
  models,
  onModelChange,
  capability
}) => {
  const getModelCostTierColor = (tier: ModelCostTier) => {
    switch (tier) {
      case ModelCostTier.STANDARD: return 'text-blue-400';
      case ModelCostTier.PREMIUM: return 'text-purple-400';
      case ModelCostTier.ENTERPRISE: return 'text-amber-400';
      default: return 'text-gray-400';
    }
  };

  const getModelLatencyClassColor = (cls: ModelLatencyClass) => {
    switch (cls) {
      case ModelLatencyClass.FAST: return 'text-green-400';
      case ModelLatencyClass.BALANCED: return 'text-yellow-400';
      case ModelLatencyClass.DEEP: return 'text-purple-400';
      default: return 'text-gray-400';
    }
  };

  const getStatusColor = (status: ModelStatus) => {
    switch (status) {
      case ModelStatus.ACTIVE: return 'text-green-400';
      case ModelStatus.DEPRECATED: return 'text-red-400';
      case ModelStatus.BETA: return 'text-amber-400';
      default: return 'text-gray-400';
    }
  };

  return (
    <div className="bg-[#0f0f0f] border border-[#1f1f1f] rounded-lg p-6">
      <h3 className="text-lg font-medium text-white mb-3">{title}</h3>
      <p className="text-sm text-gray-400 mb-4">{description}</p>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {models.map(model => (
          <div 
            key={model.id}
            className={`border rounded-lg p-4 cursor-pointer transition-all ${
              (currentModelId === model.id) 
                ? 'border-blue-500 bg-blue-900/20' 
                : 'border-[#262626] hover:border-[#333333]'
            }`}
            onClick={() => onModelChange(model.id)}
          >
            <div className="flex justify-between items-start">
              <h4 className="font-medium text-white">{model.name}</h4>
              <span className={`text-xs px-2 py-1 rounded ${getModelCostTierColor(model.costTier)}`}>
                {model.costTier}
              </span>
            </div>
            <p className="text-sm text-gray-400 mt-1">{model.description}</p>
            <div className="flex flex-wrap gap-2 mt-3 text-xs">
              <span className="text-gray-500">Ctx: {model.contextWindowSize.toLocaleString()}</span>
              <span className={`px-2 py-1 rounded ${getModelLatencyClassColor(model.latencyClass)}`}>
                {model.latencyClass}
              </span>
              <span className={`px-2 py-1 rounded ${getStatusColor(model.status)}`}>
                {model.status}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ModelSelector;