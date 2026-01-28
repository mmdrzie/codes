'use client';

import React from 'react';
import { ConfigurationPreset, RiskLevel, ResourceImpact } from '@/types/selection';

interface PresetSelectorProps {
  presets: ConfigurationPreset[];
  onApplyPreset: (presetId: string) => void;
}

const PresetSelector: React.FC<PresetSelectorProps> = ({
  presets,
  onApplyPreset
}) => {
  const getRiskLevelColor = (level: RiskLevel) => {
    switch (level) {
      case RiskLevel.LOW: return 'text-green-400';
      case RiskLevel.MEDIUM: return 'text-yellow-400';
      case RiskLevel.HIGH: return 'text-orange-400';
      case RiskLevel.CRITICAL: return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  const getResourceImpactColor = (impact: ResourceImpact) => {
    switch (impact) {
      case ResourceImpact.MINIMAL: return 'text-green-400';
      case ResourceImpact.MODERATE: return 'text-yellow-400';
      case ResourceImpact.HIGH: return 'text-orange-400';
      case ResourceImpact.EXTREME: return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {presets.map(preset => (
        <div 
          key={preset.id}
          className="border border-[#262626] rounded-lg p-5 hover:border-[#333333] transition-colors"
        >
          <div className="flex justify-between items-start">
            <div>
              <h3 className="font-medium text-white">{preset.name}</h3>
              <p className="text-sm text-gray-400 mt-1">{preset.description}</p>
              
              <div className="mt-3 space-y-1 text-xs text-gray-500">
                <div>Target: {preset.targetAudience}</div>
                <div>Risk: <span className={getRiskLevelColor(preset.riskLevel)}>{preset.riskLevel}</span></div>
                <div>Resources: <span className={getResourceImpactColor(preset.resourceImpact)}>{preset.resourceImpact}</span></div>
              </div>
            </div>
            
            <button
              onClick={() => onApplyPreset(preset.id)}
              className="px-3 py-1 bg-gray-700 text-white text-sm rounded hover:bg-gray-600"
            >
              Apply
            </button>
          </div>
        </div>
      ))}
    </div>
  );
};

export default PresetSelector;