'use client';

import React from 'react';
import { Capability, RiskLevel, ResourceImpact } from '@/types/selection';

interface CapabilityToggleProps {
  capability: Capability;
  isEnabled: boolean;
  onToggle: (enabled: boolean) => void;
}

const CapabilityToggle: React.FC<CapabilityToggleProps> = ({
  capability,
  isEnabled,
  onToggle
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
    <div 
      className={`border rounded-lg p-4 ${
        capability.isLocked ? 'opacity-60' : ''
      } ${isEnabled ? 'border-blue-500/50 bg-blue-900/10' : 'border-[#262626]'}`}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <input
            type="checkbox"
            checked={isEnabled}
            onChange={(e) => onToggle(e.target.checked)}
            disabled={capability.isLocked}
            className="w-4 h-4 text-blue-600 bg-gray-700 border-gray-600 rounded focus:ring-blue-500"
          />
          <div>
            <h3 className="font-medium text-white">{capability.name}</h3>
            <p className="text-sm text-gray-400">{capability.description}</p>
            
            <div className="flex flex-wrap gap-3 mt-2 text-xs">
              <span className={`${getRiskLevelColor(capability.riskLevel)}`}>
                Risk: {capability.riskLevel}
              </span>
              <span className={`${getResourceImpactColor(capability.resourceImpact)}`}>
                Resources: {capability.resourceImpact}
              </span>
              {capability.isBeta && <span className="text-amber-400">Beta</span>}
              {capability.isLocked && <span className="text-red-400">Locked</span>}
            </div>
          </div>
        </div>
        
        {capability.isLocked && (
          <div className="flex items-center text-sm text-red-400">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
            Requires Permissions
          </div>
        )}
      </div>
      
      {(capability.dependencies.length > 0 || capability.complianceTags.length > 0) && (
        <div className="mt-3 pt-3 border-t border-[#262626] text-xs text-gray-500">
          {capability.dependencies.length > 0 && (
            <div className="mb-1">
              <span className="font-medium">Dependencies:</span> {capability.dependencies.join(', ')}
            </div>
          )}
          {capability.complianceTags.length > 0 && (
            <div>
              <span className="font-medium">Compliance:</span> {capability.complianceTags.join(', ')}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default CapabilityToggle;