'use client';

import React from 'react';
import { DecisionMode, DecisionAuthorityLevel } from '@/types/selection';

interface DecisionModeSelectorProps {
  currentMode: DecisionAuthorityLevel;
  modes: DecisionMode[];
  onModeChange: (modeId: DecisionAuthorityLevel) => void;
}

const DecisionModeSelector: React.FC<DecisionModeSelectorProps> = ({
  currentMode,
  modes,
  onModeChange
}) => {
  const getRiskLevelColor = (riskLevel: number) => {
    if (riskLevel <= 2) return 'text-green-400';
    if (riskLevel <= 3) return 'text-yellow-400';
    if (riskLevel <= 4) return 'text-orange-400';
    return 'text-red-400';
  };

  return (
    <div className="space-y-4">
      {modes.map(mode => (
        <div 
          key={mode.id}
          className={`border rounded-lg p-6 transition-all ${
            (currentMode === mode.id) 
              ? 'border-blue-500 bg-blue-900/20' 
              : 'border-[#262626] hover:border-[#333333]'
          }`}
        >
          <div className="flex justify-between items-start">
            <div>
              <h3 className="text-lg font-medium text-white">{mode.name}</h3>
              <p className="text-gray-400 mt-2">{mode.description}</p>
              
              <div className="mt-4 space-y-2">
                <div className="flex items-center text-sm">
                  <span className="text-gray-500 w-32">Risk Level:</span>
                  <span className={getRiskLevelColor(mode.riskLevel)}>
                    {mode.riskLevel}/5
                  </span>
                </div>
                
                <div className="flex items-center text-sm">
                  <span className="text-gray-500 w-32">Requires Auth:</span>
                  <span>{mode.requiresAuthentication ? 'Yes' : 'No'}</span>
                </div>
                
                <div className="flex items-center text-sm">
                  <span className="text-gray-500 w-32">Confirmation:</span>
                  <span>{mode.requiresConfirmation ? 'Required' : 'Not Required'}</span>
                </div>
                
                {mode.prerequisites.length > 0 && (
                  <div className="flex items-center text-sm">
                    <span className="text-gray-500 w-32">Prerequisites:</span>
                    <div className="flex flex-wrap gap-1">
                      {mode.prerequisites.map(prereq => (
                        <span key={prereq} className="bg-gray-700 text-gray-300 text-xs px-2 py-1 rounded">
                          {prereq}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
            
            <button
              onClick={() => onModeChange(mode.id)}
              className={`px-4 py-2 rounded ${
                currentMode === mode.id
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-700 text-white hover:bg-gray-600'
              }`}
            >
              {currentMode === mode.id ? 'Selected' : 'Select'}
            </button>
          </div>
        </div>
      ))}
    </div>
  );
};

export default DecisionModeSelector;