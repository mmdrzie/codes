'use client';

import React from 'react';
import { FutureModule } from '@/types/selection';

interface FutureModuleToggleProps {
  module: FutureModule;
  isOptedIn: boolean;
  onToggle: (optedIn: boolean) => void;
}

const FutureModuleToggle: React.FC<FutureModuleToggleProps> = ({
  module,
  isOptedIn,
  onToggle
}) => {
  return (
    <div className="border border-[#262626] rounded-lg p-6 bg-[#0f0f0f]">
      <div className="flex justify-between items-start">
        <div>
          <h3 className="text-lg font-medium text-white">{module.name}</h3>
          <p className="text-gray-400 mt-2">{module.description}</p>
          
          <div className="mt-4 space-y-2 text-sm">
            <div className="flex items-center">
              <span className="text-gray-500 w-32">Release:</span>
              <span className="text-amber-400">{module.plannedRelease}</span>
            </div>
            
            <div className="flex items-center">
              <span className="text-gray-500 w-32">Prerequisites:</span>
              <div className="flex flex-wrap gap-1">
                {module.prerequisites.map(prereq => (
                  <span key={prereq} className="bg-gray-700 text-gray-300 text-xs px-2 py-1 rounded">
                    {prereq}
                  </span>
                ))}
              </div>
            </div>
            
            <div className="flex items-center">
              <span className="text-gray-500 w-32">Risk:</span>
              <span className="text-red-400">{module.riskDisclosure}</span>
            </div>
            
            <div className="flex items-center">
              <span className="text-gray-500 w-32">Data Notice:</span>
              <span className="text-yellow-400">{module.dataCollectionNotice}</span>
            </div>
            
            <div className="flex items-center">
              <span className="text-gray-500 w-32">Revocation:</span>
              <span className="text-green-400">{module.revocationRights}</span>
            </div>
            
            <div className="flex items-center">
              <span className="text-gray-500 w-32">Status:</span>
              <span className={`${
                module.waitlistStatus === 'open' ? 'text-green-400' :
                module.waitlistStatus === 'closed' ? 'text-red-400' : 'text-yellow-400'
              }`}>
                {module.waitlistStatus}
              </span>
            </div>
          </div>
        </div>
        
        <label className="flex items-center cursor-pointer">
          <input
            type="checkbox"
            checked={isOptedIn}
            onChange={(e) => onToggle(e.target.checked)}
            className="sr-only"
          />
          <div className={`relative w-11 h-6 rounded-full ${
            isOptedIn 
              ? 'bg-blue-600' 
              : 'bg-gray-600'
          }`}>
            <div className={`absolute top-0.5 left-0.5 bg-white border border-gray-300 w-5 h-5 rounded-full transition-transform ${
              isOptedIn 
                ? 'transform translate-x-5' 
                : ''
            }`}></div>
          </div>
          <span className="ml-3 text-white">
            {isOptedIn ? 'Opted In' : 'Opt In'}
          </span>
        </label>
      </div>
    </div>
  );
};

export default FutureModuleToggle;