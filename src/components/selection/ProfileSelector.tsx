'use client';

import React from 'react';
import { BehavioralProfile } from '@/types/selection';

interface ProfileSelectorProps {
  profiles: BehavioralProfile[];
  selectedProfiles: string[];
  onProfileToggle: (profileId: string) => void;
}

const ProfileSelector: React.FC<ProfileSelectorProps> = ({
  profiles,
  selectedProfiles,
  onProfileToggle
}) => {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {profiles.map(profile => (
        <div 
          key={profile.id}
          className={`border rounded-lg p-4 cursor-pointer transition-all ${
            (selectedProfiles.includes(profile.id)) 
              ? 'border-blue-500 bg-blue-900/20' 
              : 'border-[#262626] hover:border-[#333333]'
          }`}
          onClick={() => onProfileToggle(profile.id)}
        >
          <div className="flex justify-between items-start">
            <div>
              <h3 className="font-medium text-white">{profile.name}</h3>
              <p className="text-sm text-gray-400 mt-2">{profile.description}</p>
              
              <div className="mt-3 text-xs text-gray-500 space-y-1">
                <div><strong>Info Processing:</strong> {profile.characteristics.informationProcessing}</div>
                <div><strong>Alert Sensitivity:</strong> {profile.characteristics.alertSensitivity}</div>
                <div><strong>Data Depth:</strong> {profile.characteristics.dataDepthPreference}</div>
                <div><strong>Update Frequency:</strong> {profile.characteristics.updateFrequency}</div>
                <div><strong>Computation:</strong> {profile.characteristics.computationIntensity}</div>
              </div>
            </div>
            
            {selectedProfiles.includes(profile.id) && (
              <span className="text-blue-400 text-sm">Active</span>
            )}
          </div>
        </div>
      ))}
    </div>
  );
};

export default ProfileSelector;