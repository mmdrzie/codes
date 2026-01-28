'use client';

import React from 'react';
import { UserAccountData } from '@/types/dashboard';

interface AccountIdentityProps {
  accountData: UserAccountData | null;
  status: 'loading' | 'loaded' | 'error' | 'empty';
}

const AccountIdentity: React.FC<AccountIdentityProps> = ({ accountData, status }) => {
  if (status === 'loading') {
    return (
      <div className="bg-[#0a0a0a] border border-gray-800 rounded-xl p-6">
        <div className="animate-pulse">
          <div className="h-6 bg-gray-800 rounded w-1/3 mb-4"></div>
          <div className="space-y-3">
            {[...Array(6)].map((_, i) => (
              <div key={i} className="h-4 bg-gray-800 rounded w-2/3"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (status === 'error') {
    return (
      <div className="bg-[#0a0a0a] border border-gray-800 rounded-xl p-6">
        <h3 className="text-xl font-semibold text-white mb-4">Account & Identity</h3>
        <div className="text-red-500">Failed to load account information</div>
      </div>
    );
  }

  if (status === 'empty' || !accountData) {
    return (
      <div className="bg-[#0a0a0a] border border-gray-800 rounded-xl p-6">
        <h3 className="text-xl font-semibold text-white mb-4">Account & Identity</h3>
        <div className="text-gray-400">No account information available</div>
      </div>
    );
  }

  const formatDate = (date: Date | null) => {
    if (!date) return 'Never';
    return new Date(date).toLocaleString();
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'text-green-500';
      case 'restricted':
        return 'text-yellow-500';
      case 'limited':
        return 'text-orange-500';
      case 'inactive':
        return 'text-red-500';
      default:
        return 'text-gray-400';
    }
  };

  const getAccessLevelLabel = (level: string) => {
    switch (level) {
      case 'basic':
        return 'Basic Plan';
      case 'standard':
        return 'Standard Plan';
      case 'premium':
        return 'Premium Plan';
      case 'enterprise':
        return 'Enterprise Plan';
      default:
        return 'Unknown Plan';
    }
  };

  return (
    <div className="bg-[#0a0a0a] border border-gray-800 rounded-xl p-6">
      <h3 className="text-xl font-semibold text-white mb-4">Account & Identity</h3>
      <div className="space-y-4">
        <div className="flex justify-between items-center">
          <span className="text-gray-400">Account Status</span>
          <span className={`font-medium ${getStatusColor(accountData.status)}`}>
            {accountData.status.charAt(0).toUpperCase() + accountData.status.slice(1)}
          </span>
        </div>
        
        <div className="flex justify-between items-center">
          <span className="text-gray-400">Access Level</span>
          <span className="text-white">{getAccessLevelLabel(accountData.accessLevel)}</span>
        </div>
        
        <div className="flex justify-between items-center">
          <span className="text-gray-400">Two-Factor Auth</span>
          <span className={`font-medium ${accountData.twoFactorEnabled ? 'text-green-500' : 'text-red-500'}`}>
            {accountData.twoFactorEnabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>
        
        <div className="flex justify-between items-center">
          <span className="text-gray-400">Email Verified</span>
          <span className={`font-medium ${accountData.emailVerified ? 'text-green-500' : 'text-red-500'}`}>
            {accountData.emailVerified ? 'Yes' : 'No'}
          </span>
        </div>
        
        <div className="flex justify-between items-center">
          <span className="text-gray-400">Last Login</span>
          <span className="text-white">{formatDate(accountData.lastLogin)}</span>
        </div>
        
        <div className="flex justify-between items-center">
          <span className="text-gray-400">Account Created</span>
          <span className="text-white">{formatDate(accountData.accountCreated)}</span>
        </div>
        
        {accountData.currentDevice && (
          <div className="flex justify-between items-center">
            <span className="text-gray-400">Current Device</span>
            <span className="text-white">{accountData.currentDevice}</span>
          </div>
        )}
        
        {accountData.ipRegion && (
          <div className="flex justify-between items-center">
            <span className="text-gray-400">Location</span>
            <span className="text-white">{accountData.ipRegion}</span>
          </div>
        )}
      </div>
    </div>
  );
};

export default AccountIdentity;