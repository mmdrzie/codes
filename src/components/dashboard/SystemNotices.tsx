'use client';

import React from 'react';
import { SystemNotice } from '@/types/dashboard';

interface SystemNoticesProps {
  notices: SystemNotice[];
  status: 'loading' | 'loaded' | 'error' | 'empty';
}

const SystemNotices: React.FC<SystemNoticesProps> = ({ notices, status }) => {
  if (status === 'loading') {
    return (
      <div className="bg-[#0a0a0a] border border-gray-800 rounded-xl p-6">
        <div className="animate-pulse">
          <div className="h-6 bg-gray-800 rounded w-1/3 mb-4"></div>
          <div className="space-y-4">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="flex space-x-3">
                <div className="w-3 h-3 bg-gray-800 rounded-full mt-1"></div>
                <div className="flex-1">
                  <div className="h-4 bg-gray-800 rounded w-1/4 mb-2"></div>
                  <div className="h-3 bg-gray-800 rounded w-3/4"></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (status === 'error') {
    return (
      <div className="bg-[#0a0a0a] border border-gray-800 rounded-xl p-6">
        <h3 className="text-xl font-semibold text-white mb-4">System & Security Notices</h3>
        <div className="text-red-500">Failed to load system notices</div>
      </div>
    );
  }

  if (status === 'empty' || notices.length === 0) {
    return (
      <div className="bg-[#0a0a0a] border border-gray-800 rounded-xl p-6">
        <h3 className="text-xl font-semibold text-white mb-4">System & Security Notices</h3>
        <div className="text-gray-400">No system notices at this time</div>
      </div>
    );
  }

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical':
        return 'text-red-500';
      case 'important':
        return 'text-yellow-500';
      case 'informational':
        return 'text-blue-400';
      default:
        return 'text-gray-400';
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'security':
        return '🔒';
      case 'policy':
        return '📋';
      case 'maintenance':
        return '🔧';
      case 'account_action':
        return '👤';
      default:
        return '🔔';
    }
  };

  const formatDate = (date: Date) => {
    return new Date(date).toLocaleString();
  };

  // Limit to 10 notices as per requirements
  const limitedNotices = notices.slice(0, 10);

  return (
    <div className="bg-[#0a0a0a] border border-gray-800 rounded-xl p-6">
      <h3 className="text-xl font-semibold text-white mb-4">System & Security Notices</h3>
      
      <div className="space-y-4">
        {limitedNotices.map((notice, index) => (
          <div 
            key={notice.id} 
            className={`border-l-4 pl-4 py-2 ${
              notice.priority === 'critical' ? 'border-red-500' :
              notice.priority === 'important' ? 'border-yellow-500' :
              'border-blue-400'
            }`}
          >
            <div className="flex justify-between items-start">
              <div className="flex items-start space-x-3">
                <span>{getCategoryIcon(notice.category)}</span>
                <div>
                  <div className="flex items-center space-x-2">
                    <h4 className={`font-medium ${getPriorityColor(notice.priority)}`}>
                      {notice.title}
                    </h4>
                    {!notice.read && (
                      <span className="w-2 h-2 bg-blue-500 rounded-full inline-block"></span>
                    )}
                  </div>
                  <p className="text-gray-400 text-sm mt-1">{notice.description}</p>
                </div>
              </div>
              <div className="text-right text-xs text-gray-500 whitespace-nowrap">
                {formatDate(notice.timestamp)}
              </div>
            </div>
          </div>
        ))}
      </div>
      
      {notices.length > 10 && (
        <div className="mt-4 text-center text-sm text-gray-500">
          Showing 10 of {notices.length} notices. <a href="#" className="text-blue-400 hover:underline">View all</a>
        </div>
      )}
    </div>
  );
};

export default SystemNotices;