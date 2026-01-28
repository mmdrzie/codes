'use client';

import React from 'react';

interface NewsMetaProps {
  author: string;
  publishedAt: Date;
  category: string;
  importance: 'normal' | 'important' | 'critical';
}

export const NewsMeta: React.FC<NewsMetaProps> = ({ 
  author, 
  publishedAt, 
  category, 
  importance 
}) => {
  // Format date using built-in JavaScript methods
  const formattedDate = new Date(publishedAt).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
  
  // Get importance label and styling
  const getImportanceInfo = () => {
    switch(importance) {
      case 'critical':
        return { label: 'CRITICAL', className: 'bg-red-900/50 text-red-300 px-2 py-1 rounded text-xs font-bold' };
      case 'important':
        return { label: 'IMPORTANT', className: 'bg-blue-900/50 text-blue-300 px-2 py-1 rounded text-xs font-bold' };
      default:
        return { label: 'NORMAL', className: 'bg-gray-700/50 text-gray-300 px-2 py-1 rounded text-xs' };
    }
  };

  const importanceInfo = getImportanceInfo();

  return (
    <div className="flex flex-col items-end gap-2 text-sm text-gray-400">
      <div className="flex gap-4">
        <span className={importanceInfo.className}>
          {importanceInfo.label}
        </span>
        <span className="bg-gray-800 px-2 py-1 rounded text-xs capitalize">
          {category}
        </span>
      </div>
      <div className="text-right">
        <p className="font-medium text-gray-300">{author}</p>
        <time dateTime={new Date(publishedAt).toISOString()} className="text-xs text-gray-500">
          {formattedDate}
        </time>
      </div>
    </div>
  );
};