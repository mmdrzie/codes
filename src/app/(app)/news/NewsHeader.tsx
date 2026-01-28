'use client';

import React from 'react';

interface NewsHeaderProps {
  title?: string;
}

export const NewsHeader: React.FC<NewsHeaderProps> = ({ title = 'QuantumIQ News' }) => {
  return (
    <header className="bg-gray-900 border-b border-gray-800 py-6">
      <div className="container mx-auto px-4 max-w-6xl">
        <h1 className="text-3xl font-bold text-white">{title}</h1>
        <p className="text-gray-400 mt-2">
          Official project communications, security updates, and technical announcements
        </p>
      </div>
    </header>
  );
};