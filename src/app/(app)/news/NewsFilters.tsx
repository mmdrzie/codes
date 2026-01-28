'use client';

import React, { useState } from 'react';

interface NewsFiltersProps {
  onFilterChange: (filters: {
    category: string;
    importance: string;
    searchQuery: string;
  }) => void;
  initialFilters?: {
    category: string;
    importance: string;
    searchQuery: string;
  };
}

export const NewsFilters: React.FC<NewsFiltersProps> = ({ 
  onFilterChange, 
  initialFilters = { category: '', importance: '', searchQuery: '' } 
}) => {
  const [searchQuery, setSearchQuery] = useState(initialFilters.searchQuery);
  const [category, setCategory] = useState(initialFilters.category);
  const [importance, setImportance] = useState(initialFilters.importance);

  const categories = ['all', 'security', 'update', 'system', 'announcement'];
  const importanceLevels = ['all', 'normal', 'important', 'critical'];

  const handleInputChange = () => {
    onFilterChange({
      category: category === 'all' ? '' : category,
      importance: importance === 'all' ? '' : importance,
      searchQuery
    });
  };

  // Update filters when inputs change
  React.useEffect(() => {
    handleInputChange();
  }, [searchQuery, category, importance]);

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 mb-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="md:col-span-2">
          <label htmlFor="search" className="block text-sm font-medium text-gray-300 mb-1">
            Search
          </label>
          <input
            id="search"
            type="text"
            placeholder="Search news..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded-md px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        
        <div>
          <label htmlFor="category" className="block text-sm font-medium text-gray-300 mb-1">
            Category
          </label>
          <select
            id="category"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded-md px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            {categories.map(cat => (
              <option key={cat} value={cat}>
                {cat.charAt(0).toUpperCase() + cat.slice(1)}
              </option>
            ))}
          </select>
        </div>
        
        <div>
          <label htmlFor="importance" className="block text-sm font-medium text-gray-300 mb-1">
            Importance
          </label>
          <select
            id="importance"
            value={importance}
            onChange={(e) => setImportance(e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded-md px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            {importanceLevels.map(level => (
              <option key={level} value={level}>
                {level.charAt(0).toUpperCase() + level.slice(1)}
              </option>
            ))}
          </select>
        </div>
      </div>
    </div>
  );
};