'use client';

import React, { useState, useEffect } from 'react';
import { NewsCard } from './NewsCard';
import { NewsFilters } from './NewsFilters';
import { NewsPost } from '@/types/news';

interface NewsListProps {
  posts: NewsPost[];
}

export const NewsList: React.FC<NewsListProps> = ({ posts }) => {
  const [filteredPosts, setFilteredPosts] = useState<NewsPost[]>(posts);
  const [filters, setFilters] = useState({
    category: '',
    importance: '',
    searchQuery: ''
  });

  useEffect(() => {
    let result = [...posts];
    
    if (filters.category) {
      result = result.filter(post => post.category === filters.category);
    }
    
    if (filters.importance) {
      result = result.filter(post => post.importance === filters.importance);
    }
    
    if (filters.searchQuery) {
      const query = filters.searchQuery.toLowerCase();
      result = result.filter(post => 
        post.title.toLowerCase().includes(query) || 
        post.summary.toLowerCase().includes(query) ||
        post.content.toLowerCase().includes(query)
      );
    }
    
    setFilteredPosts(result);
  }, [filters, posts]);

  const handleFilterChange = (newFilters: typeof filters) => {
    setFilters(newFilters);
  };

  return (
    <div className="w-full">
      <NewsFilters onFilterChange={handleFilterChange} initialFilters={filters} />
      
      <div className="mt-8 space-y-6">
        {filteredPosts.length > 0 ? (
          filteredPosts.map((post) => (
            <NewsCard key={post.id} post={post} />
          ))
        ) : (
          <div className="text-center py-12">
            <p className="text-gray-500 text-lg">No news articles match your current filters.</p>
          </div>
        )}
      </div>
    </div>
  );
};