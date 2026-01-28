'use client';

import React from 'react';
import { NewsMeta } from './NewsMeta';
import { NewsPost } from '@/types/news';

interface NewsCardProps {
  post: NewsPost;
}

// Simple sanitization function to prevent XSS
const sanitizeHTML = (html: string): string => {
  // Remove script tags and other potentially dangerous elements
  return html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
             .replace(/javascript:/gi, '')
             .replace(/on\w+="[^"]*"/gi, '');
};

// Simple function to strip HTML tags for text preview
const stripHtmlTags = (html: string): string => {
  const tmp = document.createElement('div');
  tmp.innerHTML = html;
  return tmp.textContent || tmp.innerText || '';
};

export const NewsCard: React.FC<NewsCardProps> = ({ post }) => {
  // Sanitize content for security
  const sanitizedContent = sanitizeHTML(post.content);
  
  // Create plain text summary
  const plainTextSummary = stripHtmlTags(post.summary || post.content.substring(0, 200) + '...');

  // Determine styling based on importance
  const getImportanceStyling = () => {
    switch(post.importance) {
      case 'critical':
        return 'border-l-4 border-red-700 bg-gray-900/50';
      case 'important':
        return 'border-l-4 border-blue-600 bg-gray-900/30';
      default:
        return 'border-l-4 border-gray-600 bg-gray-900/20';
    }
  };

  return (
    <article 
      className={`border border-gray-800 rounded-lg p-6 transition-all duration-200 hover:bg-gray-900/40 ${getImportanceStyling()}`}
      aria-label={`News article: ${post.title}`}
    >
      <div className="flex flex-col md:flex-row md:justify-between md:items-start gap-4 mb-4">
        <div>
          <h2 className="text-xl font-bold text-white mb-2">{post.title}</h2>
          <p className="text-gray-300 mb-4">{plainTextSummary}</p>
        </div>
        
        <NewsMeta 
          author={post.author} 
          publishedAt={post.publishedAt} 
          category={post.category} 
          importance={post.importance}
        />
      </div>
      
      <div 
        className="prose prose-invert max-w-none text-gray-300 mt-4"
        dangerouslySetInnerHTML={{ __html: sanitizedContent }}
      />
    </article>
  );
};