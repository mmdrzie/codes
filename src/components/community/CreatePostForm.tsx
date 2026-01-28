'use client';

import React, { useState } from 'react';
import { CreatePostInput } from '@/types/community';
import { createCommunityPost } from '@/services/communityService';

interface CreatePostFormProps {
  onPostCreated: () => void;
  userId: string;
  username: string;
}

const CreatePostForm: React.FC<CreatePostFormProps> = ({ onPostCreated, userId, username }) => {
  const [content, setContent] = useState('');
  const [tags, setTags] = useState<string[]>([]);
  const [analysisType, setAnalysisType] = useState<'Technical' | 'Fundamental' | 'Sentiment' | 'Other'>('Other');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [currentTag, setCurrentTag] = useState('');

  const charCount = content.length;
  const isWithinLimits = charCount >= 50 && charCount <= 2000;
  const isDisabled = isLoading || !isWithinLimits;

  const handleAddTag = () => {
    if (currentTag.trim() && !tags.includes(currentTag.trim())) {
      setTags([...tags, currentTag.trim()]);
      setCurrentTag('');
    }
  };

  const handleRemoveTag = (tagToRemove: string) => {
    setTags(tags.filter(tag => tag !== tagToRemove));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!isWithinLimits) {
      setError(`Post must be between 50 and 2000 characters (${charCount}/${2000})`);
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const postData: CreatePostInput = {
        content,
        tags,
        analysisType
      };
      
      await createCommunityPost(postData);
      // Reset form after successful submission
      setContent('');
      setTags([]);
      setAnalysisType('Other');
      onPostCreated();
    } catch (err) {
      console.error('Error creating post:', err);
      setError(err instanceof Error ? err.message : 'Failed to create post');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-sm p-4 mb-6">
      <form onSubmit={handleSubmit}>
        <div className="mb-4">
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder={`Share your analysis, @${username}...`}
            className="w-full bg-gray-800 text-white border border-gray-700 rounded-sm p-3 focus:outline-none focus:ring-1 focus:ring-blue-500 min-h-[120px]"
            disabled={isLoading}
          />
          <div className="flex justify-between items-center mt-2">
            <div className={`text-xs ${charCount < 50 ? 'text-red-500' : charCount > 2000 ? 'text-red-500' : 'text-gray-500'}`}>
              {charCount}/2000
              {charCount < 50 && ' (minimum 50 characters)'}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          <div>
            <label className="block text-gray-400 text-sm mb-2">Analysis Type</label>
            <select
              value={analysisType}
              onChange={(e) => setAnalysisType(e.target.value as any)}
              className="w-full bg-gray-800 text-white border border-gray-700 rounded-sm p-2 focus:outline-none focus:ring-1 focus:ring-blue-500"
              disabled={isLoading}
            >
              <option value="Technical">Technical</option>
              <option value="Fundamental">Fundamental</option>
              <option value="Sentiment">Sentiment</option>
              <option value="Other">Other</option>
            </select>
          </div>

          <div>
            <label className="block text-gray-400 text-sm mb-2">Tags</label>
            <div className="flex">
              <input
                type="text"
                value={currentTag}
                onChange={(e) => setCurrentTag(e.target.value)}
                placeholder="Add a tag..."
                className="flex-grow bg-gray-800 text-white border border-gray-700 rounded-l-sm p-2 focus:outline-none focus:ring-1 focus:ring-blue-500"
                disabled={isLoading}
                onKeyPress={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    handleAddTag();
                  }
                }}
              />
              <button
                type="button"
                onClick={handleAddTag}
                className="bg-gray-700 text-white px-3 rounded-r-sm border-y border-r border-gray-600 hover:bg-gray-600 disabled:opacity-50"
                disabled={isLoading || !currentTag.trim()}
              >
                Add
              </button>
            </div>
          </div>
        </div>

        {tags.length > 0 && (
          <div className="flex flex-wrap gap-2 mb-4">
            {tags.map((tag, index) => (
              <span 
                key={index} 
                className="inline-flex items-center bg-gray-800 text-gray-400 px-2 py-1 rounded-sm text-sm"
              >
                #{tag}
                <button
                  type="button"
                  onClick={() => handleRemoveTag(tag)}
                  className="ml-1 text-gray-500 hover:text-white"
                >
                  ×
                </button>
              </span>
            ))}
          </div>
        )}

        {error && (
          <div className="text-red-500 text-sm mb-3">{error}</div>
        )}

        <div className="flex justify-end">
          <button
            type="submit"
            disabled={isDisabled}
            className={`px-4 py-2 rounded-sm text-sm ${
              isDisabled 
                ? 'bg-gray-700 text-gray-500 cursor-not-allowed' 
                : 'bg-blue-600 text-white hover:bg-blue-700'
            }`}
          >
            {isLoading ? 'Posting...' : 'Post Analysis'}
          </button>
        </div>
      </form>
    </div>
  );
};

export default CreatePostForm;