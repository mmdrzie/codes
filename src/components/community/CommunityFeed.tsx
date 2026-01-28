'use client';

import React, { useEffect, useState } from 'react';
import { CommunityPost as CommunityPostType } from '@/types/community';
import { getCommunityPosts } from '@/services/communityService';
import CommunityPost from './CommunityPost';
import EmptyCommunityState from './EmptyCommunityState';

interface CommunityFeedProps {
  isAuthenticated: boolean;
}

const CommunityFeed: React.FC<CommunityFeedProps> = ({ isAuthenticated }) => {
  const [posts, setPosts] = useState<CommunityPostType[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchPosts = async () => {
      try {
        setLoading(true);
        const response = await getCommunityPosts({ limit: 20, offset: 0 });
        setPosts(response.posts);
        setError(null);
      } catch (err) {
        console.error('Error fetching community posts:', err);
        setError(err instanceof Error ? err.message : 'Failed to load posts');
        setPosts([]);
      } finally {
        setLoading(false);
      }
    };

    fetchPosts();
  }, []);

  if (!isAuthenticated) {
    return (
      <div className="bg-gray-900 border border-gray-800 rounded-sm p-8 text-center">
        <h3 className="text-xl font-semibold text-gray-300 mb-2">Authentication Required</h3>
        <p className="text-gray-500 mb-4">
          Please log in to view and participate in the analytical community.
        </p>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="bg-gray-900 border border-gray-800 rounded-sm p-8 text-center">
        <div className="text-gray-500">Loading posts...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-gray-900 border border-gray-800 rounded-sm p-8 text-center">
        <h3 className="text-xl font-semibold text-gray-300 mb-2">Error Loading Posts</h3>
        <p className="text-red-500 mb-4">{error}</p>
        <p className="text-gray-500">Please try again later.</p>
      </div>
    );
  }

  if (posts.length === 0) {
    return <EmptyCommunityState />;
  }

  return (
    <div>
      {posts.map((post) => (
        <CommunityPost key={post.id} post={post} />
      ))}
    </div>
  );
};

export default CommunityFeed;