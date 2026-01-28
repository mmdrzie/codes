'use client';

import React, { useState, useEffect } from 'react';
import { useAuth } from '@/hooks/useAuth';
import CreatePostForm from '@/components/community/CreatePostForm';
import CommunityFeed from '@/components/community/CommunityFeed';

const CommunityPage: React.FC = () => {
  const { user, loading: authLoading } = useAuth();
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  const handlePostCreated = () => {
    // Trigger a refresh of the feed by updating the state
    setRefreshTrigger(prev => prev + 1);
  };

  if (authLoading) {
    return (
      <div className="min-h-screen bg-black text-white p-4">
        <div className="max-w-2xl mx-auto pt-8">
          <div className="text-center text-gray-500">Loading...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black text-white p-4">
      <div className="max-w-2xl mx-auto pt-8">
        <header className="mb-8">
          <h1 className="text-2xl font-bold text-white">Analytical Community</h1>
          <p className="text-gray-500">Professional market analysis and insights</p>
        </header>

        {user ? (
          <>
            <CreatePostForm 
              userId={user.id} 
              username={user.username} 
              onPostCreated={handlePostCreated} 
            />
            <CommunityFeed isAuthenticated={!!user} key={`feed-${refreshTrigger}`} />
          </>
        ) : (
          <CommunityFeed isAuthenticated={false} />
        )}
      </div>
    </div>
  );
};

export default CommunityPage;
