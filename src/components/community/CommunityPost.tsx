import React from 'react';
import { CommunityPost as CommunityPostType } from '@/types/community';
import { formatTimeAgo } from '@/lib/utils';

interface CommunityPostProps {
  post: CommunityPostType;
}

const CommunityPost: React.FC<CommunityPostProps> = ({ post }) => {
  const formattedTime = formatTimeAgo(new Date(post.createdAt));
  
  return (
    <article className="bg-gray-900 border border-gray-800 rounded-sm p-4 mb-4">
      <div className="flex justify-between items-center mb-2">
        <div className="text-gray-400 text-sm font-medium">
          @{post.authorUsername}
        </div>
        <time 
          dateTime={post.createdAt} 
          title={new Date(post.createdAt).toLocaleString()}
          className="text-xs text-gray-500 font-mono"
        >
          {formattedTime}
        </time>
      </div>
      
      <div className="text-white text-base leading-relaxed mb-3">
        {post.content}
      </div>
      
      {post.tags && post.tags.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {post.tags.map((tag, index) => (
            <span 
              key={index} 
              className="text-xs text-gray-400 bg-gray-800 px-2 py-1 rounded-sm"
            >
              #{tag}
            </span>
          ))}
        </div>
      )}
    </article>
  );
};

export default CommunityPost;