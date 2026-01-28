export interface CommunityPost {
  id: string;
  authorId: string;
  authorUsername: string;
  content: string;
  createdAt: string; // ISO 8601
  tags?: string[];
  analysisType?: 'Technical' | 'Fundamental' | 'Sentiment' | 'Other';
}

export interface CreatePostInput {
  content: string;
  tags?: string[];
  analysisType?: 'Technical' | 'Fundamental' | 'Sentiment' | 'Other';
}

export interface PaginationParams {
  limit: number;
  offset: number;
}

export interface CommunityFeedResponse {
  posts: CommunityPost[];
  total: number;
  hasMore: boolean;
}