export interface NewsPost {
  id: string;
  title: string;
  summary: string;
  content: string;
  author: string;
  publishedAt: Date;
  category: 'security' | 'update' | 'system' | 'announcement';
  importance: 'normal' | 'important' | 'critical';
  visibility: 'public' | 'authenticated';
  createdAt: Date;
  updatedAt: Date;
  tags?: string[];
}

export interface NewsFilterOptions {
  category?: string;
  importance?: 'normal' | 'important' | 'critical';
  searchQuery?: string;
  visibility?: 'public' | 'authenticated';
  author?: string;
}

export interface NewsFetchOptions {
  limit: number;
  offset: number;
  filters?: NewsFilterOptions;
  sortBy?: 'publishedAt' | 'createdAt' | 'title';
  sortOrder?: 'asc' | 'desc';
}