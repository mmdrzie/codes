import { NewsPost, NewsFetchOptions, NewsFilterOptions } from '@/types/news';

/**
 * Placeholder function for fetching news posts from a data source
 * This would connect to a real database or API in a production environment
 */
export const fetchNewsPosts = async (options: NewsFetchOptions): Promise<NewsPost[]> => {
  // Simulate API delay
  await new Promise(resolve => setTimeout(resolve, 300));
  
  // This is a placeholder implementation - in a real application, 
  // this would connect to a database or external API
  const allNewsPosts: NewsPost[] = [
    {
      id: '1',
      title: 'Critical Security Update Released',
      summary: 'A critical security vulnerability has been identified and patched.',
      content: '<p>We have released a critical security update to address a vulnerability discovered in our authentication system. All users are required to update immediately.</p><p>The vulnerability could potentially allow unauthorized access to user accounts under specific conditions. Our security team has implemented additional safeguards to prevent similar issues in the future.</p>',
      author: 'Security Team',
      publishedAt: new Date(Date.now() - 24 * 60 * 60 * 1000), // 1 day ago
      category: 'security',
      importance: 'critical',
      visibility: 'public',
      createdAt: new Date(Date.now() - 25 * 60 * 60 * 1000),
      updatedAt: new Date(Date.now() - 24 * 60 * 60 * 1000),
      tags: ['security', 'patch', 'urgent']
    },
    {
      id: '2',
      title: 'System Maintenance Scheduled',
      summary: 'Planned maintenance will occur this weekend affecting service availability.',
      content: '<p>Scheduled system maintenance will take place on Saturday from 2:00 AM to 6:00 AM UTC. During this window, services may experience brief interruptions.</p><p>Our infrastructure team will be performing routine updates to improve system performance and reliability. We apologize for any inconvenience this may cause.</p>',
      author: 'System Admin',
      publishedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000), // 2 days ago
      category: 'system',
      importance: 'important',
      visibility: 'public',
      createdAt: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000),
      updatedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
      tags: ['maintenance', 'downtime', 'planned']
    },
    {
      id: '3',
      title: 'New Feature: Enhanced Analytics Dashboard',
      summary: 'We\'ve launched a new analytics dashboard with improved visualization tools.',
      content: '<p>The new analytics dashboard provides enhanced visualization capabilities for monitoring your projects. Key features include real-time data feeds, customizable widgets, and improved export functionality.</p><p>Users can now create custom reports and schedule automated delivery to stakeholders. The dashboard also includes new filtering options and the ability to drill down into specific data points.</p>',
      author: 'Product Team',
      publishedAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000), // 5 days ago
      category: 'update',
      importance: 'normal',
      visibility: 'public',
      createdAt: new Date(Date.now() - 6 * 24 * 60 * 60 * 1000),
      updatedAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000),
      tags: ['feature', 'analytics', 'dashboard']
    },
    {
      id: '4',
      title: 'API Rate Limits Adjusted',
      summary: 'Updated rate limits for better performance and stability.',
      content: '<p>We have adjusted API rate limits to ensure optimal performance for all users. The new limits are designed to accommodate typical usage patterns while maintaining system stability.</p><p>For enterprise customers requiring higher limits, please contact our support team to discuss custom rate limit configurations.</p>',
      author: 'Engineering Team',
      publishedAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), // 7 days ago
      category: 'update',
      importance: 'normal',
      visibility: 'public',
      createdAt: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000),
      updatedAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
      tags: ['api', 'rate-limits', 'performance']
    },
    {
      id: '5',
      title: 'Compliance Framework Updated',
      summary: 'New compliance requirements implemented to meet regulatory standards.',
      content: '<p>Our compliance framework has been updated to meet the latest regulatory requirements. These changes ensure continued adherence to industry standards and legal obligations.</p><p>All internal processes have been reviewed and updated accordingly. Documentation is available in the compliance portal for reference.</p>',
      author: 'Compliance Team',
      publishedAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000), // 10 days ago
      category: 'announcement',
      importance: 'important',
      visibility: 'authenticated',
      createdAt: new Date(Date.now() - 11 * 24 * 60 * 60 * 1000),
      updatedAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000),
      tags: ['compliance', 'regulation', 'policy']
    }
  ];

  // Apply filters
  let filteredPosts = allNewsPosts;
  
  if (options.filters?.category) {
    filteredPosts = filteredPosts.filter(post => post.category === options.filters?.category);
  }
  
  if (options.filters?.importance) {
    filteredPosts = filteredPosts.filter(post => post.importance === options.filters?.importance);
  }
  
  if (options.filters?.searchQuery) {
    const query = options.filters.searchQuery.toLowerCase();
    filteredPosts = filteredPosts.filter(post => 
      post.title.toLowerCase().includes(query) || 
      post.summary.toLowerCase().includes(query) ||
      post.content.toLowerCase().includes(query) ||
      (post.tags && post.tags.some(tag => tag.toLowerCase().includes(query)))
    );
  }
  
  if (options.filters?.visibility) {
    filteredPosts = filteredPosts.filter(post => post.visibility === options.filters?.visibility);
  }

  // Apply sorting
  const sortBy = options.sortBy || 'publishedAt';
  const sortOrder = options.sortOrder || 'desc';
  
  filteredPosts.sort((a, b) => {
    let comparison = 0;
    
    if (sortBy === 'publishedAt') {
      comparison = new Date(a.publishedAt).getTime() - new Date(b.publishedAt).getTime();
    } else if (sortBy === 'createdAt') {
      comparison = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
    } else if (sortBy === 'title') {
      comparison = a.title.localeCompare(b.title);
    }
    
    return sortOrder === 'asc' ? comparison : -comparison;
  });

  // Apply pagination
  const startIndex = options.offset;
  const endIndex = startIndex + options.limit;
  const paginatedPosts = filteredPosts.slice(startIndex, endIndex);

  return paginatedPosts;
};

/**
 * Function to fetch a single news post by ID
 */
export const fetchNewsPostById = async (id: string): Promise<NewsPost | null> => {
  // Simulate API delay
  await new Promise(resolve => setTimeout(resolve, 200));
  
  const allNewsPosts = await fetchNewsPosts({ limit: 100, offset: 0 });
  return allNewsPosts.find(post => post.id === id) || null;
};

/**
 * Function to count total news posts matching filters
 */
export const countNewsPosts = async (filters?: NewsFilterOptions): Promise<number> => {
  const allNewsPosts = await fetchNewsPosts({ limit: 100, offset: 0, filters });
  return allNewsPosts.length;
};