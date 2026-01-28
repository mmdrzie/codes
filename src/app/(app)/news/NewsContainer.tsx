import { NewsList } from './NewsList';
import { fetchNewsPosts } from '@/lib/newsRepository';
import { Suspense } from 'react';

// Server component to fetch and render news
const NewsServerComponent = async () => {
  try {
    // Fetch news posts from the data layer
    const newsPosts = await fetchNewsPosts({
      limit: 20,
      offset: 0,
      filters: {},
      sortBy: 'publishedAt',
      sortOrder: 'desc'
    });

    return <NewsList posts={newsPosts} />;
  } catch (error) {
    console.error('Error fetching news posts:', error);
    return (
      <div className="text-center py-12">
        <h2 className="text-xl font-semibold text-red-500">Error Loading News</h2>
        <p className="text-gray-400 mt-2">Unable to load news posts at this time. Please try again later.</p>
      </div>
    );
  }
};

export const NewsContainer = () => {
  return (
    <div className="w-full">
      <Suspense fallback={
        <div className="text-center py-12">
          <p className="text-gray-500">Loading news posts...</p>
        </div>
      }>
        <NewsServerComponent />
      </Suspense>
    </div>
  );
};