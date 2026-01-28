import React from 'react';

const EmptyCommunityState: React.FC = () => {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-sm p-8 text-center">
      <h3 className="text-xl font-semibold text-gray-300 mb-2">Analytical Community</h3>
      <p className="text-gray-500 mb-4 max-w-md mx-auto">
        Professional market analysis and insights from verified traders and analysts.
        Be the first to share your analysis.
      </p>
      <div className="text-gray-600 text-sm italic">
        Community posts will appear here once database is connected
      </div>
    </div>
  );
};

export default EmptyCommunityState;