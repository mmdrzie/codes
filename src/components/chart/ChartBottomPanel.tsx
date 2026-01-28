import React from 'react';

interface ChartBottomPanelProps {
  isVisible: boolean;
}

const ChartBottomPanel: React.FC<ChartBottomPanelProps> = ({ isVisible }) => {
  if (!isVisible) return null;

  return (
    <footer 
      className="h-48 bg-gray-900 border-t border-gray-800 p-4"
      aria-label="Chart bottom panel"
    >
      <h3 className="font-semibold text-white mb-2">Volume & Details</h3>
      <div className="h-full flex items-center justify-center text-gray-500">
        <div className="text-center">
          <div>Volume Chart – To Be Integrated</div>
          <div className="mt-2 text-sm">Order Book & Execution Logs</div>
          <div className="mt-1 text-xs opacity-70">AI Explanation Pane</div>
        </div>
      </div>
    </footer>
  );
};

export { ChartBottomPanel };