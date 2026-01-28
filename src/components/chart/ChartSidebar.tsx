import React from 'react';

interface ChartSidebarProps {
  isVisible: boolean;
}

const ChartSidebar: React.FC<ChartSidebarProps> = ({ isVisible }) => {
  if (!isVisible) return null;

  return (
    <aside 
      className="w-72 bg-gray-900 border-l border-gray-800 p-4 overflow-y-auto"
      aria-label="Chart sidebar"
      style={{ minWidth: '280px' }}
    >
      <h3 className="font-semibold text-white mb-4">Indicators & Tools</h3>
      
      <div className="space-y-4">
        <div>
          <h4 className="text-sm font-medium text-gray-300 mb-2">Technical Indicators</h4>
          <div className="space-y-2">
            <div className="text-xs text-gray-400 p-2 bg-gray-800 rounded">Moving Average</div>
            <div className="text-xs text-gray-400 p-2 bg-gray-800 rounded">RSI</div>
            <div className="text-xs text-gray-400 p-2 bg-gray-800 rounded">MACD</div>
            <div className="text-xs text-gray-400 p-2 bg-gray-800 rounded">Bollinger Bands</div>
            <div className="text-xs text-gray-400 p-2 bg-gray-800 rounded">Stochastic</div>
            <div className="text-xs text-gray-400 p-2 bg-gray-800 rounded">ATR</div>
          </div>
        </div>
        
        <div>
          <h4 className="text-sm font-medium text-gray-300 mb-2">Drawing Tools</h4>
          <div className="space-y-2">
            <div className="text-xs text-gray-400 p-2 bg-gray-800 rounded">Trend Lines</div>
            <div className="text-xs text-gray-400 p-2 bg-gray-800 rounded">Fibonacci</div>
            <div className="text-xs text-gray-400 p-2 bg-gray-800 rounded">Horizontal Lines</div>
            <div className="text-xs text-gray-400 p-2 bg-gray-800 rounded">Vertical Lines</div>
            <div className="text-xs text-gray-400 p-2 bg-gray-800 rounded">Rectangles</div>
            <div className="text-xs text-gray-400 p-2 bg-gray-800 rounded">Ellipses</div>
          </div>
        </div>
        
        <div>
          <h4 className="text-sm font-medium text-gray-300 mb-2">AI Annotations</h4>
          <div className="text-xs text-gray-400 p-2 bg-gray-800 rounded">Pattern Recognition</div>
          <div className="text-xs text-gray-400 p-2 bg-gray-800 rounded">Predictive Signals</div>
        </div>
        
        <div>
          <h4 className="text-sm font-medium text-gray-300 mb-2">Market Depth</h4>
          <div className="text-xs text-gray-400 p-2 bg-gray-800 rounded">Order Book Preview</div>
        </div>
      </div>
    </aside>
  );
};

export { ChartSidebar };