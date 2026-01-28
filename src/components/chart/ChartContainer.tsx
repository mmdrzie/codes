'use client';

import React, { forwardRef, useImperativeHandle, useRef } from 'react';
import { ChartConfig, ChartEngineAdapter, MarketDataPoint } from '@/types/chart';

export interface ChartContainerProps {
  config: ChartConfig;
  onDataUpdate?: (data: MarketDataPoint[]) => void;
  onChartReady?: () => void;
  className?: string;
}

export interface ChartContainerRef {
  updateData: (data: MarketDataPoint[]) => void;
  addIndicator: (indicatorId: string) => void;
  removeIndicator: (indicatorId: string) => void;
  destroy: () => void;
}

/**
 * ChartContainer serves as a placeholder for the actual chart engine.
 * It provides an interface that can be replaced with a real chart implementation
 * like TradingView Lightweight Charts or other charting libraries.
 */
const ChartContainer = forwardRef<ChartContainerRef, ChartContainerProps>(
  ({ config, onDataUpdate, onChartReady, className = '' }, ref) => {
    const containerRef = useRef<HTMLDivElement>(null);

    // Placeholder implementation - would be replaced with actual chart engine
    useImperativeHandle(ref, () => ({
      updateData: (data: MarketDataPoint[]) => {
        // Implementation would update the chart with new data
        console.log('Updating chart with new data:', data);
        onDataUpdate?.(data);
      },
      addIndicator: (indicatorId: string) => {
        // Implementation would add an indicator to the chart
        console.log('Adding indicator:', indicatorId);
      },
      removeIndicator: (indicatorId: string) => {
        // Implementation would remove an indicator from the chart
        console.log('Removing indicator:', indicatorId);
      },
      destroy: () => {
        // Cleanup implementation
        console.log('Destroying chart container');
      }
    }));

    // Simulate chart ready event
    React.useEffect(() => {
      onChartReady?.();
    }, [onChartReady]);

    return (
      <main 
        ref={containerRef}
        className={`flex-1 overflow-hidden bg-black ${className}`}
        data-testid="chart-container"
      >
        <div className="h-full w-full flex items-center justify-center bg-black">
          <div className="text-center text-gray-500">
            <div className="text-xl mb-2">Chart Engine – To Be Integrated</div>
            <div className="text-sm">Data Source – Not Connected</div>
            <div className="mt-4 text-xs opacity-70">Preparing for live market data feed</div>
            <div className="mt-2 text-xs opacity-50">Symbol: {config.symbol} | Timeframe: {config.timeframe} | Type: {config.chartType}</div>
          </div>
        </div>
      </main>
    );
  }
);

ChartContainer.displayName = 'ChartContainer';

export { ChartContainer };