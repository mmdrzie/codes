'use client';

import { useState } from 'react';
import { Button } from '@/ui/Button';
import { useChartState } from '@/hooks/useChartState';
import { ChartContainer } from '@/components/chart/ChartContainer';
import { ChartToolbar } from '@/components/chart/ChartToolbar';
import { ChartSidebar } from '@/components/chart/ChartSidebar';
import { ChartBottomPanel } from '@/components/chart/ChartBottomPanel';
import { ChartConfig } from '@/types/chart';

const ChartPage = () => {
  const { 
    state, 
    updateSymbol, 
    updateTimeframe, 
    updateChartType, 
    toggleSidebar, 
    toggleBottomPanel 
  } = useChartState();

  const chartConfig: ChartConfig = {
    symbol: state.symbol,
    timeframe: state.timeframe,
    chartType: state.chartType,
    indicators: []
  };

  return (
    <div className="flex flex-col h-screen bg-black text-white">
      <ChartToolbar 
        selectedSymbol={state.symbol}
        selectedTimeframe={state.timeframe}
        selectedChartType={state.chartType}
        onSymbolChange={updateSymbol}
        onTimeframeChange={updateTimeframe}
        onChartTypeChange={updateChartType}
      />
      
      <div className="flex flex-1 overflow-hidden">
        <ChartContainer config={chartConfig} />
        <ChartSidebar isVisible={state.isSidebarVisible} />
      </div>
      
      <ChartBottomPanel isVisible={state.isBottomPanelVisible} />
      
      {/* Controls for panels */}
      <div className="absolute top-20 right-4 flex flex-col gap-2 z-10">
        <Button 
          variant="outline" 
          size="sm" 
          onClick={toggleSidebar}
          className="bg-gray-800 border-gray-700 text-white hover:bg-gray-700"
        >
          {state.isSidebarVisible ? 'Hide' : 'Show'} Sidebar
        </Button>
        <Button 
          variant="outline" 
          size="sm" 
          onClick={toggleBottomPanel}
          className="bg-gray-800 border-gray-700 text-white hover:bg-gray-700"
        >
          {state.isBottomPanelVisible ? 'Hide' : 'Show'} Bottom Panel
        </Button>
      </div>
    </div>
  );
};

export default ChartPage;