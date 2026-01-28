'use client';

import React from 'react';
import { Button } from '@/ui/Button';
import { 
  Select, 
  SelectContent, 
  SelectItem, 
  SelectTrigger, 
  SelectValue 
} from '@/ui/Select';
import { 
  ChartTimeframe, 
  ChartType 
} from '@/types/chart';

interface ChartToolbarProps {
  selectedSymbol: string;
  selectedTimeframe: ChartTimeframe;
  selectedChartType: ChartType;
  onSymbolChange: (symbol: string) => void;
  onTimeframeChange: (timeframe: ChartTimeframe) => void;
  onChartTypeChange: (chartType: ChartType) => void;
  onSettingsClick?: () => void;
}

const ChartToolbar: React.FC<ChartToolbarProps> = ({
  selectedSymbol,
  selectedTimeframe,
  selectedChartType,
  onSymbolChange,
  onTimeframeChange,
  onChartTypeChange,
  onSettingsClick
}) => {
  return (
    <header 
      className="flex items-center justify-between px-4 py-3 border-b border-gray-800 bg-gray-900 h-14"
      aria-label="Chart toolbar"
    >
      <div className="flex items-center space-x-4">
        <div className="text-sm font-medium text-white">Symbol:</div>
        <Select value={selectedSymbol} onValueChange={onSymbolChange}>
          <SelectTrigger className="w-[180px] bg-gray-800 border-gray-700 text-white">
            <SelectValue placeholder="Select market" />
          </SelectTrigger>
          <SelectContent className="bg-gray-800 border-gray-700 text-white">
            <SelectItem value="BTCUSDT">BTC/USDT</SelectItem>
            <SelectItem value="ETHUSDT">ETH/USDT</SelectItem>
            <SelectItem value="AAPL">AAPL</SelectItem>
            <SelectItem value="SPY">SPY</SelectItem>
            <SelectItem value="GOOGL">GOOGL</SelectItem>
            <SelectItem value="MSFT">MSFT</SelectItem>
            <SelectItem value="TSLA">TSLA</SelectItem>
            <SelectItem value="AMZN">AMZN</SelectItem>
          </SelectContent>
        </Select>
        
        <div className="text-sm font-medium text-white">Timeframe:</div>
        <Select value={selectedTimeframe} onValueChange={onTimeframeChange}>
          <SelectTrigger className="w-[100px] bg-gray-800 border-gray-700 text-white">
            <SelectValue />
          </SelectTrigger>
          <SelectContent className="bg-gray-800 border-gray-700 text-white">
            <SelectItem value="1m">1m</SelectItem>
            <SelectItem value="5m">5m</SelectItem>
            <SelectItem value="15m">15m</SelectItem>
            <SelectItem value="30m">30m</SelectItem>
            <SelectItem value="1h">1h</SelectItem>
            <SelectItem value="4h">4h</SelectItem>
            <SelectItem value="1D">1D</SelectItem>
            <SelectItem value="1W">1W</SelectItem>
            <SelectItem value="1M">1M</SelectItem>
          </SelectContent>
        </Select>
        
        <div className="text-sm font-medium text-white">Chart Type:</div>
        <Select value={selectedChartType} onValueChange={onChartTypeChange}>
          <SelectTrigger className="w-[120px] bg-gray-800 border-gray-700 text-white">
            <SelectValue />
          </SelectTrigger>
          <SelectContent className="bg-gray-800 border-gray-700 text-white">
            <SelectItem value="candle">Candles</SelectItem>
            <SelectItem value="line">Line</SelectItem>
            <SelectItem value="area">Area</SelectItem>
            <SelectItem value="heikinashi">Heikin Ashi</SelectItem>
          </SelectContent>
        </Select>
      </div>
      
      <Button 
        variant="ghost" 
        size="icon" 
        onClick={onSettingsClick}
        className="text-gray-300 hover:text-white hover:bg-gray-800"
        aria-label="Chart settings"
      >
        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="3"></circle>
          <path d="M12 1v6m0 6v6"></path>
        </svg>
      </Button>
    </header>
  );
};

export { ChartToolbar };