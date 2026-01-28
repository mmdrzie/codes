// Define types for chart configuration and data
export type ChartTimeframe = '1m' | '5m' | '15m' | '30m' | '1h' | '4h' | '1D' | '1W' | '1M';
export type ChartType = 'candle' | 'line' | 'area' | 'heikinashi';

export interface ChartConfig {
  symbol: string;
  timeframe: ChartTimeframe;
  chartType: ChartType;
  indicators: string[];
}

export interface MarketDataPoint {
  timestamp: number;
  open: number;
  high: number;
  low: number;
  close: number;
  volume?: number;
}

export interface IndicatorConfig {
  id: string;
  name: string;
  parameters: Record<string, any>;
  color?: string;
}

export interface DrawingToolConfig {
  id: string;
  type: 'trendline' | 'fibonacci' | 'horizontal-line' | 'vertical-line' | 'rectangle' | 'ellipse';
  coordinates: { x: number; y: number }[];
}

export interface ChartState {
  symbol: string;
  timeframe: ChartTimeframe;
  chartType: ChartType;
  indicators: IndicatorConfig[];
  drawingTools: DrawingToolConfig[];
  isSidebarVisible: boolean;
  isBottomPanelVisible: boolean;
  isLoading: boolean;
  error?: string;
}

export interface ChartEngineAdapter {
  mount: (containerId: string, config: ChartConfig) => void;
  updateData: (data: MarketDataPoint[]) => void;
  addIndicator: (indicator: IndicatorConfig) => void;
  removeIndicator: (indicatorId: string) => void;
  destroy: () => void;
}