'use client';

import { useState, useEffect, useCallback } from 'react';
import { ChartState, ChartTimeframe, ChartType, IndicatorConfig, DrawingToolConfig } from '@/types/chart';

const DEFAULT_SYMBOL = 'SELECT.MARKET';
const DEFAULT_TIMEFRAME: ChartTimeframe = '1h';
const DEFAULT_CHART_TYPE: ChartType = 'candle';

export const useChartState = () => {
  const [state, setState] = useState<ChartState>({
    symbol: DEFAULT_SYMBOL,
    timeframe: DEFAULT_TIMEFRAME,
    chartType: DEFAULT_CHART_TYPE,
    indicators: [],
    drawingTools: [],
    isSidebarVisible: true,
    isBottomPanelVisible: true,
    isLoading: false,
  });

  const updateSymbol = useCallback((symbol: string) => {
    setState(prev => ({ ...prev, symbol }));
  }, []);

  const updateTimeframe = useCallback((timeframe: ChartTimeframe) => {
    setState(prev => ({ ...prev, timeframe }));
  }, []);

  const updateChartType = useCallback((chartType: ChartType) => {
    setState(prev => ({ ...prev, chartType }));
  }, []);

  const addIndicator = useCallback((indicator: IndicatorConfig) => {
    setState(prev => ({
      ...prev,
      indicators: [...prev.indicators, indicator]
    }));
  }, []);

  const removeIndicator = useCallback((id: string) => {
    setState(prev => ({
      ...prev,
      indicators: prev.indicators.filter(indicator => indicator.id !== id)
    }));
  }, []);

  const toggleSidebar = useCallback(() => {
    setState(prev => ({ ...prev, isSidebarVisible: !prev.isSidebarVisible }));
  }, []);

  const toggleBottomPanel = useCallback(() => {
    setState(prev => ({ ...prev, isBottomPanelVisible: !prev.isBottomPanelVisible }));
  }, []);

  const setLoading = useCallback((loading: boolean) => {
    setState(prev => ({ ...prev, isLoading: loading }));
  }, []);

  const setError = useCallback((error?: string) => {
    setState(prev => ({ ...prev, error }));
  }, []);

  return {
    state,
    updateSymbol,
    updateTimeframe,
    updateChartType,
    addIndicator,
    removeIndicator,
    toggleSidebar,
    toggleBottomPanel,
    setLoading,
    setError,
  };
};