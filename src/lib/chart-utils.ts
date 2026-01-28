/**
 * Utility functions for chart operations
 */

import { ChartTimeframe, MarketDataPoint } from '@/types/chart';

/**
 * Converts a timeframe string to milliseconds
 */
export const timeframeToMs = (timeframe: ChartTimeframe): number => {
  switch (timeframe) {
    case '1m': return 60 * 1000;
    case '5m': return 5 * 60 * 1000;
    case '15m': return 15 * 60 * 1000;
    case '30m': return 30 * 60 * 1000;
    case '1h': return 60 * 60 * 1000;
    case '4h': return 4 * 60 * 60 * 1000;
    case '1D': return 24 * 60 * 60 * 1000;
    case '1W': return 7 * 24 * 60 * 60 * 1000;
    case '1M': return 30 * 24 * 60 * 60 * 1000; // Approximate
    default: return 60 * 1000; // Default to 1 minute
  }
};

/**
 * Formats a date according to the selected timeframe
 */
export const formatDateByTimeframe = (date: Date, timeframe: ChartTimeframe): string => {
  switch (timeframe) {
    case '1m':
    case '5m':
    case '15m':
    case '30m':
    case '1h':
    case '4h':
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    case '1D':
      return date.toLocaleDateString();
    case '1W':
      return `Week of ${date.toLocaleDateString()}`;
    case '1M':
      return date.toLocaleDateString([], { month: 'short', year: 'numeric' });
    default:
      return date.toLocaleString();
  }
};

/**
 * Calculates the time range for a given timeframe
 */
export const getTimeRangeForTimeframe = (timeframe: ChartTimeframe): { start: Date; end: Date } => {
  const end = new Date();
  const start = new Date(end);

  switch (timeframe) {
    case '1m':
      start.setMinutes(start.getMinutes() - 60); // Last hour
      break;
    case '5m':
      start.setHours(start.getHours() - 4); // Last 4 hours
      break;
    case '15m':
      start.setHours(start.getHours() - 8); // Last 8 hours
      break;
    case '30m':
      start.setDate(start.getDate() - 1); // Last day
      break;
    case '1h':
      start.setDate(start.getDate() - 3); // Last 3 days
      break;
    case '4h':
      start.setDate(start.getDate() - 7); // Last week
      break;
    case '1D':
      start.setMonth(start.getMonth() - 1); // Last month
      break;
    case '1W':
      start.setFullYear(start.getFullYear() - 1); // Last year
      break;
    case '1M':
      start.setFullYear(start.getFullYear() - 2); // Last 2 years
      break;
    default:
      start.setHours(start.getHours() - 1); // Default to last hour
  }

  return { start, end };
};

/**
 * Validates if the market data is properly formatted
 */
export const validateMarketData = (data: MarketDataPoint[]): boolean => {
  if (!Array.isArray(data) || data.length === 0) {
    return false;
  }

  for (const point of data) {
    if (
      typeof point.timestamp !== 'number' ||
      typeof point.open !== 'number' ||
      typeof point.high !== 'number' ||
      typeof point.low !== 'number' ||
      typeof point.close !== 'number'
    ) {
      return false;
    }

    if (point.high < Math.max(point.open, point.close) || point.low > Math.min(point.open, point.close)) {
      return false; // Invalid OHLC values
    }
  }

  return true;
};

/**
 * Calculates basic statistics from market data
 */
export const calculateMarketStats = (data: MarketDataPoint[]) => {
  if (!data || data.length === 0) {
    return {
      minPrice: 0,
      maxPrice: 0,
      avgPrice: 0,
      volatility: 0,
      totalVolume: 0,
    };
  }

  const prices = data.map(d => (d.high + d.low + d.close) / 3); // Typical price
  const volumes = data.map(d => d.volume || 0);

  const minPrice = Math.min(...prices);
  const maxPrice = Math.max(...prices);
  const avgPrice = prices.reduce((sum, price) => sum + price, 0) / prices.length;
  const totalVolume = volumes.reduce((sum, vol) => sum + vol, 0);

  // Simple volatility calculation (standard deviation)
  const squaredDiffs = prices.map(price => Math.pow(price - avgPrice, 2));
  const variance = squaredDiffs.reduce((sum, diff) => sum + diff, 0) / squaredDiffs.length;
  const volatility = Math.sqrt(variance);

  return {
    minPrice,
    maxPrice,
    avgPrice,
    volatility,
    totalVolume,
  };
};