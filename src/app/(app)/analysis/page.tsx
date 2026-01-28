'use client';

import React, { useState, useEffect } from 'react';
import { 
  ModelOutput, 
  AnalysisEntry, 
  DecisionLogEntry, 
  MarketStateSnapshot,
  AnalysisType,
  ConfidenceLevel,
  DecisionStatus
} from '@/types/analysis';
import { 
  fetchModelActivityFeed, 
  fetchMarketState, 
  fetchDecisionLogs, 
  fetchCrossModelComparison,
  fetchHistoricalAnalysis
} from '@/actions/analysis';
import { formatDate } from '@/utils/date';
import { generateModelOutputHash as generateHash } from '@/utils/hash';
import { Button } from '@/ui/button';
import { Input } from '@/ui/input';
import { Select } from '@/ui/select';
import { Badge } from '@/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/ui/tabs';
import { Skeleton } from '@/ui/skeleton';

// Type definitions for the analysis page
type FilterOptions = {
  model?: string;
  dateRange?: { start: Date; end: Date };
  analysisType?: AnalysisType;
};

type TimeRange = {
  start: Date;
  end: Date;
};

const AnalysisPage = () => {
  // State management
  const [activityFeed, setActivityFeed] = useState<AnalysisEntry[]>([]);
  const [marketState, setMarketState] = useState<MarketStateSnapshot | null>(null);
  const [decisionLogs, setDecisionLogs] = useState<DecisionLogEntry[]>([]);
  const [crossModelComparison, setCrossModelComparison] = useState<any[]>([]);
  const [historicalAnalysis, setHistoricalAnalysis] = useState<AnalysisEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // Filters and search
  const [filters, setFilters] = useState<FilterOptions>({});
  const [searchQuery, setSearchQuery] = useState('');
  const [timeRange, setTimeRange] = useState<TimeRange>({
    start: new Date(Date.now() - 24 * 60 * 60 * 1000),
    end: new Date()
  });

  // Load initial data
  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      
      // Fetch all required data concurrently
      const [feed, state, decisions, comparison, history] = await Promise.all([
        fetchModelActivityFeed(filters, searchQuery, timeRange),
        fetchMarketState(),
        fetchDecisionLogs(filters),
        fetchCrossModelComparison(timeRange),
        fetchHistoricalAnalysis(timeRange)
      ]);
      
      setActivityFeed(feed);
      setMarketState(state);
      setDecisionLogs(decisions);
      setCrossModelComparison(comparison);
      setHistoricalAnalysis(history);
    } catch (err) {
      setError('Failed to load analysis data');
      console.error('Error loading analysis data:', err);
    } finally {
      setLoading(false);
    }
  };

  // Apply filters
  const applyFilters = () => {
    loadData();
  };

  // Reset filters
  const resetFilters = () => {
    setFilters({});
    setSearchQuery('');
    setTimeRange({
      start: new Date(Date.now() - 24 * 60 * 60 * 1000),
      end: new Date()
    });
    loadData();
  };

  return (
    <div className="min-h-screen bg-black text-white p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <header className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">AI Model Analysis Feed</h1>
          <p className="text-gray-400">Live intelligence from institutional AI models</p>
        </header>

        {/* Filters Section */}
        <div className="mb-8 p-4 bg-gray-900 rounded-lg border border-gray-800">
          <div className="flex flex-col md:flex-row gap-4 items-start md:items-center">
            <Input
              placeholder="Search analysis content..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-gray-800 border-gray-700 text-white"
            />
            
            <select 
              value={filters.model || ''} 
              onChange={(e) => setFilters({...filters, model: e.target.value})}
              className="w-[200px] bg-gray-800 border border-gray-700 text-white px-3 py-2 rounded-md"
            >
              <option value="">Filter by model</option>
              <option value="quantum-v1">QuantumAI v1</option>
              <option value="macro-insight">Macro Insight Model</option>
              <option value="risk-assessment">Risk Assessment Model</option>
              <option value="pattern-recognition">Pattern Recognition Model</option>
            </select>
            
            <Select 
              value={filters.analysisType || ''} 
              onValueChange={(value) => setFilters({...filters, analysisType: value as AnalysisType})}
            >
              <SelectTrigger className="w-[200px] bg-gray-800 border-gray-700 text-white">
                <SelectValue placeholder="Filter by type" />
              </SelectTrigger>
              <SelectContent className="bg-gray-800 border-gray-700 text-white">
                <SelectItem value="market_state">Market State</SelectItem>
                <SelectItem value="risk_evaluation">Risk Evaluation</SelectItem>
                <SelectItem value="macro_context">Macro Context</SelectItem>
                <SelectItem value="system_alert">System Alert</SelectItem>
              </SelectContent>
            </Select>
            
            <Button onClick={applyFilters} variant="default" className="bg-blue-600 hover:bg-blue-700">
              Apply Filters
            </Button>
            
            <Button onClick={resetFilters} variant="outline" className="border-gray-600 text-white">
              Reset
            </Button>
          </div>
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column - Activity Feed and Market State */}
          <div className="lg:col-span-2 space-y-6">
            {/* Model Activity Feed */}
            <Card className="bg-gray-900 border-gray-800">
              <CardHeader>
                <CardTitle className="text-xl text-white flex items-center gap-2">
                  <span className="w-3 h-3 bg-green-500 rounded-full"></span>
                  Model Activity Feed
                </CardTitle>
              </CardHeader>
              <CardContent>
                {loading ? (
                  <div className="space-y-4">
                    {[...Array(5)].map((_, i) => (
                      <Skeleton key={i} className="h-24 w-full bg-gray-800" />
                    ))}
                  </div>
                ) : error ? (
                  <div className="text-red-500">{error}</div>
                ) : activityFeed.length === 0 ? (
                  <div className="text-gray-500 italic">No recent model activity</div>
                ) : (
                  <div className="space-y-4 max-h-[600px] overflow-y-auto pr-2">
                    {activityFeed.map((entry) => (
                      <div 
                        key={entry.id} 
                        className="p-4 bg-gray-800 rounded-lg border border-gray-700 transition-all duration-200 hover:border-gray-600"
                      >
                        <div className="flex justify-between items-start mb-2">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-sm bg-gray-700 px-2 py-1 rounded">
                              {entry.modelName}
                            </span>
                            <Badge 
                              variant={getConfidenceBadgeVariant(entry.confidence)}
                              className={getConfidenceBadgeClass(entry.confidence)}
                            >
                              {entry.confidence}
                            </Badge>
                          </div>
                          <span className="text-xs text-gray-400 font-mono">
                            {formatDate(new Date(entry.timestamp))}
                          </span>
                        </div>
                        
                        <div className="text-sm text-gray-300 mb-2">
                          <Badge variant="secondary" className="mr-2 bg-gray-700 text-gray-300">
                            {entry.analysisType}
                          </Badge>
                          {entry.immutable && (
                            <span className="inline-flex items-center text-xs text-gray-400">
                              <LockIcon className="w-3 h-3 mr-1" /> Immutable
                            </span>
                          )}
                        </div>
                        
                        <p className="text-white mb-2">{entry.content}</p>
                        
                        <div className="text-xs text-gray-500 mt-2">
                          <div>ID: {entry.id}</div>
                          <div>Hash: {entry.hash.substring(0, 12)}...</div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Market State Analysis Panel */}
            <Card className="bg-gray-900 border-gray-800">
              <CardHeader>
                <CardTitle className="text-xl text-white">Market State Analysis</CardTitle>
              </CardHeader>
              <CardContent>
                {loading ? (
                  <Skeleton className="h-32 w-full bg-gray-800" />
                ) : marketState ? (
                  <div className="space-y-3">
                    <div>
                      <h4 className="text-sm font-medium text-gray-400 mb-1">Market Regime</h4>
                      <p className="text-white">{marketState.regime}</p>
                    </div>
                    
                    <div>
                      <h4 className="text-sm font-medium text-gray-400 mb-1">Volatility Interpretation</h4>
                      <p className="text-white">{marketState.volatilityInterpretation}</p>
                    </div>
                    
                    <div>
                      <h4 className="text-sm font-medium text-gray-400 mb-1">Liquidity Observations</h4>
                      <p className="text-white">{marketState.liquidityObservations}</p>
                    </div>
                    
                    <div>
                      <h4 className="text-sm font-medium text-gray-400 mb-1">Consensus Summary</h4>
                      <p className="text-white">{marketState.consensusSummary}</p>
                    </div>
                    
                    <div className="flex flex-wrap gap-2 mt-4">
                      {marketState.contributingModels.map((model, index) => (
                        <span key={index} className="text-xs bg-gray-800 px-2 py-1 rounded">
                          {model}
                        </span>
                      ))}
                    </div>
                    
                    <div className="text-xs text-gray-500 mt-4">
                      Updated: {formatDate(new Date(marketState.timestamp))} | 
                      Data freshness: {formatDate(new Date(marketState.dataFreshness))}
                    </div>
                    
                    <div className="text-xs text-yellow-500 italic mt-2">
                      This is an interpretation, not a fact. Models may disagree.
                    </div>
                  </div>
                ) : (
                  <div className="text-gray-500 italic">No market state data available</div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Right Column - Decision Log and Comparisons */}
          <div className="space-y-6">
            {/* Model Decision Log */}
            <Card className="bg-gray-900 border-gray-800">
              <CardHeader>
                <CardTitle className="text-xl text-white">Model Decision Log</CardTitle>
              </CardHeader>
              <CardContent>
                {loading ? (
                  <div className="space-y-3">
                    {[...Array(3)].map((_, i) => (
                      <Skeleton key={i} className="h-16 w-full bg-gray-800" />
                    ))}
                  </div>
                ) : decisionLogs.length === 0 ? (
                  <div className="text-gray-500 italic">No decision logs available</div>
                ) : (
                  <div className="space-y-4 max-h-[400px] overflow-y-auto pr-2">
                    {decisionLogs.map((log) => (
                      <div key={log.id} className="p-3 bg-gray-800 rounded border border-gray-700">
                        <div className="flex justify-between items-start mb-1">
                          <Badge 
                            variant={getStatusBadgeVariant(log.status)}
                            className="capitalize"
                          >
                            {log.status}
                          </Badge>
                          <span className="text-xs text-gray-400 font-mono">
                            {formatDate(new Date(log.timestamp))}
                          </span>
                        </div>
                        
                        <div className="text-sm font-medium text-white mb-1">
                          {log.decisionType}
                        </div>
                        
                        <div className="text-xs text-gray-300 mb-1">
                          {log.triggerReason}
                        </div>
                        
                        <div className="flex flex-wrap gap-1 mt-2">
                          {log.modelsInvolved.map((model, idx) => (
                            <span key={idx} className="text-xs bg-gray-700 px-2 py-1 rounded">
                              {model}
                            </span>
                          ))}
                        </div>
                        
                        {log.requiresHumanReview && (
                          <div className="mt-2 text-xs text-yellow-500 flex items-center">
                            <AlertIcon className="w-3 h-3 mr-1" /> Requires human review
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Cross-Model Reasoning Comparison */}
            <Card className="bg-gray-900 border-gray-800">
              <CardHeader>
                <CardTitle className="text-xl text-white">Cross-Model Reasoning</CardTitle>
              </CardHeader>
              <CardContent>
                {loading ? (
                  <Skeleton className="h-40 w-full bg-gray-800" />
                ) : crossModelComparison.length > 0 ? (
                  <div className="space-y-4">
                    <div className="text-sm text-gray-300">
                      <p className="mb-2">Models are currently in {crossModelComparison[0].consensusLevel} consensus.</p>
                      <p>Divergence detected in {crossModelComparison[0].divergenceAreas.join(', ')}</p>
                    </div>
                    
                    <div className="space-y-2">
                      <h4 className="text-sm font-medium text-gray-400">Agreement Areas:</h4>
                      <ul className="text-sm text-white list-disc pl-5">
                        {crossModelComparison[0].agreementAreas?.map((area: string, idx: number) => (
                          <li key={idx}>{area}</li>
                        )) || <li>No agreement areas found</li>}
                      </ul>
                    </div>
                    
                    <div className="space-y-2">
                      <h4 className="text-sm font-medium text-gray-400">Divergence Areas:</h4>
                      <ul className="text-sm text-white list-disc pl-5">
                        {crossModelComparison[0].divergenceAreas?.map((area: string, idx: number) => (
                          <li key={idx}>{area}</li>
                        )) || <li>No divergence areas found</li>}
                      </ul>
                    </div>
                  </div>
                ) : (
                  <div className="text-gray-500 italic">No cross-model comparison data available</div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Historical Analysis Section */}
        <Card className="mt-6 bg-gray-900 border-gray-800">
          <CardHeader>
            <CardTitle className="text-xl text-white">Historical Analysis Review</CardTitle>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="timeline" className="w-full">
              <TabsList className="grid w-full grid-cols-2 bg-gray-800">
                <TabsTrigger value="timeline" className="data-[state=active]:bg-gray-700">Timeline</TabsTrigger>
                <TabsTrigger value="comparison" className="data-[state=active]:bg-gray-700">Comparison</TabsTrigger>
              </TabsList>
              
              <TabsContent value="timeline" className="mt-4">
                {loading ? (
                  <div className="space-y-3">
                    {[...Array(3)].map((_, i) => (
                      <Skeleton key={i} className="h-20 w-full bg-gray-800" />
                    ))}
                  </div>
                ) : historicalAnalysis.length === 0 ? (
                  <div className="text-gray-500 italic">No historical analysis available</div>
                ) : (
                  <div className="space-y-4">
                    {historicalAnalysis.map((entry, index) => (
                      <div key={index} className="p-4 bg-gray-800 rounded border border-gray-700">
                        <div className="flex justify-between items-start mb-2">
                          <span className="font-mono text-sm bg-gray-700 px-2 py-1 rounded">
                            {entry.modelName}
                          </span>
                          <span className="text-xs text-gray-400 font-mono">
                            {formatDate(new Date(entry.timestamp))}
                          </span>
                        </div>
                        <p className="text-white">{entry.content}</p>
                      </div>
                    ))}
                  </div>
                )}
              </TabsContent>
              
              <TabsContent value="comparison" className="mt-4">
                <div className="text-gray-500 italic">Comparison view allows selecting two time periods to compare model interpretations.</div>
                <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-400 mb-2">First Period</label>
                    <Input 
                      type="date" 
                      className="bg-gray-800 border-gray-700 text-white" 
                      value={timeRange.start.toISOString().split('T')[0]}
                      onChange={(e) => setTimeRange({...timeRange, start: new Date(e.target.value)})}
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-400 mb-2">Second Period</label>
                    <Input 
                      type="date" 
                      className="bg-gray-800 border-gray-700 text-white" 
                      value={timeRange.end.toISOString().split('T')[0]}
                      onChange={(e) => setTimeRange({...timeRange, end: new Date(e.target.value)})}
                    />
                  </div>
                </div>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

// Helper functions
const getConfidenceBadgeVariant = (confidence: ConfidenceLevel) => {
  switch(confidence) {
    case 'high': return 'default';
    case 'medium': return 'secondary';
    case 'low': return 'outline';
    case 'uncertain': return 'destructive';
    default: return 'outline';
  }
};

const getConfidenceBadgeClass = (confidence: ConfidenceLevel) => {
  switch(confidence) {
    case 'high': return 'bg-green-900 text-green-200 border-green-800';
    case 'medium': return 'bg-yellow-900 text-yellow-200 border-yellow-800';
    case 'low': return 'bg-orange-900 text-orange-200 border-orange-800';
    case 'uncertain': return 'bg-red-900 text-red-200 border-red-800';
    default: return '';
  }
};

const getStatusBadgeVariant = (status: DecisionStatus) => {
  switch(status) {
    case 'executed': return 'default';
    case 'pending': return 'secondary';
    case 'withheld': return 'outline';
    case 'overridden': return 'destructive';
    default: return 'outline';
  }
};

// Icon components
const LockIcon = ({ className }: { className?: string }) => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <rect width="18" height="11" x="3" y="11" rx="2" ry="2"></rect>
    <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
  </svg>
);

const AlertIcon = ({ className }: { className?: string }) => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <circle cx="12" cy="12" r="10"></circle>
    <line x1="12" x2="12" y1="8" y2="12"></line>
    <line x1="12" x2="12.01" y1="16" y2="16"></line>
  </svg>
);

export default AnalysisPage;
