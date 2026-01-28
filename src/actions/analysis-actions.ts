'use server';

import { 
  ModelOutput, 
  DecisionLogEntry, 
  MarketStateSnapshot, 
  CrossModelComparison,
  AnalysisType,
  ConfidenceLevel,
  DecisionStatus,
  DecisionType
} from '@/types/analysis';
import { generateModelOutputHash } from '@/utils/hash';
import { validateAndSanitizeModelOutput } from '@/lib/validation';

interface PaginationParams {
  page: number;
  limit: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

interface FilterParams {
  modelIds?: string[];
  dateRange?: { start: Date; end: Date };
  analysisTypes?: AnalysisType[];
  searchQuery?: string;
}

/**
 * Fetch model activity feed with pagination and filtering
 */
export async function getModelActivityFeed(
  filters: FilterParams = {},
  pagination: PaginationParams = { page: 1, limit: 20 }
): Promise<{ data: ModelOutput[]; total: number; page: number; totalPages: number }> {
  try {
    // Simulate server-side data fetching
    // In a real implementation, this would connect to a database
    
    // Mock data for demonstration
    const mockData: ModelOutput[] = [
      {
        id: '1',
        modelId: 'qm-001',
        modelName: 'QuantumMind Alpha',
        modelVersion: '1.2.3',
        timestamp: new Date(Date.now() - 3600000), // 1 hour ago
        analysisType: AnalysisType.MARKET_STATE,
        content: 'Market exhibits signs of elevated uncertainty with increased correlation across sectors. Volatility indicators suggest potential regime shift in progress.',
        confidence: ConfidenceLevel.HIGH,
        referenceContext: {
          timeframe: '60min',
          marketSnapshot: { spx: 4500, vix: 28.5, btc: 42000 }
        },
        metadata: { version: '1.0' },
        hash: generateModelOutputHash({ id: '1' }),
        immutable: true
      },
      {
        id: '2',
        modelId: 'qm-002',
        modelName: 'QuantumRisk Beta',
        modelVersion: '1.1.0',
        timestamp: new Date(Date.now() - 7200000), // 2 hours ago
        analysisType: AnalysisType.RISK_EVALUATION,
        content: 'Detected elevated risk in emerging markets segment. Data quality degraded for Asian indices post-market close. Recommend deferring position adjustments until fresh data available.',
        confidence: ConfidenceLevel.MEDIUM,
        referenceContext: {
          timeframe: 'daily',
          marketSnapshot: { asia_indices: 'degraded_data' }
        },
        metadata: { version: '1.0' },
        hash: generateModelOutputHash({ id: '2' }),
        immutable: true
      },
      {
        id: '3',
        modelId: 'qm-003',
        modelName: 'QuantumMacro Gamma',
        modelVersion: '1.0.5',
        timestamp: new Date(Date.now() - 10800000), // 3 hours ago
        analysisType: AnalysisType.MACRO_CONTEXT,
        content: 'Fed policy uncertainty continues to drive bond market volatility. Currency correlations increasing across developed markets. Energy sector showing resilience despite geopolitical tensions.',
        confidence: ConfidenceLevel.HIGH,
        referenceContext: {
          timeframe: 'daily',
          environment: 'pre-FOMC'
        },
        metadata: { version: '1.0' },
        hash: generateModelOutputHash({ id: '3' }),
        immutable: true
      },
      {
        id: '4',
        modelId: 'qm-001',
        modelName: 'QuantumMind Alpha',
        modelVersion: '1.2.3',
        timestamp: new Date(Date.now() - 14400000), // 4 hours ago
        analysisType: AnalysisType.SYSTEM_ALERT,
        content: 'Anomalous price action detected in semiconductor sector. Pattern recognition suggests potential algorithmic coordination. Flagging for human review.',
        confidence: ConfidenceLevel.HIGH,
        referenceContext: {
          timeframe: '30min',
          marketSnapshot: { semiconductors: 'anomalous_pattern' }
        },
        metadata: { version: '1.0' },
        hash: generateModelOutputHash({ id: '4' }),
        immutable: true
      },
      {
        id: '5',
        modelId: 'qm-004',
        modelName: 'QuantumQuality Delta',
        modelVersion: '0.9.2',
        timestamp: new Date(Date.now() - 18000000), // 5 hours ago
        analysisType: AnalysisType.DATA_QUALITY_ISSUE,
        content: 'Data quality issues identified in European equity feeds. Coverage reduced to 60% of usual universe. Temporarily reducing model confidence in European exposure calculations.',
        confidence: ConfidenceLevel.UNCERTAIN,
        referenceContext: {
          timeframe: 'hourly',
          environment: 'data_feed_issue'
        },
        metadata: { version: '1.0' },
        hash: generateModelOutputHash({ id: '5' }),
        immutable: true
      }
    ];

    // Apply filters
    let filteredData = [...mockData];
    
    if (filters.modelIds && filters.modelIds.length > 0) {
      filteredData = filteredData.filter(item => filters.modelIds?.includes(item.modelId));
    }
    
    if (filters.analysisTypes && filters.analysisTypes.length > 0) {
      filteredData = filteredData.filter(item => filters.analysisTypes?.includes(item.analysisType));
    }
    
    if (filters.dateRange) {
      filteredData = filteredData.filter(item => 
        item.timestamp >= filters.dateRange.start && item.timestamp <= filters.dateRange.end
      );
    }
    
    if (filters.searchQuery) {
      const query = filters.searchQuery.toLowerCase();
      filteredData = filteredData.filter(item => 
        item.content.toLowerCase().includes(query) || 
        item.modelName.toLowerCase().includes(query)
      );
    }

    // Apply pagination
    const total = filteredData.length;
    const startIndex = (pagination.page - 1) * pagination.limit;
    const endIndex = startIndex + pagination.limit;
    const paginatedData = filteredData.slice(startIndex, endIndex);
    const totalPages = Math.ceil(total / pagination.limit);

    return {
      data: paginatedData,
      total,
      page: pagination.page,
      totalPages
    };
  } catch (error) {
    console.error('Error fetching model activity feed:', error);
    throw new Error('Failed to fetch model activity feed');
  }
}

/**
 * Fetch market state analysis
 */
export async function getMarketStateAnalysis(): Promise<MarketStateSnapshot> {
  try {
    // Mock data for demonstration
    return {
      id: 'state-001',
      timestamp: new Date(),
      regime: 'Uncertainty Regime - Elevated Correlation',
      volatilityInterpretation: 'Volatility clustering observed with increased intraday swings. VIX above 25 suggests sustained uncertainty.',
      liquidityObservations: 'Liquidity remains adequate overall but showing regional disparities. Emerging markets experiencing outflows.',
      consensusSummary: 'Models generally aligned on elevated uncertainty but diverging on duration of current regime.',
      contributingModels: ['QuantumMind Alpha', 'QuantumRisk Beta', 'QuantumMacro Gamma'],
      dataFreshness: new Date(Date.now() - 120000), // 2 minutes ago
      uncertaintyLevel: ConfidenceLevel.HIGH
    };
  } catch (error) {
    console.error('Error fetching market state analysis:', error);
    throw new Error('Failed to fetch market state analysis');
  }
}

/**
 * Fetch decision log with pagination and filtering
 */
export async function getDecisionLog(
  filters: {
    modelIds?: string[];
    statuses?: DecisionStatus[];
    decisionTypes?: DecisionType[];
    dateRange?: { start: Date; end: Date };
  } = {},
  pagination: PaginationParams = { page: 1, limit: 20 }
): Promise<{ data: DecisionLogEntry[]; total: number; page: number; totalPages: number }> {
  try {
    // Mock data for demonstration
    const mockDecisions: DecisionLogEntry[] = [
      {
        id: 'dec-001',
        decisionType: DecisionType.RISK_FLAG,
        triggerReason: 'Elevated volatility in emerging markets segment',
        modelsInvolved: ['qm-002'],
        requiresHumanReview: true,
        status: DecisionStatus.PENDING,
        timestamp: new Date(Date.now() - 3600000),
        outcomeDescription: 'Risk flag raised for EM exposure. Awaiting human confirmation to adjust position limits.',
        reviewedBy: null,
        reviewTimestamp: null,
        linkedActivityId: '1'
      },
      {
        id: 'dec-002',
        decisionType: DecisionType.ANALYSIS_PAUSE,
        triggerReason: 'Degraded data quality in Asian indices',
        modelsInvolved: ['qm-001', 'qm-003'],
        requiresHumanReview: false,
        status: DecisionStatus.EXECUTED,
        timestamp: new Date(Date.now() - 7200000),
        outcomeDescription: 'Paused analysis of Asian markets until fresh data available.',
        reviewedBy: null,
        reviewTimestamp: null,
        linkedActivityId: '2'
      },
      {
        id: 'dec-003',
        decisionType: DecisionType.HUMAN_CONFIRMATION,
        triggerReason: 'Anomalous pattern detected in semiconductor sector',
        modelsInvolved: ['qm-001'],
        requiresHumanReview: true,
        status: DecisionStatus.WITHHELD,
        timestamp: new Date(Date.now() - 14400000),
        outcomeDescription: 'Requested human confirmation for algorithmic coordination flag in semiconductors.',
        reviewedBy: null,
        reviewTimestamp: null,
        linkedActivityId: '4'
      },
      {
        id: 'dec-004',
        decisionType: DecisionType.DATA_QUALITY_ISSUE,
        triggerReason: 'Coverage reduced to 60% of usual universe in European equities',
        modelsInvolved: ['qm-004'],
        requiresHumanReview: false,
        status: DecisionStatus.EXECUTED,
        timestamp: new Date(Date.now() - 18000000),
        outcomeDescription: 'Reduced model confidence in European exposure calculations due to data quality issues.',
        reviewedBy: null,
        reviewTimestamp: null,
        linkedActivityId: '5'
      }
    ];

    // Apply filters
    let filteredData = [...mockDecisions];
    
    if (filters.modelIds && filters.modelIds.length > 0) {
      filteredData = filteredData.filter(item => 
        item.modelsInvolved.some(model => filters.modelIds?.includes(model))
      );
    }
    
    if (filters.statuses && filters.statuses.length > 0) {
      filteredData = filteredData.filter(item => filters.statuses?.includes(item.status));
    }
    
    if (filters.decisionTypes && filters.decisionTypes.length > 0) {
      filteredData = filteredData.filter(item => filters.decisionTypes?.includes(item.decisionType));
    }
    
    if (filters.dateRange) {
      filteredData = filteredData.filter(item => 
        item.timestamp >= filters.dateRange.start && item.timestamp <= filters.dateRange.end
      );
    }

    // Apply pagination
    const total = filteredData.length;
    const startIndex = (pagination.page - 1) * pagination.limit;
    const endIndex = startIndex + pagination.limit;
    const paginatedData = filteredData.slice(startIndex, endIndex);
    const totalPages = Math.ceil(total / pagination.limit);

    return {
      data: paginatedData,
      total,
      page: pagination.page,
      totalPages
    };
  } catch (error) {
    console.error('Error fetching decision log:', error);
    throw new Error('Failed to fetch decision log');
  }
}

/**
 * Fetch cross-model reasoning comparison
 */
export async function getCrossModelComparison(): Promise<CrossModelComparison[]> {
  try {
    // Mock data for demonstration
    return [
      {
        id: 'cmp-001',
        timestamp: new Date(Date.now() - 3600000),
        agreementAreas: [
          'Elevated market uncertainty',
          'Increased correlation across sectors',
          'Volatility clustering pattern'
        ],
        divergenceAreas: [
          'Duration of current regime',
          'Impact on emerging markets',
          'Policy response timing'
        ],
        divergenceReasons: [
          'Different training data timeframes',
          'Varying sensitivity to macro indicators',
          'Alternative risk factor weighting'
        ],
        divergenceMagnitude: 'significant',
        contributingModels: ['QuantumMind Alpha', 'QuantumRisk Beta', 'QuantumMacro Gamma'],
        temporalTrend: 'Divergence initiated 3 days ago, stabilizing recently'
      },
      {
        id: 'cmp-002',
        timestamp: new Date(Date.now() - 86400000), // 1 day ago
        agreementAreas: [
          'Bond market sensitivity to Fed policy',
          'Currency correlation increases',
          'Energy sector resilience'
        ],
        divergenceAreas: [
          'Equity market direction',
          'Credit spread expectations',
          'Commodity positioning'
        ],
        divergenceReasons: [
          'Different economic scenario assumptions',
          'Varying geopolitical risk assessment',
          'Alternative sector rotation timing'
        ],
        divergenceMagnitude: 'minor',
        contributingModels: ['QuantumMind Alpha', 'QuantumRisk Beta', 'QuantumMacro Gamma'],
        temporalTrend: 'Minor divergence, showing early convergence'
      }
    ];
  } catch (error) {
    console.error('Error fetching cross-model comparison:', error);
    throw new Error('Failed to fetch cross-model comparison');
  }
}

/**
 * Validate and store new model output
 */
export async function submitModelOutput(output: Omit<ModelOutput, 'id' | 'hash' | 'immutable'>): Promise<ModelOutput> {
  try {
    // Sanitize and validate the incoming model output
    const sanitizedOutput = validateAndSanitizeModelOutput(output);
    
    // Generate ID and hash
    const id = `out-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const hash = generateModelOutputHash({ ...sanitizedOutput, id });
    
    const completeOutput: ModelOutput = {
      ...sanitizedOutput,
      id,
      hash,
      immutable: true
    };

    // In a real implementation, save to database here
    console.log(`Model output submitted: ${completeOutput.id}`);
    
    return completeOutput;
  } catch (error) {
    console.error('Error submitting model output:', error);
    throw new Error('Failed to submit model output');
  }
}