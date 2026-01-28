import { z } from 'zod';

// Enum types
export enum AnalysisType {
  MARKET_STATE = 'market_state',
  RISK_EVALUATION = 'risk_evaluation',
  MACRO_CONTEXT = 'macro_context',
  SYSTEM_ALERT = 'system_alert',
  DATA_QUALITY_ISSUE = 'data_quality_issue',
  UNCERTAINTY_DETECTION = 'uncertainty_detection',
  HUMAN_INPUT_REQUESTED = 'human_input_requested',
  MODEL_CONSENSUS = 'model_conensus',
  MODEL_DIVERGENCE = 'model_divergence'
}

export enum ConfidenceLevel {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  UNCERTAIN = 'uncertain'
}

export enum DecisionStatus {
  EXECUTED = 'executed',
  WITHHELD = 'withheld',
  PENDING = 'pending',
  OVERRIDDEN = 'overridden'
}

export enum DecisionType {
  RISK_FLAG = 'risk_flag',
  ANALYSIS_PAUSE = 'analysis_pause',
  HUMAN_CONFIRMATION = 'human_confirmation',
  WEIGHT_ADJUSTMENT = 'weight_adjustment',
  ESCALATION = 'escalation',
  DATA_QUALITY_ISSUE = 'data_quality_issue'
}

// Interfaces
export interface ModelOutput {
  id: string;
  modelId: string;
  modelName: string;
  modelVersion: string;
  timestamp: Date;
  analysisType: AnalysisType;
  content: string;
  confidence: ConfidenceLevel;
  referenceContext: {
    marketSnapshot?: any;
    timeframe?: string;
    environment?: string;
    [key: string]: any;
  };
  metadata: {
    version: string;
    source?: string;
    [key: string]: any;
  };
  hash: string;
  immutable: boolean;
}

export interface DecisionLogEntry {
  id: string;
  decisionType: DecisionType;
  triggerReason: string;
  modelsInvolved: string[];
  requiresHumanReview: boolean;
  status: DecisionStatus;
  timestamp: Date;
  outcomeDescription: string;
  reviewedBy: string | null;
  reviewTimestamp: Date | null;
  linkedActivityId?: string; // Links to corresponding activity feed entry
}

export interface MarketStateSnapshot {
  id: string;
  timestamp: Date;
  regime: string;
  volatilityInterpretation: string;
  liquidityObservations: string;
  consensusSummary: string;
  contributingModels: string[];
  dataFreshness: Date;
  uncertaintyLevel?: ConfidenceLevel;
}

export interface CrossModelComparison {
  id: string;
  timestamp: Date;
  agreementAreas: string[];
  divergenceAreas: string[];
  divergenceReasons: string[];
  divergenceMagnitude: 'minor' | 'significant' | 'critical';
  contributingModels: string[];
  temporalTrend: string;
}

export interface HistoricalAnalysisQuery {
  startDate: Date;
  endDate: Date;
  modelIds?: string[];
  analysisTypes?: AnalysisType[];
  searchKeywords?: string[];
}

// Zod schemas for validation
export const ModelOutputSchema = z.object({
  id: z.string().uuid(),
  modelId: z.string(),
  modelName: z.string(),
  modelVersion: z.string(),
  timestamp: z.date(),
  analysisType: z.nativeEnum(AnalysisType),
  content: z.string(),
  confidence: z.nativeEnum(ConfidenceLevel),
  referenceContext: z.record(z.any()),
  metadata: z.object({
    version: z.string(),
    source: z.string().optional()
  }),
  hash: z.string(),
  immutable: z.boolean()
});

export const DecisionLogEntrySchema = z.object({
  id: z.string().uuid(),
  decisionType: z.nativeEnum(DecisionType),
  triggerReason: z.string(),
  modelsInvolved: z.array(z.string()),
  requiresHumanReview: z.boolean(),
  status: z.nativeEnum(DecisionStatus),
  timestamp: z.date(),
  outcomeDescription: z.string(),
  reviewedBy: z.string().nullable(),
  reviewTimestamp: z.date().nullable(),
  linkedActivityId: z.string().optional()
});

export const MarketStateSnapshotSchema = z.object({
  id: z.string().uuid(),
  timestamp: z.date(),
  regime: z.string(),
  volatilityInterpretation: z.string(),
  liquidityObservations: z.string(),
  consensusSummary: z.string(),
  contributingModels: z.array(z.string()),
  dataFreshness: z.date(),
  uncertaintyLevel: z.nativeEnum(ConfidenceLevel).optional()
});