// Type definitions for dashboard data structures

export interface UserAccountData {
  status: 'active' | 'restricted' | 'limited' | 'inactive';
  accessLevel: 'basic' | 'standard' | 'premium' | 'enterprise';
  twoFactorEnabled: boolean;
  emailVerified: boolean;
  lastLogin: Date | null;
  accountCreated: Date;
  currentDevice?: string;
  ipRegion?: string;
}

export interface PortfolioSummary {
  assetExposure: string;
  positionCount: number;
  totalValue: number;
  allocationBreakdown: AllocationBreakdown[];
  assetClassDistribution: AssetClassDistribution[];
  geographicExposure: GeographicExposure[];
  currencyExposure: CurrencyExposure[];
  topHoldings: Holding[];
  diversityScore: number;
}

export interface AllocationBreakdown {
  category: string;
  percentage: number;
}

export interface AssetClassDistribution {
  type: 'stocks' | 'crypto' | 'bonds' | 'commodities' | 'real_estate' | 'other';
  percentage: number;
}

export interface GeographicExposure {
  region: string;
  percentage: number;
}

export interface CurrencyExposure {
  currency: string;
  percentage: number;
}

export interface Holding {
  name: string;
  symbol: string;
  percentage: number;
}

export interface RiskAssessment {
  exposureLevel: 'low' | 'moderate' | 'elevated' | 'critical';
  marketRisk: number;
  volatilityRisk: number;
  concentrationRisk: number;
  liquidityRisk: number;
  currencyRisk: number;
  riskScore: number; // 0-100 scale
  riskTolerance: number; // 0-100 scale
  complianceStatus: 'compliant' | 'warning' | 'non_compliant';
  marginUsage?: number;
  leverageRatio?: number;
  stopLossCoverage?: boolean;
}

export interface ModelStatus {
  activeModels: string[];
  readinessState: 'ready' | 'training' | 'offline' | 'maintenance';
  lastAnalysis: Date | null;
  decisionSupportAvailable: boolean;
  analysisQueueStatus: 'idle' | 'processing' | 'queued';
  modelVersion: string;
  dataFreshness: string; // e.g. "2 hours ago"
  subscriptionStatus: 'active' | 'pending' | 'expired';
  apiUsageStats: {
    callsMade: number;
    remainingQuota: number;
  };
}

export interface SystemNotice {
  id: string;
  title: string;
  description: string;
  priority: 'critical' | 'important' | 'informational';
  category: 'security' | 'policy' | 'maintenance' | 'account_action';
  timestamp: Date;
  read: boolean;
  dismissible: boolean;
}

export interface DashboardData {
  userAccount: UserAccountData;
  portfolio: PortfolioSummary;
  risk: RiskAssessment;
  modelStatus: ModelStatus;
  systemNotices: SystemNotice[];
}

export enum SectionStatus {
  LOADING = 'loading',
  LOADED = 'loaded',
  ERROR = 'error',
  EMPTY = 'empty'
}