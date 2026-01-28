'use client';

import React, { useState, useEffect } from 'react';
import { auth } from '@/auth';
import { 
  getUserSelections, 
  updateModelSelection, 
  updateDecisionMode, 
  updateCapability, 
  updateProfileSelection, 
  updateFutureModuleOptIn, 
  getUserAuditLogs, 
  applyPreset 
} from '@/actions/selection';
import { 
  UserSelections, 
  AIModel, 
  DecisionMode, 
  BehavioralProfile, 
  Capability, 
  FutureModule, 
  ConfigurationPreset, 
  RiskSummary,
  DecisionAuthorityLevel,
  RiskLevel,
  ResourceImpact,
  ModelCostTier,
  ModelLatencyClass,
  ModelStatus
} from '@/types/selection';
import ModelSelector from '@/components/selection/ModelSelector';
import DecisionModeSelector from '@/components/selection/DecisionModeSelector';
import CapabilityToggle from '@/components/selection/CapabilityToggle';
import ProfileSelector from '@/components/selection/ProfileSelector';
import FutureModuleToggle from '@/components/selection/FutureModuleToggle';
import PresetSelector from '@/components/selection/PresetSelector';
import AuditLogTable from '@/components/selection/AuditLogTable';

// Mock data for demonstration
const mockModels: AIModel[] = [
  {
    id: 'gpt-4-standard',
    name: 'GPT-4 Standard',
    description: 'General purpose model with balanced performance',
    contextWindowSize: 8192,
    costTier: ModelCostTier.STANDARD,
    latencyClass: ModelLatencyClass.BALANCED,
    status: ModelStatus.ACTIVE,
    capabilities: ['marketAnalysis', 'newsInterpretation', 'conversationalAI'],
    version: '4.0.1'
  },
  {
    id: 'gpt-4-turbo',
    name: 'GPT-4 Turbo',
    description: 'High-performance model optimized for speed',
    contextWindowSize: 128000,
    costTier: ModelCostTier.PREMIUM,
    latencyClass: ModelLatencyClass.FAST,
    status: ModelStatus.ACTIVE,
    capabilities: ['marketAnalysis', 'scenarioAnalysis', 'technicalPattern'],
    version: '4.0-turbo'
  },
  {
    id: 'claude-3-haiku',
    name: 'Claude 3 Haiku',
    description: 'Lightweight model for quick analysis',
    contextWindowSize: 200000,
    costTier: ModelCostTier.STANDARD,
    latencyClass: ModelLatencyClass.FAST,
    status: ModelStatus.ACTIVE,
    capabilities: ['riskEvaluation', 'anomalyDetection', 'sentimentAnalysis'],
    version: '3.0-haiku'
  },
  {
    id: 'claude-3-sonnet',
    name: 'Claude 3 Sonnet',
    description: 'Balanced model for complex analysis',
    contextWindowSize: 200000,
    costTier: ModelCostTier.PREMIUM,
    latencyClass: ModelLatencyClass.BALANCED,
    status: ModelStatus.ACTIVE,
    capabilities: ['riskEvaluation', 'fundamentalAnalysis', 'newsInterpretation'],
    version: '3.0-sonnet'
  },
  {
    id: 'claude-3-opus',
    name: 'Claude 3 Opus',
    description: 'Advanced model for deep analysis',
    contextWindowSize: 200000,
    costTier: ModelCostTier.ENTERPRISE,
    latencyClass: ModelLatencyClass.DEEP,
    status: ModelStatus.ACTIVE,
    capabilities: ['scenarioAnalysis', 'portfolioOptimization'],
    version: '3.0-opus'
  },
  {
    id: 'dbrx-standard',
    name: 'DBRX Standard',
    description: 'Specialized model for pattern recognition',
    contextWindowSize: 32768,
    costTier: ModelCostTier.PREMIUM,
    latencyClass: ModelLatencyClass.BALANCED,
    status: ModelStatus.ACTIVE,
    capabilities: ['patternRecognition', 'technicalPattern'],
    version: '1.0'
  },
];

const mockDecisionModes: DecisionMode[] = [
  {
    id: DecisionAuthorityLevel.OBSERVATION_ONLY,
    name: 'Observation Only',
    description: 'AI provides insights for review. No execution authority.',
    riskLevel: 1,
    requiresAuthentication: false,
    requiresConfirmation: false,
    prerequisites: [],
    auditTrailRequired: true
  },
  {
    id: DecisionAuthorityLevel.ADVISORY,
    name: 'Advisory Mode',
    description: 'AI provides recommendations requiring human confirmation before execution.',
    riskLevel: 2,
    requiresAuthentication: true,
    requiresConfirmation: true,
    prerequisites: ['identity_verification'],
    auditTrailRequired: true
  },
  {
    id: DecisionAuthorityLevel.ASSISTED_EXECUTION,
    name: 'Assisted Execution',
    description: 'AI can execute actions with limited scope after initial confirmation.',
    riskLevel: 4,
    requiresAuthentication: true,
    requiresConfirmation: true,
    prerequisites: ['identity_verification', 'risk_acknowledgment', 'admin_approval'],
    auditTrailRequired: true
  },
  {
    id: DecisionAuthorityLevel.AUTOMATED_EXECUTION,
    name: 'Automated Execution',
    description: 'AI can execute actions autonomously based on predefined criteria.',
    riskLevel: 5,
    requiresAuthentication: true,
    requiresConfirmation: true,
    prerequisites: ['identity_verification', 'risk_acknowledgment', 'multi_factor_auth', 'admin_approval'],
    auditTrailRequired: true
  },
];

const mockProfiles: BehavioralProfile[] = [
  {
    id: 'conservative',
    name: 'Conservative',
    description: 'Prioritizes risk mitigation and cautious analysis',
    characteristics: {
      informationProcessing: 'Thorough, detailed analysis',
      alertSensitivity: 'Low threshold for alerts',
      dataDepthPreference: 'Deep historical analysis',
      updateFrequency: 'Daily updates',
      computationIntensity: 'Moderate'
    },
    flags: ['risk_aversion', 'detailed_validation']
  },
  {
    id: 'balanced',
    name: 'Balanced',
    description: 'Standard approach balancing risk and opportunity',
    characteristics: {
      informationProcessing: 'Standard analytical approach',
      alertSensitivity: 'Medium threshold for alerts',
      dataDepthPreference: 'Mixed historical/real-time',
      updateFrequency: 'Hourly updates',
      computationIntensity: 'Moderate'
    },
    flags: ['balanced_approach']
  },
  {
    id: 'exploratory',
    name: 'Exploratory',
    description: 'Focuses on discovering new opportunities',
    characteristics: {
      informationProcessing: 'Open to novel approaches',
      alertSensitivity: 'High threshold for alerts',
      dataDepthPreference: 'Real-time focused',
      updateFrequency: 'Continuous updates',
      computationIntensity: 'High'
    },
    flags: ['opportunity_focused', 'novel_approaches']
  },
  {
    id: 'risk-aware',
    name: 'Risk-Aware',
    description: 'Emphasizes risk assessment and monitoring',
    characteristics: {
      informationProcessing: 'Risk-focused analysis',
      alertSensitivity: 'Very low threshold for alerts',
      dataDepthPreference: 'Comprehensive historical',
      updateFrequency: 'Continuous updates',
      computationIntensity: 'High'
    },
    flags: ['risk_focus', 'comprehensive_monitoring']
  },
  {
    id: 'data-intensive',
    name: 'Data-Intensive',
    description: 'Processes large volumes of data for insights',
    characteristics: {
      informationProcessing: 'Volume-focused analysis',
      alertSensitivity: 'Medium threshold for alerts',
      dataDepthPreference: 'Deep historical datasets',
      updateFrequency: 'Frequent updates',
      computationIntensity: 'Very High'
    },
    flags: ['volume_processing', 'deep_analysis']
  },
  {
    id: 'latency-sensitive',
    name: 'Latency-Sensitive',
    description: 'Prioritizes speed over depth of analysis',
    characteristics: {
      informationProcessing: 'Fast analysis with limited depth',
      alertSensitivity: 'Medium threshold for alerts',
      dataDepthPreference: 'Recent data focus',
      updateFrequency: 'Real-time updates',
      computationIntensity: 'Moderate'
    },
    flags: ['speed_optimized', 'recent_data_focus']
  },
  {
    id: 'compliance-first',
    name: 'Compliance-First',
    description: 'Ensures all activities meet regulatory requirements',
    characteristics: {
      informationProcessing: 'Regulatory-compliant analysis',
      alertSensitivity: 'Medium threshold for alerts',
      dataDepthPreference: 'Compliance-focused datasets',
      updateFrequency: 'Daily updates',
      computationIntensity: 'Moderate'
    },
    flags: ['regulatory_compliance', 'audit_trail']
  },
  {
    id: 'research-oriented',
    name: 'Research-Oriented',
    description: 'Focuses on academic and market research',
    characteristics: {
      informationProcessing: 'Academic-style analysis',
      alertSensitivity: 'Low threshold for alerts',
      dataDepthPreference: 'Long-term historical',
      updateFrequency: 'Weekly updates',
      computationIntensity: 'High'
    },
    flags: ['academic_approach', 'long_term_focus']
  }
];

const mockCapabilities: Capability[] = [
  {
    id: 'news-aware-analysis',
    name: 'News-Aware Analysis',
    description: 'Integrates real-time news and events into market analysis',
    enabled: true,
    riskLevel: RiskLevel.LOW,
    resourceImpact: ResourceImpact.MODERATE,
    dependencies: [],
    dataRequirements: ['news_feeds', 'event_data'],
    complianceTags: ['regulatory_compliant'],
    isBeta: false,
    isLocked: false,
    lastUpdated: new Date('2024-01-15')
  },
  {
    id: 'multi-model-consensus',
    name: 'Multi-Model Consensus',
    description: 'Combines insights from multiple AI models for consensus',
    enabled: true,
    riskLevel: RiskLevel.LOW,
    resourceImpact: ResourceImpact.HIGH,
    dependencies: ['ai_models'],
    dataRequirements: ['multiple_ai_outputs'],
    complianceTags: ['transparent'],
    isBeta: false,
    isLocked: false,
    lastUpdated: new Date('2024-01-10')
  },
  {
    id: 'scenario-simulation',
    name: 'Scenario Simulation',
    description: 'Runs hypothetical market scenarios to assess potential outcomes',
    enabled: false,
    riskLevel: RiskLevel.MEDIUM,
    resourceImpact: ResourceImpact.HIGH,
    dependencies: ['historical_data'],
    dataRequirements: ['simulation_parameters'],
    complianceTags: ['educational'],
    isBeta: true,
    isLocked: false,
    lastUpdated: new Date('2024-01-20')
  },
  {
    id: 'auto-report-generation',
    name: 'Auto-Report Generation',
    description: 'Automatically creates periodic reports based on analysis',
    enabled: false,
    riskLevel: RiskLevel.LOW,
    resourceImpact: ResourceImpact.MODERATE,
    dependencies: ['analysis_results'],
    dataRequirements: ['report_templates'],
    complianceTags: ['archival'],
    isBeta: false,
    isLocked: false,
    lastUpdated: new Date('2024-01-05')
  },
  {
    id: 'real-time-alert-system',
    name: 'Real-Time Alert System',
    description: 'Provides immediate notifications for significant market events',
    enabled: true,
    riskLevel: RiskLevel.LOW,
    resourceImpact: ResourceImpact.MODERATE,
    dependencies: ['market_data'],
    dataRequirements: ['alert_rules'],
    complianceTags: ['monitoring'],
    isBeta: false,
    isLocked: false,
    lastUpdated: new Date('2024-01-12')
  },
  {
    id: 'historical-pattern-matching',
    name: 'Historical Pattern Matching',
    description: 'Identifies patterns in historical data that may repeat',
    enabled: true,
    riskLevel: RiskLevel.LOW,
    resourceImpact: ResourceImpact.HIGH,
    dependencies: ['historical_data'],
    dataRequirements: ['pattern_databases'],
    complianceTags: ['analytical'],
    isBeta: false,
    isLocked: false,
    lastUpdated: new Date('2024-01-08')
  },
  {
    id: 'cross-asset-correlation',
    name: 'Cross-Asset Correlation',
    description: 'Analyzes relationships between different asset classes',
    enabled: true,
    riskLevel: RiskLevel.MEDIUM,
    resourceImpact: ResourceImpact.HIGH,
    dependencies: ['multi_asset_data'],
    dataRequirements: ['correlation_matrices'],
    complianceTags: ['diversified'],
    isBeta: false,
    isLocked: false,
    lastUpdated: new Date('2024-01-18')
  },
  {
    id: 'macro-event-tracking',
    name: 'Macro Event Tracking',
    description: 'Monitors economic indicators and policy changes',
    enabled: true,
    riskLevel: RiskLevel.LOW,
    resourceImpact: ResourceImpact.MODERATE,
    dependencies: ['economic_data'],
    dataRequirements: ['macro_indicators'],
    complianceTags: ['fundamental'],
    isBeta: false,
    isLocked: false,
    lastUpdated: new Date('2024-01-14')
  },
  {
    id: 'portfolio-stress-testing',
    name: 'Portfolio Stress Testing',
    description: 'Simulates portfolio performance under adverse conditions',
    enabled: true,
    riskLevel: RiskLevel.LOW,
    resourceImpact: ResourceImpact.HIGH,
    dependencies: ['portfolio_data'],
    dataRequirements: ['stress_scenarios'],
    complianceTags: ['risk_management'],
    isBeta: false,
    isLocked: false,
    lastUpdated: new Date('2024-01-16')
  },
  {
    id: 'sentiment-drift-detection',
    name: 'Sentiment Drift Detection',
    description: 'Identifies shifts in market sentiment over time',
    enabled: true,
    riskLevel: RiskLevel.LOW,
    resourceImpact: ResourceImpact.MODERATE,
    dependencies: ['news_sentiment'],
    dataRequirements: ['sentiment_scores'],
    complianceTags: ['behavioral'],
    isBeta: false,
    isLocked: false,
    lastUpdated: new Date('2024-01-11')
  },
  {
    id: 'volatility-regime-detection',
    name: 'Volatility Regime Detection',
    description: 'Identifies periods of high and low market volatility',
    enabled: true,
    riskLevel: RiskLevel.LOW,
    resourceImpact: ResourceImpact.MODERATE,
    dependencies: ['price_data'],
    dataRequirements: ['volatility_metrics'],
    complianceTags: ['technical'],
    isBeta: false,
    isLocked: false,
    lastUpdated: new Date('2024-01-09')
  },
  {
    id: 'liquidity-analysis',
    name: 'Liquidity Analysis',
    description: 'Assesses market liquidity conditions and their impact',
    enabled: false,
    riskLevel: RiskLevel.MEDIUM,
    resourceImpact: ResourceImpact.HIGH,
    dependencies: ['trading_volume'],
    dataRequirements: ['liquidity_metrics'],
    complianceTags: ['execution'],
    isBeta: true,
    isLocked: false,
    lastUpdated: new Date('2024-01-22')
  },
  {
    id: 'future-automated-execution',
    name: 'Future Automated Execution',
    description: 'Automated execution of trading strategies (Coming Soon)',
    enabled: false,
    riskLevel: RiskLevel.CRITICAL,
    resourceImpact: ResourceImpact.EXTREME,
    dependencies: ['execution_permissions'],
    dataRequirements: ['strategy_parameters'],
    complianceTags: ['high_risk'],
    isBeta: false,
    isLocked: true,
    lastUpdated: new Date('2024-01-25')
  }
];

const mockFutureModules: FutureModule[] = [
  {
    id: 'advanced-algo-trading',
    name: 'Advanced Algorithmic Trading',
    description: 'Sophisticated algorithmic trading strategies powered by ML',
    plannedRelease: 'Q2 2024',
    prerequisites: ['execution_permissions', 'risk_acknowledgment'],
    riskDisclosure: 'Higher risk due to automated trading decisions',
    dataCollectionNotice: 'Usage data will be collected for model improvement',
    revocationRights: 'You may revoke access at any time',
    waitlistStatus: 'open',
    isOptedIn: false
  },
  {
    id: 'predictive-modeling',
    name: 'Predictive Market Modeling',
    description: 'Advanced predictive models for price forecasting',
    plannedRelease: 'Q3 2024',
    prerequisites: ['research_subscription'],
    riskDisclosure: 'Predictive models are not guarantees of future performance',
    dataCollectionNotice: 'Market data will be analyzed to improve predictions',
    revocationRights: 'You may revoke access at any time',
    waitlistStatus: 'closed',
    isOptedIn: false
  },
  {
    id: 'cross-platform-integration',
    name: 'Cross-Platform Integration',
    description: 'Integration with external trading platforms and APIs',
    plannedRelease: 'Q4 2024',
    prerequisites: ['api_access'],
    riskDisclosure: 'External integrations may introduce additional security risks',
    dataCollectionNotice: 'Transaction data may be shared with integrated platforms',
    revocationRights: 'You may revoke access at any time',
    waitlistStatus: 'beta',
    isOptedIn: false
  }
];

const mockPresets: ConfigurationPreset[] = [
  {
    id: 'default-safe-mode',
    name: 'Default Safe Mode',
    description: 'Basic analysis with minimal risk exposure',
    targetAudience: 'New users, conservative traders',
    riskLevel: RiskLevel.LOW,
    resourceImpact: ResourceImpact.MODERATE,
    changes: {
      models: {},
      modes: { decisionMode: 'observation_only' },
      capabilities: {},
      profiles: ['conservative', 'compliance-first']
    }
  },
  {
    id: 'research-analysis-mode',
    name: 'Research & Analysis Mode',
    description: 'Comprehensive analysis tools for research purposes',
    targetAudience: 'Researchers, analysts',
    riskLevel: RiskLevel.MEDIUM,
    resourceImpact: ResourceImpact.HIGH,
    changes: {
      models: {},
      modes: { decisionMode: 'advisory' },
      capabilities: {},
      profiles: ['exploratory', 'data-intensive']
    }
  },
  {
    id: 'active-trading-mode',
    name: 'Active Trading Mode',
    description: 'Tools optimized for active trading decisions',
    targetAudience: 'Active traders (requires elevated permissions)',
    riskLevel: RiskLevel.HIGH,
    resourceImpact: ResourceImpact.HIGH,
    changes: {
      models: {},
      modes: { decisionMode: 'advisory' },
      capabilities: {},
      profiles: ['balanced', 'latency-sensitive']
    }
  },
  {
    id: 'compliance-audit-mode',
    name: 'Compliance & Audit Mode',
    description: 'Focus on regulatory compliance and audit trails',
    targetAudience: 'Compliance officers',
    riskLevel: RiskLevel.LOW,
    resourceImpact: ResourceImpact.MODERATE,
    changes: {
      models: {},
      modes: { decisionMode: 'observation_only' },
      capabilities: {},
      profiles: ['compliance-first', 'risk-aware']
    }
  },
  {
    id: 'minimal-resource-mode',
    name: 'Minimal Resource Mode',
    description: 'Reduced capabilities to minimize computational resources',
    targetAudience: 'Budget-conscious users',
    riskLevel: RiskLevel.LOW,
    resourceImpact: ResourceImpact.MINIMAL,
    changes: {
      models: {},
      modes: { decisionMode: 'observation_only' },
      capabilities: {},
      profiles: ['conservative']
    }
  },
  {
    id: 'maximum-intelligence-mode',
    name: 'Maximum Intelligence Mode',
    description: 'Full suite of advanced analytical capabilities',
    targetAudience: 'Power users (requires enterprise subscription)',
    riskLevel: RiskLevel.HIGH,
    resourceImpact: ResourceImpact.EXTREME,
    changes: {
      models: {},
      modes: { decisionMode: 'advisory' },
      capabilities: {},
      profiles: ['exploratory', 'data-intensive', 'research-oriented']
    }
  }
];

const mockRiskSummary: RiskSummary = {
  overallRiskLevel: RiskLevel.MEDIUM,
  activeHighRiskConfigs: ['multi-model-consensus', 'cross-asset-correlation'],
  complianceStatus: 'Compliant',
  requiredActionsCount: 0,
  lastSecurityReview: new Date()
};

const mockAuditLogs = [
  {
    timestamp: new Date(Date.now() - 86400000),
    changeType: 'model',
    previousValue: 'gpt-4-standard',
    newValue: 'gpt-4-turbo',
    ipAddress: '192.168.1.100',
    sessionId: 'sess_abc123',
    changeReason: 'Performance optimization'
  },
  {
    timestamp: new Date(Date.now() - 172800000),
    changeType: 'mode',
    previousValue: 'observation_only',
    newValue: 'advisory',
    ipAddress: '192.168.1.100',
    sessionId: 'sess_def456',
    changeReason: 'Increased authority level'
  },
  {
    timestamp: new Date(Date.now() - 259200000),
    changeType: 'capability',
    previousValue: false,
    newValue: true,
    ipAddress: '192.168.1.100',
    sessionId: 'sess_ghi789',
    changeReason: 'Enabled new feature'
  }
];

const SelectionPage = () => {
  const [userSelections, setUserSelections] = useState<UserSelections | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('models');
  const [searchTerm, setSearchTerm] = useState('');
  const [filteredCapabilities, setFilteredCapabilities] = useState<Capability[]>(mockCapabilities);
  const [unsavedChanges, setUnsavedChanges] = useState(false);
  const [lastSaved, setLastSaved] = useState<Date | null>(null);

  useEffect(() => {
    const fetchUserData = async () => {
      try {
        // In a real implementation, we would get the user ID from the session
        const userId = 'user_123'; // Placeholder
        const selections = await getUserSelections(userId);
        
        if (selections) {
          setUserSelections(selections);
        } else {
          // Initialize with default selections
          setUserSelections({
            id: 'init_123',
            userId: 'user_123',
            aiModels: {
              marketAnalysis: 'gpt-4-standard',
              riskEvaluation: 'claude-3-haiku',
              newsInterpretation: 'gpt-4-standard',
              scenarioAnalysis: 'claude-3-opus',
              conversationalAI: 'gpt-4-turbo',
              portfolioOptimization: 'dbrx-standard',
              anomalyDetection: 'claude-3-haiku',
              sentimentAnalysis: 'gpt-4-standard',
              patternRecognition: 'dbrx-standard',
              fundamentalAnalysis: 'claude-3-sonnet',
            },
            decisionMode: 'observation_only',
            activeProfiles: ['conservative'],
            enabledCapabilities: [
              'news-aware-analysis',
              'multi-model-consensus',
              'historical-pattern-matching',
              'cross-asset-correlation',
              'macro-event-tracking',
              'portfolio-stress-testing',
              'sentiment-drift-detection',
              'volatility-regime-detection',
            ],
            optedInModules: [],
            configurationVersion: '1.0.0',
            createdAt: new Date(),
            updatedAt: new Date(),
            hash: 'hash_123'
          });
        }
      } catch (error) {
        console.error('Error fetching user selections:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchUserData();
  }, []);

  useEffect(() => {
    if (searchTerm.trim() === '') {
      setFilteredCapabilities(mockCapabilities);
    } else {
      const term = searchTerm.toLowerCase();
      setFilteredCapabilities(
        mockCapabilities.filter(cap =>
          cap.name.toLowerCase().includes(term) ||
          cap.description.toLowerCase().includes(term)
        )
      );
    }
  }, [searchTerm]);

  const handleModelChange = async (capability: string, modelId: string) => {
    if (!userSelections) return;
    
    const result = await updateModelSelection(userSelections.userId, capability, modelId);
    if (result.success) {
      setUserSelections(prev => prev ? {
        ...prev,
        aiModels: { ...prev.aiModels, [capability]: modelId }
      } : null);
      setUnsavedChanges(true);
    }
  };

  const handleDecisionModeChange = async (modeId: DecisionAuthorityLevel) => {
    if (!userSelections) return;
    
    const result = await updateDecisionMode(userSelections.userId, modeId);
    if (result.success) {
      setUserSelections(prev => prev ? { ...prev, decisionMode: modeId } : null);
      setUnsavedChanges(true);
    }
  };

  const handleCapabilityToggle = async (capabilityId: string, enabled: boolean) => {
    if (!userSelections) return;
    
    const result = await updateCapability(userSelections.userId, capabilityId, enabled);
    if (result.success) {
      setUserSelections(prev => {
        if (!prev) return null;
        const newCapabilities = enabled 
          ? [...prev.enabledCapabilities, capabilityId]
          : prev.enabledCapabilities.filter(id => id !== capabilityId);
        return { ...prev, enabledCapabilities: newCapabilities };
      });
      setUnsavedChanges(true);
    }
  };

  const handleProfileToggle = async (profileId: string) => {
    if (!userSelections) return;
    
    const newProfiles = userSelections.activeProfiles.includes(profileId)
      ? userSelections.activeProfiles.filter(id => id !== profileId)
      : [...userSelections.activeProfiles, profileId];
      
    const result = await updateProfileSelection(userSelections.userId, newProfiles);
    if (result.success) {
      setUserSelections(prev => prev ? { ...prev, activeProfiles: newProfiles } : null);
      setUnsavedChanges(true);
    }
  };

  const handleFutureModuleToggle = async (moduleId: string, optedIn: boolean) => {
    if (!userSelections) return;
    
    const result = await updateFutureModuleOptIn(userSelections.userId, moduleId, optedIn);
    if (result.success) {
      setUserSelections(prev => {
        if (!prev) return null;
        const newOptedIns = optedIn 
          ? [...prev.optedInModules, moduleId]
          : prev.optedInModules.filter(id => id !== moduleId);
        return { ...prev, optedInModules: newOptedIns };
      });
      setUnsavedChanges(true);
    }
  };

  const handleApplyPreset = async (presetId: string) => {
    if (!userSelections) return;
    
    const result = await applyPreset(userSelections.userId, presetId);
    if (result.success) {
      // In a real implementation, we would reload the selections
      setUnsavedChanges(true);
    }
  };

  const handleSaveChanges = () => {
    setUnsavedChanges(false);
    setLastSaved(new Date());
  };

  const getRiskLevelColor = (level: RiskLevel) => {
    switch (level) {
      case RiskLevel.LOW: return 'text-green-400';
      case RiskLevel.MEDIUM: return 'text-yellow-400';
      case RiskLevel.HIGH: return 'text-orange-400';
      case RiskLevel.CRITICAL: return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  const getResourceImpactColor = (impact: ResourceImpact) => {
    switch (impact) {
      case ResourceImpact.MINIMAL: return 'text-green-400';
      case ResourceImpact.MODERATE: return 'text-yellow-400';
      case ResourceImpact.HIGH: return 'text-orange-400';
      case ResourceImpact.EXTREME: return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  const getModelCostTierColor = (tier: ModelCostTier) => {
    switch (tier) {
      case ModelCostTier.STANDARD: return 'text-blue-400';
      case ModelCostTier.PREMIUM: return 'text-purple-400';
      case ModelCostTier.ENTERPRISE: return 'text-amber-400';
      default: return 'text-gray-400';
    }
  };

  const getModelLatencyClassColor = (cls: ModelLatencyClass) => {
    switch (cls) {
      case ModelLatencyClass.FAST: return 'text-green-400';
      case ModelLatencyClass.BALANCED: return 'text-yellow-400';
      case ModelLatencyClass.DEEP: return 'text-purple-400';
      default: return 'text-gray-400';
    }
  };

  const renderModelSelectionSection = () => (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-white mb-4">AI Model Selection</h2>
      <p className="text-gray-400 mb-6">
        Select which AI model(s) are used for each system area. Models are characterized by their attributes, not performance claims.
      </p>
      
      <ModelSelector
        title="Market Analysis"
        description="For analyzing market trends, price movements, and general market conditions"
        currentModelId={userSelections?.aiModels.marketAnalysis || 'gpt-4-standard'}
        models={mockModels}
        onModelChange={(modelId) => handleModelChange('marketAnalysis', modelId)}
        capability="marketAnalysis"
      />
      
      <ModelSelector
        title="Risk Evaluation"
        description="For assessing and monitoring risk factors and potential threats"
        currentModelId={userSelections?.aiModels.riskEvaluation || 'claude-3-haiku'}
        models={mockModels}
        onModelChange={(modelId) => handleModelChange('riskEvaluation', modelId)}
        capability="riskEvaluation"
      />
      
      <ModelSelector
        title="News & Macro Interpretation"
        description="For processing news events and macroeconomic data"
        currentModelId={userSelections?.aiModels.newsInterpretation || 'gpt-4-standard'}
        models={mockModels}
        onModelChange={(modelId) => handleModelChange('newsInterpretation', modelId)}
        capability="newsInterpretation"
      />
      
      <ModelSelector
        title="Scenario Analysis"
        description="For modeling hypothetical scenarios and their potential impacts"
        currentModelId={userSelections?.aiModels.scenarioAnalysis || 'claude-3-opus'}
        models={mockModels}
        onModelChange={(modelId) => handleModelChange('scenarioAnalysis', modelId)}
        capability="scenarioAnalysis"
      />
      
      <ModelSelector
        title="Conversational AI"
        description="For interactive conversations and Q&A sessions"
        currentModelId={userSelections?.aiModels.conversationalAI || 'gpt-4-turbo'}
        models={mockModels}
        onModelChange={(modelId) => handleModelChange('conversationalAI', modelId)}
        capability="conversationalAI"
      />
      
      <ModelSelector
        title="Portfolio Optimization"
        description="For optimizing portfolio allocation and rebalancing"
        currentModelId={userSelections?.aiModels.portfolioOptimization || 'dbrx-standard'}
        models={mockModels}
        onModelChange={(modelId) => handleModelChange('portfolioOptimization', modelId)}
        capability="portfolioOptimization"
      />
      
      <ModelSelector
        title="Anomaly Detection"
        description="For identifying unusual patterns or outliers in data"
        currentModelId={userSelections?.aiModels.anomalyDetection || 'claude-3-haiku'}
        models={mockModels}
        onModelChange={(modelId) => handleModelChange('anomalyDetection', modelId)}
        capability="anomalyDetection"
      />
      
      <ModelSelector
        title="Sentiment Analysis"
        description="For analyzing market sentiment from various sources"
        currentModelId={userSelections?.aiModels.sentimentAnalysis || 'gpt-4-standard'}
        models={mockModels}
        onModelChange={(modelId) => handleModelChange('sentimentAnalysis', modelId)}
        capability="sentimentAnalysis"
      />
      
      <ModelSelector
        title="Technical Pattern Recognition"
        description="For identifying technical chart patterns and signals"
        currentModelId={userSelections?.aiModels.patternRecognition || 'dbrx-standard'}
        models={mockModels}
        onModelChange={(modelId) => handleModelChange('patternRecognition', modelId)}
        capability="patternRecognition"
      />
      
      <ModelSelector
        title="Fundamental Data Interpretation"
        description="For analyzing fundamental financial data and reports"
        currentModelId={userSelections?.aiModels.fundamentalAnalysis || 'claude-3-sonnet'}
        models={mockModels}
        onModelChange={(modelId) => handleModelChange('fundamentalAnalysis', modelId)}
        capability="fundamentalAnalysis"
      />
    </div>
  );

  const renderDecisionModeSection = () => (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-white mb-4">Decision Mode Configuration</h2>
      <p className="text-gray-400 mb-6">
        Explicitly choose how AI outputs are treated. Each mode shows clear definitions and risk indicators.
      </p>
      
      <DecisionModeSelector
        currentMode={userSelections?.decisionMode || DecisionAuthorityLevel.OBSERVATION_ONLY}
        modes={mockDecisionModes}
        onModeChange={handleDecisionModeChange}
      />
    </div>
  );

  const renderProfileSelectionSection = () => (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-white mb-4">Behavioral Profile Selection</h2>
      <p className="text-gray-400 mb-6">
        Select behavioral profiles that define your information processing approach and risk posture.
      </p>
      
      <ProfileSelector
        profiles={mockProfiles}
        selectedProfiles={userSelections?.activeProfiles || []}
        onProfileToggle={handleProfileToggle}
      />
    </div>
  );

  const renderCapabilityToggleSection = () => (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-white mb-4">Capability Toggle System</h2>
      <p className="text-gray-400 mb-6">
        Enable or disable platform capabilities based on your needs and risk tolerance.
      </p>
      
      <div className="mb-4">
        <input
          type="text"
          placeholder="Search capabilities..."
          className="w-full max-w-md px-4 py-2 bg-[#0f0f0f] border border-[#262626] rounded-lg text-white"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
      </div>
      
      <div className="space-y-3">
        {filteredCapabilities.map(cap => (
          <CapabilityToggle
            key={cap.id}
            capability={cap}
            isEnabled={userSelections?.enabledCapabilities.includes(cap.id) || false}
            onToggle={(enabled) => handleCapabilityToggle(cap.id, enabled)}
          />
        ))}
      </div>
    </div>
  );

  const renderFutureModulesSection = () => (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-white mb-4">Future Modules Opt-In</h2>
      <p className="text-gray-400 mb-6">
        Preview upcoming features and experimental modules. Opt-in explicitly for access.
      </p>
      
      <div className="space-y-4">
        {mockFutureModules.map(module => (
          <FutureModuleToggle
            key={module.id}
            module={module}
            isOptedIn={userSelections?.optedInModules.includes(module.id) || false}
            onToggle={(optedIn) => handleFutureModuleToggle(module.id, optedIn)}
          />
        ))}
      </div>
    </div>
  );

  const renderAuditLogSection = () => (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-white mb-4">Audit & Change Log</h2>
      <p className="text-gray-400 mb-6">
        View configuration changes for transparency and compliance documentation.
      </p>
      
      <AuditLogTable logs={mockAuditLogs} />
    </div>
  );

  const renderPresetsSection = () => (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-white mb-4">Configuration Presets</h2>
      <p className="text-gray-400 mb-6">
        Apply predefined configuration bundles designed for specific use cases.
      </p>
      
      <PresetSelector
        presets={mockPresets}
        onApplyPreset={handleApplyPreset}
      />
    </div>
  );

  const renderRiskSummaryPanel = () => (
    <div className="fixed right-4 top-24 w-80 bg-[#0f0f0f] border border-[#262626] rounded-lg p-4">
      <h3 className="font-semibold text-white mb-3">Risk & Compliance Summary</h3>
      
      <div className="space-y-3">
        <div>
          <div className="flex justify-between text-sm mb-1">
            <span className="text-gray-400">Overall Risk Level</span>
            <span className={`font-medium ${
              mockRiskSummary.overallRiskLevel === RiskLevel.LOW ? 'text-green-400' :
              mockRiskSummary.overallRiskLevel === RiskLevel.MEDIUM ? 'text-yellow-400' :
              mockRiskSummary.overallRiskLevel === RiskLevel.HIGH ? 'text-orange-400' : 'text-red-400'
            }`}>
              {mockRiskSummary.overallRiskLevel.toUpperCase()}
            </span>
          </div>
          <div className="w-full bg-gray-700 rounded-full h-2">
            <div 
              className={`h-2 rounded-full ${
                mockRiskSummary.overallRiskLevel === RiskLevel.LOW ? 'bg-green-500 w-1/4' :
                mockRiskSummary.overallRiskLevel === RiskLevel.MEDIUM ? 'bg-yellow-500 w-2/4' :
                mockRiskSummary.overallRiskLevel === RiskLevel.HIGH ? 'bg-orange-500 w-3/4' : 'bg-red-500 w-full'
              }`}
            ></div>
          </div>
        </div>
        
        <div className="pt-2 border-t border-[#262626]">
          <h4 className="text-sm font-medium text-gray-400 mb-2">Active High-Risk Configurations</h4>
          <div className="space-y-1">
            {mockRiskSummary.activeHighRiskConfigs.map((config, idx) => (
              <div key={idx} className="text-xs text-red-400 truncate">{config}</div>
            ))}
          </div>
        </div>
        
        <div className="pt-2 border-t border-[#262626]">
          <div className="flex justify-between text-sm">
            <span className="text-gray-400">Compliance Status</span>
            <span className="text-green-400">{mockRiskSummary.complianceStatus}</span>
          </div>
          
          <div className="flex justify-between text-sm mt-1">
            <span className="text-gray-400">Required Actions</span>
            <span className="text-orange-400">{mockRiskSummary.requiredActionsCount}</span>
          </div>
          
          <div className="flex justify-between text-sm mt-1">
            <span className="text-gray-400">Last Review</span>
            <span className="text-gray-400">{mockRiskSummary.lastSecurityReview.toLocaleDateString()}</span>
          </div>
        </div>
      </div>
    </div>
  );

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto p-6">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-700 rounded w-1/4 mb-8"></div>
          <div className="h-4 bg-gray-700 rounded w-3/4 mb-4"></div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {[1, 2, 3].map(i => (
              <div key={i} className="h-32 bg-gray-700 rounded"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto p-6 relative">
      {/* Fixed Header */}
      <div className="fixed top-16 left-0 right-0 bg-[#0a0a0a] border-b border-[#1f1f1f] z-10">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <h1 className="text-2xl font-bold text-white">AI & Capability Selection Control</h1>
          <p className="text-gray-400">Configure AI models, decision modes, and platform capabilities</p>
        </div>
      </div>
      
      {/* Main Content */}
      <div className="pt-24">
        {/* Tabs */}
        <div className="flex flex-wrap gap-2 mb-6 border-b border-[#262626] pb-4">
          {[
            { id: 'models', label: 'AI Models' },
            { id: 'modes', label: 'Decision Modes' },
            { id: 'profiles', label: 'Behavioral Profiles' },
            { id: 'capabilities', label: 'Capabilities' },
            { id: 'future', label: 'Future Modules' },
            { id: 'presets', label: 'Presets' },
            { id: 'audit', label: 'Audit Log' },
          ].map(tab => (
            <button
              key={tab.id}
              className={`px-4 py-2 rounded-t-lg ${
                activeTab === tab.id
                  ? 'bg-[#1f1f1f] text-white border-b-2 border-blue-500'
                  : 'text-gray-400 hover:text-white'
              }`}
              onClick={() => setActiveTab(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </div>
        
        {/* Tab Content */}
        <div className="bg-[#0a0a0a] min-h-screen">
          {activeTab === 'models' && renderModelSelectionSection()}
          {activeTab === 'modes' && renderDecisionModeSection()}
          {activeTab === 'profiles' && renderProfileSelectionSection()}
          {activeTab === 'capabilities' && renderCapabilityToggleSection()}
          {activeTab === 'future' && renderFutureModulesSection()}
          {activeTab === 'presets' && renderPresetsSection()}
          {activeTab === 'audit' && renderAuditLogSection()}
        </div>
      </div>
      
      {/* Risk Summary Panel */}
      {renderRiskSummaryPanel()}
      
      {/* Fixed Footer */}
      <div className="fixed bottom-0 left-0 right-0 bg-[#0a0a0a] border-t border-[#1f1f1f] z-10">
        <div className="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
          <div className="text-sm text-gray-400">
            {lastSaved ? `Last saved: ${lastSaved.toLocaleTimeString()}` : 'Unsaved changes'}
          </div>
          <div className="flex items-center space-x-4">
            {unsavedChanges && (
              <span className="text-yellow-400 text-sm">Unsaved changes</span>
            )}
            <button
              onClick={handleSaveChanges}
              className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
              Save Changes
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SelectionPage;
