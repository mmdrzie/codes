import { z } from 'zod';

// Model types
export enum ModelCostTier {
  STANDARD = 'standard',
  PREMIUM = 'premium',
  ENTERPRISE = 'enterprise'
}

export enum ModelLatencyClass {
  FAST = 'fast',
  BALANCED = 'balanced',
  DEEP = 'deep'
}

export enum ModelStatus {
  ACTIVE = 'active',
  DEPRECATED = 'deprecated',
  BETA = 'beta'
}

export interface AIModel {
  id: string;
  name: string;
  description: string;
  contextWindowSize: number;
  costTier: ModelCostTier;
  latencyClass: ModelLatencyClass;
  status: ModelStatus;
  capabilities: string[];
  fallbackModelId?: string;
  version: string;
}

// Decision mode types
export enum DecisionAuthorityLevel {
  OBSERVATION_ONLY = 'observation_only',
  ADVISORY = 'advisory',
  ASSISTED_EXECUTION = 'assisted_execution',
  AUTOMATED_EXECUTION = 'automated_execution'
}

export interface DecisionMode {
  id: DecisionAuthorityLevel;
  name: string;
  description: string;
  riskLevel: number; // 1-5 scale
  requiresAuthentication: boolean;
  requiresConfirmation: boolean;
  prerequisites: string[];
  auditTrailRequired: boolean;
}

// Profile types
export interface ProfileCharacteristic {
  informationProcessing: string;
  alertSensitivity: string;
  dataDepthPreference: string;
  updateFrequency: string;
  computationIntensity: string;
}

export interface BehavioralProfile {
  id: string;
  name: string;
  description: string;
  characteristics: ProfileCharacteristic;
  flags: string[]; // Internal configuration flags
}

// Capability types
export enum RiskLevel {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

export enum ResourceImpact {
  MINIMAL = 'minimal',
  MODERATE = 'moderate',
  HIGH = 'high',
  EXTREME = 'extreme'
}

export interface Capability {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  riskLevel: RiskLevel;
  resourceImpact: ResourceImpact;
  dependencies: string[];
  dataRequirements: string[];
  complianceTags: string[];
  isBeta: boolean;
  isLocked: boolean;
  lastUpdated: Date;
}

// Future module types
export interface FutureModule {
  id: string;
  name: string;
  description: string;
  plannedRelease: string; // Q1 2025, etc.
  prerequisites: string[];
  riskDisclosure: string;
  dataCollectionNotice: string;
  revocationRights: string;
  waitlistStatus?: string;
  isOptedIn: boolean;
}

// Audit log types
export enum ChangeType {
  MODEL = 'model',
  MODE = 'mode',
  CAPABILITY = 'capability',
  PROFILE = 'profile',
  FUTURE_MODULE = 'future_module',
  PRESET = 'preset'
}

export interface AuditEntry {
  timestamp: Date;
  changeType: ChangeType;
  previousValue: any;
  newValue: any;
  ipAddress: string;
  sessionId: string;
  changeReason?: string;
}

// Configuration preset types
export interface ConfigurationPreset {
  id: string;
  name: string;
  description: string;
  targetAudience: string;
  riskLevel: RiskLevel;
  resourceImpact: ResourceImpact;
  changes: {
    models: Record<string, string>;
    modes: Record<string, string>;
    capabilities: Record<string, boolean>;
    profiles: string[];
  };
}

// User selection configuration
export interface UserSelections {
  id: string;
  userId: string;
  aiModels: Record<string, string>; // capability -> modelId mapping
  decisionMode: DecisionAuthorityLevel;
  activeProfiles: string[];
  enabledCapabilities: string[];
  optedInModules: string[];
  configurationVersion: string;
  createdAt: Date;
  updatedAt: Date;
  hash: string; // For integrity verification
}

// Risk summary types
export interface RiskSummary {
  overallRiskLevel: RiskLevel;
  activeHighRiskConfigs: string[];
  complianceStatus: string;
  requiredActionsCount: number;
  lastSecurityReview: Date;
}

// Form validation schemas
export const ModelSelectionSchema = z.object({
  capability: z.string(),
  modelId: z.string(),
});

export const DecisionModeSchema = z.object({
  modeId: z.nativeEnum(DecisionAuthorityLevel),
  requiresAuth: z.boolean().optional(),
});

export const CapabilityToggleSchema = z.object({
  capabilityId: z.string(),
  enabled: z.boolean(),
});

export const ProfileSelectionSchema = z.object({
  profileIds: z.array(z.string()),
});