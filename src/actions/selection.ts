'use server';

import { revalidatePath } from 'next/cache';
import { cookies } from 'next/headers';
import { z } from 'zod';
import { auth } from '@/auth';
import { UserSelections, ChangeType, AuditEntry } from '@/types/selection';

// Validation schemas
const UpdateModelSelectionSchema = z.object({
  capability: z.string(),
  modelId: z.string(),
});

const UpdateDecisionModeSchema = z.object({
  modeId: z.enum(['observation_only', 'advisory', 'assisted_execution', 'automated_execution']),
});

const UpdateCapabilitySchema = z.object({
  capabilityId: z.string(),
  enabled: z.boolean(),
});

const UpdateProfileSchema = z.object({
  profileIds: z.array(z.string()),
});

const UpdateFutureModuleSchema = z.object({
  moduleId: z.string(),
  optedIn: z.boolean(),
});

// Mock data store - in production this would connect to a database
let userSelections: Record<string, UserSelections> = {};
let auditLogs: AuditEntry[] = [];

// Initialize default selections for a user
export async function initializeUserSelections(userId: string): Promise<UserSelections> {
  const session = await auth();
  if (!session || session.user?.id !== userId) {
    throw new Error('Unauthorized');
  }

  const defaultSelections: UserSelections = {
    id: `sel_${Date.now()}`,
    userId,
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
    hash: 'initial_hash_' + Date.now(),
  };

  userSelections[userId] = defaultSelections;

  // Log initialization
  const auditEntry: AuditEntry = {
    timestamp: new Date(),
    changeType: ChangeType.PRESET,
    previousValue: null,
    newValue: defaultSelections,
    ipAddress: getIpAddress(),
    sessionId: session.user.id,
  };
  auditLogs.push(auditEntry);

  return defaultSelections;
}

// Get current user selections
export async function getUserSelections(userId: string): Promise<UserSelections | null> {
  const session = await auth();
  if (!session || session.user?.id !== userId) {
    throw new Error('Unauthorized');
  }

  return userSelections[userId] || null;
}

// Update model selection for a specific capability
export async function updateModelSelection(
  userId: string,
  capability: string,
  modelId: string
): Promise<{ success: boolean; error?: string }> {
  try {
    const session = await auth();
    if (!session || session.user?.id !== userId) {
      return { success: false, error: 'Unauthorized' };
    }

    // Validate inputs
    const validated = UpdateModelSelectionSchema.parse({ capability, modelId });

    // Check if user has existing selections
    const currentSelections = userSelections[userId];
    if (!currentSelections) {
      await initializeUserSelections(userId);
    }

    // Store previous value for audit
    const previousValue = { ...userSelections[userId].aiModels };
    
    // Update the selection
    userSelections[userId] = {
      ...userSelections[userId],
      aiModels: {
        ...userSelections[userId].aiModels,
        [validated.capability]: validated.modelId,
      },
      updatedAt: new Date(),
    };

    // Log the change
    const auditEntry: AuditEntry = {
      timestamp: new Date(),
      changeType: ChangeType.MODEL,
      previousValue: { [validated.capability]: previousValue[validated.capability] },
      newValue: { [validated.capability]: validated.modelId },
      ipAddress: getIpAddress(),
      sessionId: session.user.id,
    };
    auditLogs.push(auditEntry);

    // Revalidate cache
    revalidatePath('/selection');

    return { success: true };
  } catch (error) {
    console.error('Error updating model selection:', error);
    if (error instanceof z.ZodError) {
      return { success: false, error: 'Invalid input data' };
    }
    return { success: false, error: 'Failed to update model selection' };
  }
}

// Update decision mode
export async function updateDecisionMode(
  userId: string,
  modeId: string
): Promise<{ success: boolean; error?: string }> {
  try {
    const session = await auth();
    if (!session || session.user?.id !== userId) {
      return { success: false, error: 'Unauthorized' };
    }

    // Validate input
    const validated = UpdateDecisionModeSchema.parse({ modeId });

    // Check if user has existing selections
    const currentSelections = userSelections[userId];
    if (!currentSelections) {
      await initializeUserSelections(userId);
    }

    // Store previous value for audit
    const previousValue = userSelections[userId].decisionMode;
    
    // Update the selection
    userSelections[userId] = {
      ...userSelections[userId],
      decisionMode: validated.modeId,
      updatedAt: new Date(),
    };

    // Log the change
    const auditEntry: AuditEntry = {
      timestamp: new Date(),
      changeType: ChangeType.MODE,
      previousValue,
      newValue: validated.modeId,
      ipAddress: getIpAddress(),
      sessionId: session.user.id,
    };
    auditLogs.push(auditEntry);

    // Revalidate cache
    revalidatePath('/selection');

    return { success: true };
  } catch (error) {
    console.error('Error updating decision mode:', error);
    if (error instanceof z.ZodError) {
      return { success: false, error: 'Invalid input data' };
    }
    return { success: false, error: 'Failed to update decision mode' };
  }
}

// Update capability toggle
export async function updateCapability(
  userId: string,
  capabilityId: string,
  enabled: boolean
): Promise<{ success: boolean; error?: string }> {
  try {
    const session = await auth();
    if (!session || session.user?.id !== userId) {
      return { success: false, error: 'Unauthorized' };
    }

    // Validate input
    const validated = UpdateCapabilitySchema.parse({ capabilityId, enabled });

    // Check if user has existing selections
    const currentSelections = userSelections[userId];
    if (!currentSelections) {
      await initializeUserSelections(userId);
    }

    // Store previous value for audit
    const wasEnabled = userSelections[userId].enabledCapabilities.includes(validated.capabilityId);
    
    // Update the selection
    let newCapabilities = [...userSelections[userId].enabledCapabilities];
    if (validated.enabled && !wasEnabled) {
      newCapabilities.push(validated.capabilityId);
    } else if (!validated.enabled && wasEnabled) {
      newCapabilities = newCapabilities.filter(id => id !== validated.capabilityId);
    }

    userSelections[userId] = {
      ...userSelections[userId],
      enabledCapabilities: newCapabilities,
      updatedAt: new Date(),
    };

    // Log the change
    const auditEntry: AuditEntry = {
      timestamp: new Date(),
      changeType: ChangeType.CAPABILITY,
      previousValue: wasEnabled,
      newValue: validated.enabled,
      ipAddress: getIpAddress(),
      sessionId: session.user.id,
    };
    auditLogs.push(auditEntry);

    // Revalidate cache
    revalidatePath('/selection');

    return { success: true };
  } catch (error) {
    console.error('Error updating capability:', error);
    if (error instanceof z.ZodError) {
      return { success: false, error: 'Invalid input data' };
    }
    return { success: false, error: 'Failed to update capability' };
  }
}

// Update profile selection
export async function updateProfileSelection(
  userId: string,
  profileIds: string[]
): Promise<{ success: boolean; error?: string }> {
  try {
    const session = await auth();
    if (!session || session.user?.id !== userId) {
      return { success: false, error: 'Unauthorized' };
    }

    // Validate input
    const validated = UpdateProfileSchema.parse({ profileIds });

    // Check if user has existing selections
    const currentSelections = userSelections[userId];
    if (!currentSelections) {
      await initializeUserSelections(userId);
    }

    // Store previous value for audit
    const previousValue = [...userSelections[userId].activeProfiles];
    
    // Update the selection
    userSelections[userId] = {
      ...userSelections[userId],
      activeProfiles: validated.profileIds,
      updatedAt: new Date(),
    };

    // Log the change
    const auditEntry: AuditEntry = {
      timestamp: new Date(),
      changeType: ChangeType.PROFILE,
      previousValue,
      newValue: validated.profileIds,
      ipAddress: getIpAddress(),
      sessionId: session.user.id,
    };
    auditLogs.push(auditEntry);

    // Revalidate cache
    revalidatePath('/selection');

    return { success: true };
  } catch (error) {
    console.error('Error updating profile selection:', error);
    if (error instanceof z.ZodError) {
      return { success: false, error: 'Invalid input data' };
    }
    return { success: false, error: 'Failed to update profile selection' };
  }
}

// Update future module opt-in
export async function updateFutureModuleOptIn(
  userId: string,
  moduleId: string,
  optedIn: boolean
): Promise<{ success: boolean; error?: string }> {
  try {
    const session = await auth();
    if (!session || session.user?.id !== userId) {
      return { success: false, error: 'Unauthorized' };
    }

    // Validate input
    const validated = UpdateFutureModuleSchema.parse({ moduleId, optedIn });

    // Check if user has existing selections
    const currentSelections = userSelections[userId];
    if (!currentSelections) {
      await initializeUserSelections(userId);
    }

    // Store previous value for audit
    const wasOptedIn = userSelections[userId].optedInModules.includes(validated.moduleId);
    
    // Update the selection
    let newOptedInModules = [...userSelections[userId].optedInModules];
    if (validated.optedIn && !wasOptedIn) {
      newOptedInModules.push(validated.moduleId);
    } else if (!validated.optedIn && wasOptedIn) {
      newOptedInModules = newOptedInModules.filter(id => id !== validated.moduleId);
    }

    userSelections[userId] = {
      ...userSelections[userId],
      optedInModules: newOptedInModules,
      updatedAt: new Date(),
    };

    // Log the change
    const auditEntry: AuditEntry = {
      timestamp: new Date(),
      changeType: ChangeType.FUTURE_MODULE,
      previousValue: wasOptedIn,
      newValue: validated.optedIn,
      ipAddress: getIpAddress(),
      sessionId: session.user.id,
    };
    auditLogs.push(auditEntry);

    // Revalidate cache
    revalidatePath('/selection');

    return { success: true };
  } catch (error) {
    console.error('Error updating future module opt-in:', error);
    if (error instanceof z.ZodError) {
      return { success: false, error: 'Invalid input data' };
    }
    return { success: false, error: 'Failed to update future module opt-in' };
  }
}

// Get audit logs for a user
export async function getUserAuditLogs(userId: string): Promise<AuditEntry[]> {
  const session = await auth();
  if (!session || session.user?.id !== userId) {
    throw new Error('Unauthorized');
  }

  // Return last 50 logs, filtered by user if needed
  return auditLogs.slice(-50).reverse(); // Most recent first
}

// Apply a configuration preset
export async function applyPreset(
  userId: string,
  presetId: string
): Promise<{ success: boolean; error?: string }> {
  try {
    const session = await auth();
    if (!session || session.user?.id !== userId) {
      return { success: false, error: 'Unauthorized' };
    }

    // Define presets
    const presets: Record<string, any> = {
      'default-safe-mode': {
        aiModels: {
          marketAnalysis: 'claude-3-haiku',
          riskEvaluation: 'claude-3-haiku',
          newsInterpretation: 'gpt-4-standard',
        },
        decisionMode: 'observation_only',
        activeProfiles: ['conservative', 'compliance-first'],
        enabledCapabilities: [
          'news-aware-analysis',
          'historical-pattern-matching',
          'macro-event-tracking',
        ],
      },
      'research-analysis-mode': {
        aiModels: {
          marketAnalysis: 'gpt-4-turbo',
          riskEvaluation: 'claude-3-sonnet',
          scenarioAnalysis: 'claude-3-opus',
        },
        decisionMode: 'advisory',
        activeProfiles: ['exploratory', 'data-intensive'],
        enabledCapabilities: [
          'multi-model-consensus',
          'scenario-simulation',
          'real-time-alert-system',
          'historical-pattern-matching',
          'cross-asset-correlation',
          'portfolio-stress-testing',
        ],
      },
      'active-trading-mode': {
        aiModels: {
          marketAnalysis: 'gpt-4-turbo',
          riskEvaluation: 'claude-3-sonnet',
          technicalPattern: 'dbrx-standard',
        },
        decisionMode: 'advisory',
        activeProfiles: ['balanced', 'latency-sensitive'],
        enabledCapabilities: [
          'news-aware-analysis',
          'multi-model-consensus',
          'real-time-alert-system',
          'cross-asset-correlation',
          'liquidity-analysis',
          'volatility-regime-detection',
        ],
      },
      'compliance-audit-mode': {
        aiModels: {
          riskEvaluation: 'claude-3-sonnet',
          newsInterpretation: 'gpt-4-standard',
        },
        decisionMode: 'observation_only',
        activeProfiles: ['compliance-first', 'risk-aware'],
        enabledCapabilities: [
          'portfolio-stress-testing',
          'sentiment-drift-detection',
          'macro-event-tracking',
        ],
      },
    };

    const preset = presets[presetId];
    if (!preset) {
      return { success: false, error: 'Preset not found' };
    }

    // Check if user has existing selections
    const currentSelections = userSelections[userId];
    if (!currentSelections) {
      await initializeUserSelections(userId);
    }

    // Store previous values for audit
    const previousValue = {
      aiModels: { ...userSelections[userId].aiModels },
      decisionMode: userSelections[userId].decisionMode,
      activeProfiles: [...userSelections[userId].activeProfiles],
      enabledCapabilities: [...userSelections[userId].enabledCapabilities],
    };

    // Apply preset
    userSelections[userId] = {
      ...userSelections[userId],
      aiModels: { ...userSelections[userId].aiModels, ...preset.aiModels },
      decisionMode: preset.decisionMode,
      activeProfiles: preset.activeProfiles,
      enabledCapabilities: preset.enabledCapabilities,
      updatedAt: new Date(),
    };

    // Log the change
    const auditEntry: AuditEntry = {
      timestamp: new Date(),
      changeType: ChangeType.PRESET,
      previousValue,
      newValue: preset,
      ipAddress: getIpAddress(),
      sessionId: session.user.id,
    };
    auditLogs.push(auditEntry);

    // Revalidate cache
    revalidatePath('/selection');

    return { success: true };
  } catch (error) {
    console.error('Error applying preset:', error);
    return { success: false, error: 'Failed to apply preset' };
  }
}

// Helper function to get IP address
function getIpAddress(): string {
  // In a real implementation, this would extract the IP from headers
  return '192.168.1.1'; // Placeholder
}