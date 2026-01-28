import React from 'react';
import { ModelConfig } from '../types';

interface ConversationMetadataProps {
  model: string;
  modelConfigs: ModelConfig[];
}

export default function ConversationMetadata({ model, modelConfigs }: ConversationMetadataProps) {
  const modelConfig = modelConfigs.find(config => config.id === model);
  
  if (!modelConfig) return null;
  
  return (
    <div className="bg-gray-900 border border-gray-700 rounded-lg py-2 px-3 text-sm">
      <div className="text-gray-300">
        <span className="font-medium">{modelConfig.name}</span>
        <span className="mx-2">•</span>
        <span>{modelConfig.context_window.toLocaleString()} tokens</span>
        {modelConfig.cost_per_token && (
          <>
            <span className="mx-2">•</span>
            <span>${modelConfig.cost_per_token}/token</span>
          </>
        )}
      </div>
    </div>
  );
}