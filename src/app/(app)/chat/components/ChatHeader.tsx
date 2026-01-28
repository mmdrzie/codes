import React from 'react';
import ModelSelector from './ModelSelector';
import ConversationMetadata from './ConversationMetadata';
import { ModelConfig } from '../types';

interface ChatHeaderProps {
  model: string;
  modelConfigs: ModelConfig[];
  onModelChange: (modelId: string) => void;
}

export default function ChatHeader({ model, modelConfigs, onModelChange }: ChatHeaderProps) {
  return (
    <header className="border-b border-gray-800 pb-4 mb-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">AI Chat</h1>
          <p className="text-sm text-gray-400 mt-1">Secure AI-powered trading analysis and insights</p>
        </div>
        
        <div className="flex flex-col sm:flex-row gap-3">
          <ModelSelector 
            currentModel={model} 
            modelConfigs={modelConfigs} 
            onModelChange={onModelChange} 
          />
          <ConversationMetadata model={model} modelConfigs={modelConfigs} />
        </div>
      </div>
    </header>
  );
}