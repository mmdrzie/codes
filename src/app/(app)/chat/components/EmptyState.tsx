import React from 'react';
import { ModelConfig } from '../types';

interface EmptyStateProps {
  onModelSelect: (modelId: string) => void;
  modelConfigs: ModelConfig[];
}

export default function EmptyState({ onModelSelect, modelConfigs }: EmptyStateProps) {
  const availableModels = modelConfigs.filter(model => model.available);
  
  return (
    <div className="flex flex-col items-center justify-center h-full py-12">
      <div className="text-center max-w-lg">
        <h2 className="text-2xl font-bold text-white mb-4">Start a new conversation</h2>
        <p className="text-gray-400 mb-8">
          Choose a model and begin chatting with our AI assistant for trading insights and analysis.
        </p>
        
        <div className="mb-8">
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Select AI Model
          </label>
          <select
            onChange={(e) => onModelSelect(e.target.value)}
            className="w-full max-w-xs bg-gray-900 border border-gray-700 rounded-lg py-2 px-3 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            {availableModels.map((model) => (
              <option key={model.id} value={model.id}>
                {model.name}
              </option>
            ))}
          </select>
        </div>
        
        <div className="space-y-3 text-left bg-gray-900/50 border border-gray-800 rounded-lg p-4">
          <h3 className="font-medium text-white">Try asking:</h3>
          <ul className="space-y-2 text-gray-300">
            <li className="flex items-start">
              <span className="text-blue-400 mr-2">•</span>
              <span>"What are today's market trends?"</span>
            </li>
            <li className="flex items-start">
              <span className="text-blue-400 mr-2">•</span>
              <span>"Analyze this trading strategy: [your strategy]"</span>
            </li>
            <li className="flex items-start">
              <span className="text-blue-400 mr-2">•</span>
              <span>"Explain the impact of recent economic events"</span>
            </li>
            <li className="flex items-start">
              <span className="text-blue-400 mr-2">•</span>
              <span>"Risk assessment for portfolio diversification"</span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
}