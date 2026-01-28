import React from 'react';
import { ModelConfig } from '../types';

interface ModelSelectorProps {
  currentModel: string;
  modelConfigs: ModelConfig[];
  onModelChange: (modelId: string) => void;
}

export default function ModelSelector({ currentModel, modelConfigs, onModelChange }: ModelSelectorProps) {
  const availableModels = modelConfigs.filter(model => model.available);
  
  return (
    <div className="relative">
      <select
        value={currentModel}
        onChange={(e) => onModelChange(e.target.value)}
        className="bg-gray-900 border border-gray-700 rounded-lg py-2 px-3 pr-8 text-white focus:outline-none focus:ring-2 focus:ring-blue-500 appearance-none"
      >
        {availableModels.map((model) => (
          <option key={model.id} value={model.id}>
            {model.name}
          </option>
        ))}
      </select>
      <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-gray-400">
        <svg className="fill-current h-4 w-4" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20">
          <path d="M9.293 12.95l.707.707L15.657 8l-1.414-1.414L10 10.828 5.757 6.586 4.343 8z" />
        </svg>
      </div>
    </div>
  );
}