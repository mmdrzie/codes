import React from 'react';
import { ChatState } from '../types';

interface ChatStatusProps {
  state: ChatState;
  error: string | null;
}

export default function ChatStatus({ state, error }: ChatStatusProps) {
  if (state === 'idle') return null;

  let statusText = '';
  let statusColor = '';

  switch (state) {
    case 'thinking':
      statusText = 'Thinking...';
      statusColor = 'text-blue-400';
      break;
    case 'streaming':
      statusText = 'Generating response...';
      statusColor = 'text-purple-400';
      break;
    case 'error':
      statusText = error || 'An error occurred';
      statusColor = 'text-red-400';
      break;
    default:
      return null;
  }

  return (
    <div className={`text-sm flex items-center px-4 py-2 ${statusColor}`}>
      <span className="mr-2">{statusText}</span>
      {state !== 'error' && (
        <div className="flex space-x-1">
          <div className="w-2 h-2 bg-current rounded-full animate-bounce"></div>
          <div className="w-2 h-2 bg-current rounded-full animate-bounce delay-75"></div>
          <div className="w-2 h-2 bg-current rounded-full animate-bounce delay-150"></div>
        </div>
      )}
    </div>
  );
}