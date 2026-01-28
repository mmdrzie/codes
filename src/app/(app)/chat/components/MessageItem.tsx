import React from 'react';
import MessageContent from './MessageContent';
import MessageActions from './MessageActions';
import { Message } from '../types';

interface MessageItemProps {
  message: Message;
}

export default function MessageItem({ message }: MessageItemProps) {
  const isUser = message.role === 'user';
  const isAssistant = message.role === 'assistant';
  const isSystem = message.role === 'system';
  
  let roleLabel = message.role.charAt(0).toUpperCase() + message.role.slice(1);
  if (message.role === 'assistant') roleLabel = 'AI Assistant';
  else if (message.role === 'user') roleLabel = 'You';
  
  return (
    <div className={`flex ${isUser ? 'justify-end' : 'justify-start'}`}>
      <div className={`max-w-[90%] w-full ${isUser ? 'order-2' : 'order-1'} group`}>
        <div className="mb-1 flex items-center">
          <span className={`text-xs font-medium ${
            isUser ? 'text-blue-400' : 
            isAssistant ? 'text-green-400' : 
            'text-yellow-400'
          }`}>
            {roleLabel}
          </span>
          {message.metadata?.tokens && (
            <span className="ml-2 text-xs text-gray-500">
              {message.metadata.tokens} tokens
            </span>
          )}
        </div>
        
        <div 
          className={`rounded-xl p-4 relative ${
            isUser 
              ? 'bg-blue-900/20 border border-blue-800/50' 
              : isSystem
                ? 'bg-yellow-900/20 border border-yellow-800/50'
                : 'bg-gray-800/50 border border-gray-700/50'
          }`}
        >
          <MessageContent content={message.content} />
          <MessageActions messageId={message.id} content={message.content} />
        </div>
      </div>
    </div>
  );
}