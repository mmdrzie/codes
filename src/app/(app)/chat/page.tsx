'use client';

import { useState, useEffect, useRef } from 'react';
import { useSession } from 'next-auth/react';
import { Message, Conversation, ModelConfig, ChatState } from './types';
import ChatContainer from './components/ChatContainer';
import ChatHeader from './components/ChatHeader';
import MessageList from './components/MessageList';
import ChatInput from './components/ChatInput';
import ChatStatus from './components/ChatStatus';
import EmptyState from './components/EmptyState';

// Generate UUID using crypto API
const generateUUID = (): string => {
  if (typeof window !== 'undefined' && window.crypto) {
    return crypto.randomUUID ? crypto.randomUUID() : Date.now().toString();
  }
  return Date.now().toString();
};

// Define model configurations
const MODEL_CONFIGS: ModelConfig[] = [
  {
    id: 'default',
    name: 'GPT-4 Turbo',
    provider: 'OpenAI',
    context_window: 128000,
    cost_per_token: 0.00001,
    available: true,
  },
  {
    id: 'advanced',
    name: 'GPT-4o',
    provider: 'OpenAI',
    context_window: 128000,
    cost_per_token: 0.00002,
    available: true,
  },
  {
    id: 'fast',
    name: 'GPT-3.5 Turbo',
    provider: 'OpenAI',
    context_window: 16385,
    cost_per_token: 0.000005,
    available: true,
  },
  {
    id: 'experimental',
    name: 'Claude 3.5 Sonnet',
    provider: 'Anthropic',
    context_window: 200000,
    cost_per_token: 0.00003,
    available: false,
    requires_role: ['admin', 'premium'],
  },
];

export default function ChatPage() {
  const { data: session, status } = useSession();
  const [conversation, setConversation] = useState<Conversation>({
    id: generateUUID(),
    title: 'New Conversation',
    messages: [],
    model: 'default',
    created_at: new Date(),
    updated_at: new Date(),
    metadata: {
      total_tokens: 0,
      total_cost: 0,
      message_count: 0,
    },
  });
  const [inputValue, setInputValue] = useState('');
  const [chatState, setChatState] = useState<ChatState>('idle');
  const [error, setError] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Scroll to bottom when messages change
  useEffect(() => {
    scrollToBottom();
  }, [conversation.messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const handleSendMessage = async () => {
    if (!inputValue.trim() || chatState !== 'idle') return;

    const userMessage: Message = {
      id: generateUUID(),
      role: 'user',
      content: inputValue.trim(),
      timestamp: new Date(),
    };

    // Add user message optimistically
    const newMessages = [...conversation.messages, userMessage];
    setConversation(prev => ({
      ...prev,
      messages: newMessages,
      updated_at: new Date(),
    }));

    setInputValue('');
    setChatState('thinking');
    setError(null);

    try {
      // Make API call to backend
      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${session?.accessToken}`,
        },
        body: JSON.stringify({
          conversation_id: conversation.id,
          model: conversation.model,
          messages: newMessages,
          stream: true,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error_message || 'Failed to get response from AI');
      }

      // Handle streaming response
      const reader = response.body?.getReader();
      if (!reader) {
        throw new Error('No response body');
      }

      const decoder = new TextDecoder();
      let assistantMessage: Message = {
        id: generateUUID(),
        role: 'assistant',
        content: '',
        timestamp: new Date(),
      };

      setChatState('streaming');

      // Read stream
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value);
        const lines = chunk.split('\n');

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const data = line.slice(6);
            if (data === '[DONE]') {
              break;
            }
            
            try {
              const parsed = JSON.parse(data);
              if (parsed.content) {
                assistantMessage.content += parsed.content;
                
                // Update message in state
                setConversation(prev => ({
                  ...prev,
                  messages: prev.messages.map(msg => 
                    msg.id === assistantMessage.id ? assistantMessage : msg
                  ),
                }));
              }
            } catch (e) {
              console.error('Error parsing SSE data:', e);
            }
          }
        }
      }

      // Add assistant message to conversation
      setConversation(prev => ({
        ...prev,
        messages: [...prev.messages, assistantMessage],
        updated_at: new Date(),
        metadata: {
          ...prev.metadata,
          message_count: prev.metadata.message_count + 1,
        },
      }));

      setChatState('idle');
    } catch (err) {
      console.error('Error sending message:', err);
      setError(err instanceof Error ? err.message : 'An unknown error occurred');
      setChatState('error');
    }
  };

  const handleModelChange = (modelId: string) => {
    const model = MODEL_CONFIGS.find(m => m.id === modelId);
    if (model && model.available) {
      setConversation(prev => ({
        ...prev,
        model: modelId,
      }));
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  if (status === 'loading') {
    return (
      <div className="flex items-center justify-center h-screen bg-black">
        <div className="text-white">Loading...</div>
      </div>
    );
  }

  if (!session) {
    return (
      <div className="flex items-center justify-center h-screen bg-black">
        <div className="text-white">Access denied. Please sign in.</div>
      </div>
    );
  }

  return (
    <ChatContainer>
      <ChatHeader 
        model={conversation.model} 
        modelConfigs={MODEL_CONFIGS} 
        onModelChange={handleModelChange} 
      />
      
      {conversation.messages.length > 0 ? (
        <>
          <MessageList messages={conversation.messages} />
          <ChatStatus state={chatState} error={error} />
          <ChatInput
            value={inputValue}
            onChange={setInputValue}
            onSend={handleSendMessage}
            onKeyDown={handleKeyDown}
            disabled={chatState !== 'idle'}
          />
        </>
      ) : (
        <EmptyState onModelSelect={handleModelChange} modelConfigs={MODEL_CONFIGS} />
      )}
      
      <div ref={messagesEndRef} />
    </ChatContainer>
  );
}
