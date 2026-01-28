export type MessageRole = 'user' | 'assistant' | 'system' | 'function' | 'tool';

export type Message = {
  id: string;
  role: MessageRole;
  content: string;
  timestamp: Date;
  metadata?: {
    model?: string;
    tokens?: number;
    cost?: number;
    duration?: number;
  };
};

export type Conversation = {
  id: string;
  title: string;
  messages: Message[];
  model: string;
  created_at: Date;
  updated_at: Date;
  metadata: {
    total_tokens: number;
    total_cost: number;
    message_count: number;
  };
};

export type ModelConfig = {
  id: string;
  name: string;
  provider: string;
  context_window: number;
  cost_per_token?: number;
  available: boolean;
  requires_role?: string[];
};

export type ChatState = 'idle' | 'streaming' | 'thinking' | 'error';