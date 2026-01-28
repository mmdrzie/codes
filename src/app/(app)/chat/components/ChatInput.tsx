import React, { useState, useRef, useEffect } from 'react';

interface ChatInputProps {
  value: string;
  onChange: (value: string) => void;
  onSend: () => void;
  onKeyDown: (e: React.KeyboardEvent) => void;
  disabled: boolean;
}

export default function ChatInput({ 
  value, 
  onChange, 
  onSend, 
  onKeyDown, 
  disabled 
}: ChatInputProps) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const [height, setHeight] = useState('auto');

  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      const scrollHeight = textareaRef.current.scrollHeight;
      // Set max height to 200px as specified in requirements
      const newHeight = Math.min(scrollHeight, 200);
      setHeight(`${newHeight}px`);
    }
  }, [value]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSend();
  };

  const handleKeyDownLocal = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      onSend();
    } else {
      onKeyDown(e);
    }
  };

  return (
    <div className="border-t border-gray-800 pt-4">
      <form onSubmit={handleSubmit} className="relative">
        <div className="flex items-end border border-gray-700 rounded-lg bg-gray-900 focus-within:border-blue-500 transition-colors">
          <textarea
            ref={textareaRef}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            onKeyDown={handleKeyDownLocal}
            placeholder="Type your message here..."
            disabled={disabled}
            rows={1}
            style={{ height, minHeight: '44px', maxHeight: '200px' }}
            className="w-full bg-transparent border-0 resize-none py-3 px-4 text-white placeholder-gray-500 focus:outline-none focus:ring-0"
          />
          <button
            type="submit"
            disabled={disabled || !value.trim()}
            className={`m-2 px-4 py-2 rounded-md ${
              disabled || !value.trim()
                ? 'bg-gray-700 text-gray-500 cursor-not-allowed'
                : 'bg-blue-600 text-white hover:bg-blue-700'
            }`}
          >
            Send
          </button>
        </div>
        <div className="flex justify-between text-xs text-gray-500 mt-2 px-1">
          <span>
            {value.length} character{value.length !== 1 ? 's' : ''}
          </span>
          <span>
            Shift + Enter for new line
          </span>
        </div>
      </form>
    </div>
  );
}