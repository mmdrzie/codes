import React from 'react';

interface MessageActionsProps {
  messageId: string;
  content: string;
}

export default function MessageActions({ messageId, content }: MessageActionsProps) {
  const handleCopy = () => {
    navigator.clipboard.writeText(content);
  };

  return (
    <div className="flex space-x-2 mt-3 opacity-0 group-hover:opacity-100 transition-opacity">
      <button
        onClick={handleCopy}
        className="text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 px-2 py-1 rounded"
        title="Copy message"
      >
        Copy
      </button>
      <button
        className="text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 px-2 py-1 rounded"
        title="Regenerate response"
      >
        Regenerate
      </button>
      <button
        className="text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 px-2 py-1 rounded"
        title="Thumbs up"
      >
        👍
      </button>
      <button
        className="text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 px-2 py-1 rounded"
        title="Thumbs down"
      >
        👎
      </button>
    </div>
  );
}