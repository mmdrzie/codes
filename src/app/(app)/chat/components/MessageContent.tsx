import React from 'react';

interface MessageContentProps {
  content: string;
}

export default function MessageContent({ content }: MessageContentProps) {
  // Simple markdown rendering for basic formatting
  const renderMarkdown = (text: string) => {
    // Convert markdown to HTML elements
    return text
      .split('\n')
      .map((line, index) => {
        // Check for headers
        if (line.startsWith('# ')) {
          return <h1 key={index} className="text-xl font-bold my-2">{line.substring(2)}</h1>;
        } else if (line.startsWith('## ')) {
          return <h2 key={index} className="text-lg font-bold my-2">{line.substring(3)}</h2>;
        } else if (line.startsWith('### ')) {
          return <h3 key={index} className="font-bold my-2">{line.substring(4)}</h3>;
        }
        // Check for unordered lists
        else if (line.startsWith('- ') || line.startsWith('* ')) {
          return <li key={index} className="list-disc ml-5 my-1">{line.substring(2)}</li>;
        }
        // Check for ordered lists
        else if (/^\d+\. /.test(line)) {
          return <li key={index} className="list-decimal ml-5 my-1">{line.replace(/^\d+\. /, '')}</li>;
        }
        // Check for bold text
        else if (line.includes('**') && line.includes('**')) {
          const parts = line.split(/(\*\*.*?\*\*)/);
          return (
            <p key={index} className="my-2">
              {parts.map((part, i) => 
                part.startsWith('**') && part.endsWith('**') 
                  ? <strong key={i}>{part.substring(2, part.length - 2)}</strong> 
                  : part
              )}
            </p>
          );
        }
        // Check for code blocks
        else if (line.startsWith('```')) {
          // This is a simplified approach - in a real implementation we'd handle multi-line code blocks
          return <pre key={index} className="bg-gray-900 border border-gray-700 rounded-md p-3 my-2 overflow-x-auto"><code>{line}</code></pre>;
        }
        // Check for inline code
        else if (line.includes('`') && line.includes('`')) {
          const parts = line.split(/(`.*?`)/);
          return (
            <p key={index} className="my-2">
              {parts.map((part, i) => 
                part.startsWith('`') && part.endsWith('`') 
                  ? <code key={i} className="bg-gray-700/50 text-gray-200 px-1.5 py-0.5 rounded text-sm">{part.substring(1, part.length - 1)}</code> 
                  : part
              )}
            </p>
          );
        }
        // Regular paragraph
        else if (line.trim() !== '') {
          return <p key={index} className="my-2">{line}</p>;
        }
        // Empty line
        else {
          return <br key={index} />;
        }
      });
  };

  return (
    <div className="text-gray-200">
      {renderMarkdown(content)}
    </div>
  );
}