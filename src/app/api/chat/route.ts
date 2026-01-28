import { NextRequest } from 'next/server';

export async function POST(req: NextRequest) {
  try {
    const { conversation_id, model, messages, stream, max_tokens } = await req.json();

    // Validate required fields
    if (!messages || !Array.isArray(messages) || messages.length === 0) {
      return Response.json(
        { error: 'Messages array is required' },
        { status: 400 }
      );
    }

    // Get the latest user message
    const userMessage = messages[messages.length - 1];
    if (userMessage.role !== 'user') {
      return Response.json(
        { error: 'Last message must be from user' },
        { status: 400 }
      );
    }

    // Simulate AI response generation
    // In a real implementation, this would call an AI service
    const aiResponse = generateMockAIResponse(userMessage.content, model);

    if (stream) {
      // Create a readable stream for SSE
      const encoder = new TextEncoder();
      const stream = new ReadableStream({
        start(controller) {
          // Send initial thinking message
          controller.enqueue(encoder.encode(`data: ${JSON.stringify({ content: "" })}\n\n`));
          
          // Simulate streaming response
          let currentIndex = 0;
          const responseText = aiResponse;
          
          const sendChunk = () => {
            if (currentIndex < responseText.length) {
              const chunk = responseText.substring(currentIndex, currentIndex + 10); // Send 10 characters at a time
              currentIndex += 10;
              
              controller.enqueue(encoder.encode(`data: ${JSON.stringify({ content: chunk })}\n\n`));
              setTimeout(sendChunk, 50); // Simulate delay between chunks
            } else {
              controller.enqueue(encoder.encode("data: [DONE]\n\n"));
              controller.close();
            }
          };
          
          setTimeout(sendChunk, 100);
        }
      });

      return new Response(stream, {
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
        },
      });
    } else {
      // Non-streaming response
      const response = {
        message: {
          id: crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(),
          role: 'assistant' as const,
          content: aiResponse,
          timestamp: new Date(),
        },
        usage: {
          prompt_tokens: messages.reduce((acc, msg) => acc + msg.content.length, 0),
          completion_tokens: aiResponse.length,
          total_tokens: messages.reduce((acc, msg) => acc + msg.content.length, 0) + aiResponse.length,
        },
        cost: 0.00001 * aiResponse.length, // Simplified cost calculation
      };

      return Response.json(response);
    }
  } catch (error) {
    console.error('Error in chat API:', error);
    return Response.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

// Mock AI response generator - in a real implementation, this would call an actual AI service
function generateMockAIResponse(input: string, model: string): string {
  const lowerInput = input.toLowerCase();
  
  if (lowerInput.includes('hello') || lowerInput.includes('hi')) {
    return `Hello! I'm your AI assistant for trading insights. How can I help you with market analysis today?`;
  } else if (lowerInput.includes('trend') || lowerInput.includes('market')) {
    return `Based on current market conditions, I observe that volatility has increased by approximately 15% over the past week. Key sectors showing strength include technology and renewable energy, while traditional retail continues to face headwinds. Consider rebalancing your portfolio to take advantage of these shifts.`;
  } else if (lowerInput.includes('risk') || lowerInput.includes('portfolio')) {
    return `For portfolio risk assessment, I recommend diversifying across at least 5-7 different asset classes. Current market conditions suggest maintaining 60% in equities, 25% in bonds, and 15% in alternative investments. Consider reducing exposure to high-beta stocks during periods of elevated VIX readings.`;
  } else if (lowerInput.includes('strategy') || lowerInput.includes('trade')) {
    return `A momentum-based trading strategy could be effective given current market conditions. Focus on stocks with strong relative strength indicators and positive earnings revisions. Set stop-loss orders at 8-10% below entry price and consider taking profits at 15-20% gains.`;
  } else {
    return `Thank you for your query about "${input.substring(0, 30)}${input.length > 30 ? '...' : ''}". Based on my analysis of current market conditions and historical patterns, I recommend considering both technical and fundamental factors in your decision-making process. The current economic environment suggests a cautious but opportunistic approach to trading.`;
  }
}