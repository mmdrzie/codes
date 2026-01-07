import { NextRequest } from 'next/server';
import { AuthService } from '@/services/auth-service';
import { SecurityMonitor, SecurityEvent } from '@/lib/security-monitoring';
import { z } from 'zod';

// Web3 sign-in schema
const web3SignInSchema = z.object({
  message: z.string(),
  signature: z.string().regex(/^0x[a-fA-F0-9]{130}$/, 'Invalid signature format'),
  domain: z.string(),
});

export async function POST(request: NextRequest) {
  try {
    // Get client IP and user agent for security monitoring
    const ipAddress = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown';
    const userAgent = request.headers.get('user-agent') || 'unknown';
    
    // Parse request body
    const body = await request.json();
    const validatedData = web3SignInSchema.safeParse(body);
    
    if (!validatedData.success) {
      // Log validation failure
      SecurityMonitor.logAuthFailure(
        null,
        { ipAddress, userAgent },
        `Web3 sign-in validation failed: ${validatedData.error.errors.map(e => e.message).join(', ')}`
      );
      
      return new Response(
        JSON.stringify({ 
          error: 'Validation failed', 
          details: validatedData.error.errors 
        }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }
    
    const { message, signature, domain } = validatedData.data;
    
    // Attempt Web3 sign-in
    const result = await AuthService.signInWithWeb3({ message, signature }, domain);
    
    // Log successful Web3 authentication
    SecurityMonitor.logAuthSuccess(
      result.user.id,
      { 
        userId: result.user.id, 
        ipAddress, 
        userAgent,
        sessionId: result.token.substring(0, 16), // Only log partial token for security
        metadata: { auth_type: 'web3' }
      }
    );
    
    // Return success response
    return new Response(
      JSON.stringify({ 
        success: true, 
        user: {
          id: result.user.id,
          type: result.user.type,
          isVerified: result.user.isVerified,
        },
        token: result.token
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  } catch (error: any) {
    // Log Web3 authentication failure
    SecurityMonitor.logAuthFailure(
      null,
      { 
        ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
        userAgent: request.headers.get('user-agent') || 'unknown',
        metadata: { auth_type: 'web3' }
      },
      error.message
    );
    
    return new Response(
      JSON.stringify({ error: error.message }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    );
  }
}