import { NextRequest } from 'next/server';
import { AuthService } from '@/services/auth-service';
import { SecurityMonitor, SecurityEvent } from '@/lib/security-monitoring';
import { z } from 'zod';

// Sign-in request schema
const signInSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
});

export async function POST(request: NextRequest) {
  try {
    // Get client IP and user agent for security monitoring
    const ipAddress = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown';
    const userAgent = request.headers.get('user-agent') || 'unknown';
    
    // Parse request body
    const body = await request.json();
    const validatedData = signInSchema.safeParse(body);
    
    if (!validatedData.success) {
      // Log validation failure
      SecurityMonitor.logAuthFailure(
        null,
        { ipAddress, userAgent },
        `Validation error: ${validatedData.error.errors.map(e => e.message).join(', ')}`
      );
      
      return new Response(
        JSON.stringify({ 
          error: 'Validation failed', 
          details: validatedData.error.errors 
        }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }
    
    const { email, password } = validatedData.data;
    
    // Attempt sign-in
    const result = await AuthService.signInWithEmailAndPassword(email, password);
    
    // Log successful authentication
    SecurityMonitor.logAuthSuccess(
      result.user.id,
      { 
        userId: result.user.id, 
        ipAddress, 
        userAgent,
        sessionId: result.token.substring(0, 16) // Only log partial token for security
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
    // Log authentication failure
    SecurityMonitor.logAuthFailure(
      null,
      { 
        ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
        userAgent: request.headers.get('user-agent') || 'unknown'
      },
      error.message
    );
    
    return new Response(
      JSON.stringify({ error: error.message }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    );
  }
}