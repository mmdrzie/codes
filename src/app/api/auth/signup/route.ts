import { NextRequest } from 'next/server';
import { AuthService } from '@/services/auth-service';
import { SecurityMonitor, SecurityEvent } from '@/lib/security-monitoring';
import { z } from 'zod';

// Sign-up request schema
const signUpSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  displayName: z.string().optional(),
});

export async function POST(request: NextRequest) {
  try {
    // Get client IP and user agent for security monitoring
    const ipAddress = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown';
    const userAgent = request.headers.get('user-agent') || 'unknown';
    
    // Parse request body
    const body = await request.json();
    const validatedData = signUpSchema.safeParse(body);
    
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
    
    const { email, password, displayName } = validatedData.data;
    
    // Attempt sign-up
    const result = await AuthService.signUpWithEmailAndPassword(email, password, displayName);
    
    // Log successful registration
    SecurityMonitor.logAuthSuccess(
      result.user.id,
      { 
        userId: result.user.id, 
        ipAddress, 
        userAgent,
        sessionId: result.token.substring(0, 16), // Only log partial token for security
        metadata: { action: 'registration' }
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
      { status: 201, headers: { 'Content-Type': 'application/json' } }
    );
  } catch (error: any) {
    // Log registration failure
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
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }
}