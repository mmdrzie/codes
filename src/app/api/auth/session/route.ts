import { NextRequest, NextResponse } from 'next/server';
import { AuthService } from '@/services/auth-service';
import { SecurityMonitor, SecurityEvent } from '@/lib/security-monitoring';

export async function GET(request: NextRequest) {
  try {
    // Get client IP and user agent for security monitoring
    const ipAddress = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown';
    const userAgent = request.headers.get('user-agent') || 'unknown';
    
    // Get current user from session
    const user = await AuthService.getCurrentUser();
    
    if (!user) {
      // No active session
      return new Response(
        JSON.stringify({ loggedIn: false }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    }
    
    // Log session access
    SecurityMonitor.logEvent(
      SecurityEvent.AUTH_SUCCESS,
      { 
        userId: user.id, 
        ipAddress, 
        userAgent,
        metadata: { action: 'session_check' }
      },
      `Session check for user: ${user.id}`
    );
    
    // Return user info (excluding sensitive data)
    return new Response(
      JSON.stringify({ 
        loggedIn: true,
        user: {
          id: user.id,
          type: user.type,
          isVerified: user.isVerified,
        },
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  } catch (error: any) {
    // Log error
    SecurityMonitor.captureError(error, {
      ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
      userAgent: request.headers.get('user-agent') || 'unknown',
    });
    
    return new Response(
      JSON.stringify({ error: error.message }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}

export async function DELETE(request: NextRequest) {
  try {
    // Get client IP and user agent for security monitoring
    const ipAddress = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown';
    const userAgent = request.headers.get('user-agent') || 'unknown';
    
    // Perform logout
    await AuthService.logout();
    
    // Log logout event
    SecurityMonitor.logEvent(
      SecurityEvent.AUTH_SUCCESS,
      { 
        ipAddress, 
        userAgent,
        metadata: { action: 'logout' }
      },
      'User logged out successfully'
    );
    
    // Return success response
    return new Response(
      JSON.stringify({ success: true }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  } catch (error: any) {
    // Log error
    SecurityMonitor.captureError(error, {
      ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
      userAgent: request.headers.get('user-agent') || 'unknown',
    });
    
    return new Response(
      JSON.stringify({ error: error.message }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
