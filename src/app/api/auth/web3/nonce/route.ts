import { NextRequest } from 'next/server';
import { SiweService } from '@/services/web3/siwe-service';
import { SecurityMonitor, SecurityEvent } from '@/lib/security-monitoring';
import { z } from 'zod';

// Nonce generation schema
const nonceSchema = z.object({
  address: z.string().regex(/^0x[a-fA-F0-9]{40}$/, 'Invalid Ethereum address'),
  domain: z.string(),
  chainId: z.number().int().positive(),
});

export async function POST(request: NextRequest) {
  try {
    // Get client IP and user agent for security monitoring
    const ipAddress = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown';
    const userAgent = request.headers.get('user-agent') || 'unknown';
    
    // Parse request body
    const body = await request.json();
    const validatedData = nonceSchema.safeParse(body);
    
    if (!validatedData.success) {
      // Log validation failure
      SecurityMonitor.logSuspiciousActivity(
        { ipAddress, userAgent },
        `Nonce request validation failed: ${validatedData.error.errors.map(e => e.message).join(', ')}`
      );
      
      return new Response(
        JSON.stringify({ 
          error: 'Validation failed', 
          details: validatedData.error.errors 
        }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }
    
    const { address, domain, chainId } = validatedData.data;
    
    // Generate SIWE message with nonce
    const { message, nonce } = SiweService.generateSiweMessage(address, domain, chainId);
    
    // Log nonce generation for monitoring
    SecurityMonitor.logEvent(
      SecurityEvent.AUTH_SUCCESS,
      { 
        ipAddress, 
        userAgent,
        metadata: { 
          action: 'nonce_generation', 
          address: address.substring(0, 8) + '...' + address.substring(address.length - 4) // Mask address
        }
      },
      `Nonce generated for address: ${address.substring(0, 8)}...`
    );
    
    // Return SIWE message and nonce
    return new Response(
      JSON.stringify({ 
        message,
        nonce,
        success: true
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