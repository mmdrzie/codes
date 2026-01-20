/**
 * Security Health Check API Endpoint
 * Provides security status and health information
 */

import { NextRequest, NextResponse } from 'next/server';
import { SecurityInitializer } from '@/src/lib/security-init';
import { logger } from '@/src/lib/logger';
import { SecurityMonitor } from '@/src/lib/security-monitoring';

export async function GET(request: NextRequest) {
  try {
    // Log the health check request
    const clientIp = request.headers.get('x-forwarded-for') || 'unknown';
    const userAgent = request.headers.get('user-agent') || 'unknown';
    
    logger.info('Security health check requested', {
      ip: clientIp,
      userAgent,
      url: request.url
    });

    // Perform security health check
    const healthStatus = await SecurityInitializer.healthCheck();
    
    // Log the health check result
    await SecurityMonitor.logEvent(
      healthStatus.status === 'healthy' 
        ? 'auth_success' 
        : 'suspicious_activity', 
      {
        userId: 'system',
        ipAddress: clientIp,
        userAgent,
        timestamp: new Date(),
        metadata: {
          health_status: healthStatus.status,
          component: 'security',
          endpoint: '/api/health/security'
        }
      },
      `Security health check: ${healthStatus.status}`
    );

    return NextResponse.json(
      {
        status: healthStatus.status,
        timestamp: new Date().toISOString(),
        details: healthStatus.details,
        version: '1.0.0',
        checks: {
          securityInitialized: SecurityInitializer.isInitialized(),
          environmentValidated: !!process.env.NODE_ENV,
          siemConnected: healthStatus.details?.siem?.connected ?? false,
          secretsConfigured: healthStatus.details?.environment?.configured ?? false
        }
      },
      {
        status: healthStatus.status === 'healthy' ? 200 : 503,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
          'Pragma': 'no-cache',
          'Expires': '0'
        }
      }
    );
  } catch (error) {
    logger.error('Security health check failed', {
      error: (error as Error).message,
      stack: (error as Error).stack
    });

    // Log security event for the failure
    const clientIp = request.headers.get('x-forwarded-for') || 'unknown';
    const userAgent = request.headers.get('user-agent') || 'unknown';
    
    await SecurityMonitor.logEvent(
      'auth_failure',
      {
        userId: 'system',
        ipAddress: clientIp,
        userAgent,
        timestamp: new Date(),
        metadata: {
          health_status: 'failed',
          component: 'security',
          endpoint: '/api/health/security',
          error: (error as Error).message
        }
      },
      `Security health check failed: ${(error as Error).message}`
    );

    return NextResponse.json(
      {
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        error: 'Security health check failed',
        details: {
          error: (error as Error).message
        }
      },
      {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
          'Pragma': 'no-cache',
          'Expires': '0'
        }
      }
    );
  }
}

export async function HEAD(request: NextRequest) {
  try {
    const healthStatus = await SecurityInitializer.healthCheck();
    
    return new NextResponse(null, {
      status: healthStatus.status === 'healthy' ? 200 : 503,
      headers: {
        'X-Security-Status': healthStatus.status,
        'X-Timestamp': new Date().toISOString(),
        'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      }
    });
  } catch (error) {
    return new NextResponse(null, {
      status: 500,
      headers: {
        'X-Security-Status': 'unhealthy',
        'X-Timestamp': new Date().toISOString(),
        'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      }
    });
  }
}