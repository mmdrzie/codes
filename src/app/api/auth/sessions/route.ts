import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { ConcurrentSessionManager } from '../../../../lib/auth/concurrent-sessions';
import { DeviceFingerprintGenerator } from '../../../../lib/auth/device-fingerprint';
import { logger } from '../../../../lib/logger';

export async function GET(request: NextRequest) {
  try {
    // Authenticate the user
    const session = await getServerSession(authOptions);
    if (!session || !session.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const userId = session.user.id as string;
    if (!userId) {
      return NextResponse.json({ error: 'Invalid user ID' }, { status: 400 });
    }

    // Initialize session manager
    const sessionManager = new ConcurrentSessionManager();

    // Get all active sessions for the user
    const activeSessions = await sessionManager.getActiveSessions(userId);

    // Format the response to exclude sensitive information
    const formattedSessions = activeSessions.map(session => ({
      sessionId: session.sessionId,
      deviceId: session.deviceId,
      ipAddress: session.ipAddress,
      userAgent: session.userAgent,
      deviceType: session.deviceFingerprint.deviceType,
      browserName: session.deviceFingerprint.browserName,
      os: session.deviceFingerprint.os,
      createdAt: session.createdAt,
      lastAccessed: session.lastAccessed,
      isActive: session.isActive,
      isCurrent: session.sessionId === session.sessionId // Will be replaced with actual logic
    }));

    // Add information about current session
    const currentSessionId = request.headers.get('x-session-id') || 'unknown';
    const enrichedSessions = formattedSessions.map(sess => ({
      ...sess,
      isCurrent: sess.sessionId === currentSessionId
    }));

    logger.info('User retrieved active sessions', {
      userId,
      sessionCount: enrichedSessions.length
    });

    return NextResponse.json({ sessions: enrichedSessions });
  } catch (error) {
    logger.error('Failed to get user sessions', {
      error: (error as Error).message,
      userId: request.headers.get('x-user-id') || 'unknown'
    });

    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

export async function DELETE(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    // Authenticate the user
    const session = await getServerSession(authOptions);
    if (!session || !session.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const userId = session.user.id as string;
    if (!userId) {
      return NextResponse.json({ error: 'Invalid user ID' }, { status: 400 });
    }

    // Extract session ID from URL or request body
    const sessionId = params.id || request.nextUrl.searchParams.get('id');
    if (!sessionId) {
      return NextResponse.json({ error: 'Session ID is required' }, { status: 400 });
    }

    // Initialize session manager
    const sessionManager = new ConcurrentSessionManager();

    // Verify that the session belongs to the user
    const sessionToTerminate = await sessionManager.getSessionById(sessionId);
    if (!sessionToTerminate || sessionToTerminate.userId !== userId) {
      return NextResponse.json({ error: 'Session not found or does not belong to user' }, { status: 404 });
    }

    // Terminate the specific session
    const success = await sessionManager.terminateSession(sessionId, userId);
    
    if (!success) {
      return NextResponse.json({ error: 'Failed to terminate session' }, { status: 500 });
    }

    logger.info('User terminated session', {
      userId,
      terminatedSessionId: sessionId
    });

    return NextResponse.json({ message: 'Session terminated successfully' });
  } catch (error) {
    logger.error('Failed to terminate session', {
      error: (error as Error).message,
      userId: request.headers.get('x-user-id') || 'unknown',
      sessionId: params.id || request.nextUrl.searchParams.get('id') || 'unknown'
    });

    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  try {
    // Authenticate the user
    const session = await getServerSession(authOptions);
    if (!session || !session.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const userId = session.user.id as string;
    if (!userId) {
      return NextResponse.json({ error: 'Invalid user ID' }, { status: 400 });
    }

    const { action, sessionId } = await request.json();

    if (!action) {
      return NextResponse.json({ error: 'Action is required' }, { status: 400 });
    }

    // Initialize session manager
    const sessionManager = new ConcurrentSessionManager();

    switch (action) {
      case 'terminate_all':
        // Terminate all sessions except the current one
        const currentSessionId = request.headers.get('x-session-id');
        
        const allSessions = await sessionManager.getActiveSessions(userId);
        let terminatedCount = 0;
        
        for (const sess of allSessions) {
          if (sess.sessionId !== currentSessionId) {
            await sessionManager.terminateSession(sess.sessionId, userId);
            terminatedCount++;
          }
        }
        
        logger.info('User terminated all sessions', {
          userId,
          terminatedCount,
          currentSessionId
        });

        return NextResponse.json({ 
          message: `Terminated ${terminatedCount} sessions successfully`,
          terminatedCount 
        });

      case 'verify_current':
        // Verify the current session
        const currentSessionIdFromHeader = request.headers.get('x-session-id');
        if (!currentSessionIdFromHeader) {
          return NextResponse.json({ error: 'Session ID not provided' }, { status: 400 });
        }

        const verificationResult = await sessionManager.verifySession(currentSessionIdFromHeader, userId);
        
        return NextResponse.json({
          isValid: verificationResult.isValid,
          session: verificationResult.session ? {
            sessionId: verificationResult.session.sessionId,
            deviceId: verificationResult.session.deviceId,
            deviceType: verificationResult.session.deviceFingerprint.deviceType,
            browserName: verificationResult.session.deviceFingerprint.browserName,
            os: verificationResult.session.deviceFingerprint.os,
            lastAccessed: verificationResult.session.lastAccessed,
            isActive: verificationResult.session.isActive
          } : null
        });

      case 'report_unauthorized_access':
        // Report unauthorized access attempt
        if (!sessionId) {
          return NextResponse.json({ error: 'Session ID is required for reporting' }, { status: 400 });
        }

        logger.securityEvent('UNAUTHORIZED_ACCESS_REPORTED', 'high', {
          userId,
          reportedSessionId: sessionId,
          reporterIpAddress: request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown',
          userAgent: request.headers.get('user-agent') || 'unknown'
        });

        return NextResponse.json({ 
          message: 'Unauthorized access report received and logged' 
        });

      default:
        return NextResponse.json({ error: 'Invalid action' }, { status: 400 });
    }
  } catch (error) {
    logger.error('Failed to process session management request', {
      error: (error as Error).message,
      userId: request.headers.get('x-user-id') || 'unknown',
      action: await request.json().then(data => data.action).catch(() => 'unknown')
    });

    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}