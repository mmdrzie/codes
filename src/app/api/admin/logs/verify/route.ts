import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../../auth/[...nextauth]/route';
import { TamperProofLogger } from '../../../../../lib/logging/tamper-proof-logger';
import { LogVerifier } from '../../../../../lib/logging/log-verifier';
import { logger } from '../../../../../lib/logger';

export async function POST(request: NextRequest) {
  try {
    // Authenticate the admin user
    const session = await getServerSession(authOptions);
    if (!session || !session.user || session.user.role !== 'admin') {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tamperProofLogger = new TamperProofLogger('./logs', process.env.S3_LOG_BUCKET);
    const logVerifier = new LogVerifier(tamperProofLogger);

    // Perform integrity verification
    const verificationResult = await logVerifier.performIntegrityCheck();

    // Log the verification result
    logger.audit('Log integrity verification performed', {
      verifiedBy: session.user.id,
      isValid: verificationResult.isValid,
      tamperedEntries: verificationResult.tamperedEntries?.length || 0,
      duration: verificationResult.duration
    });

    return NextResponse.json(verificationResult);
  } catch (error) {
    logger.error('Failed to verify log integrity', {
      error: (error as Error).message,
      adminId: request.headers.get('x-user-id') || 'unknown'
    });

    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

export async function GET(request: NextRequest) {
  try {
    // Authenticate the admin user
    const session = await getServerSession(authOptions);
    if (!session || !session.user || session.user.role !== 'admin') {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tamperProofLogger = new TamperProofLogger('./logs', process.env.S3_LOG_BUCKET);
    const logVerifier = new LogVerifier(tamperProofLogger);

    // Parse query parameters
    const { searchParams } = new URL(request.url);
    const startDateParam = searchParams.get('startDate');
    const endDateParam = searchParams.get('endDate');
    const userId = searchParams.get('userId');
    const level = searchParams.get('level');
    const searchTerm = searchParams.get('searchTerm');

    // Perform integrity check
    if (startDateParam && endDateParam) {
      // Verify a specific time period
      const startDate = parseInt(startDateParam, 10);
      const endDate = parseInt(endDateParam, 10);

      if (isNaN(startDate) || isNaN(endDate)) {
        return NextResponse.json({ error: 'Invalid date parameters' }, { status: 400 });
      }

      const result = await logVerifier.verifyTimePeriod(startDate, endDate);
      
      logger.audit('Time period log integrity verification performed', {
        verifiedBy: session.user.id,
        startDate,
        endDate,
        isValid: result.isValid,
        tamperedEntries: result.tamperedEntries.length
      });

      return NextResponse.json(result);
    } else {
      // Perform forensic analysis if specific criteria are provided
      if (userId || level || searchTerm) {
        const criteria: any = {};
        if (userId) criteria.userId = userId;
        if (level) criteria.level = level;
        if (searchTerm) criteria.searchTerm = searchTerm;

        const forensicResult = await logVerifier.performForensicAnalysis(criteria);
        
        logger.audit('Log forensic analysis performed', {
          verifiedBy: session.user.id,
          criteria,
          totalEntries: forensicResult.totalEntries,
          matchingEntries: forensicResult.matchingEntries,
          tamperedEntries: forensicResult.tamperedEntries.length,
          suspiciousPatterns: forensicResult.suspiciousPatterns.length
        });

        return NextResponse.json(forensicResult);
      } else {
        // Just get basic integrity status
        const integrityStatus = await logVerifier.performIntegrityCheck();
        
        logger.audit('Log integrity status requested', {
          requestedBy: session.user.id,
          isValid: integrityStatus.isValid,
          duration: integrityStatus.duration
        });

        return NextResponse.json(integrityStatus);
      }
    }
  } catch (error) {
    logger.error('Failed to get log integrity status', {
      error: (error as Error).message,
      adminId: request.headers.get('x-user-id') || 'unknown'
    });

    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}