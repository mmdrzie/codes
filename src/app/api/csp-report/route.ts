import { NextRequest, NextResponse } from 'next/server';
import SecureLogger from '../../../utils/logger';

export async function POST(request: NextRequest) {
  try {
    const report = await request.json();
    
    // Log the CSP violation
    SecureLogger.security('CSP Violation Detected', {
      sourceFile: report['csp-report']?.source_file,
      lineNumber: report['csp-report']?.line_number,
      columnNumber: report['csp-report']?.column_number,
      violatedDirective: report['csp-report']?.violated_directive,
      effectiveDirective: report['csp-report']?.effective_directive,
      originalPolicy: report['csp-report']?.original_policy,
      blockedUri: report['csp-report']?.blocked_uri,
      documentUri: report['csp-report']?.document_uri,
      referrer: report['csp-report']?.referrer,
      statusCode: report['csp-report']?.status_code,
      userAgent: request.headers.get('user-agent'),
      ip: request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown'
    });

    return NextResponse.json({ message: 'CSP report received' }, { status: 204 });
  } catch (error) {
    SecureLogger.error('Failed to process CSP report', { 
      error: (error as Error).message,
      stack: (error as Error).stack
    });
    
    return NextResponse.json({ error: 'Invalid CSP report format' }, { status: 400 });
  }
}