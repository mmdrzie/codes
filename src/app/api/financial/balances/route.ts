/**
 * Bank-Grade Financial Balances API Endpoint
 * Implements secure balance checking with post-quantum cryptography
 */

import { NextRequest, NextResponse } from 'next/server';
import { FinancialCore } from '../../../../src/lib/financial-core';
import { FinancialSecurityBindings } from '../../../../src/lib/financial-core/security-bindings';

// Balance response interface
interface BalanceResponse {
  success: boolean;
  accountId?: string;
  balance?: number;
  currency?: string;
  error?: string;
}

export async function GET(request: NextRequest) {
  try {
    // Extract auth token from headers
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json(
        { success: false, error: 'Authorization token required' },
        { status: 401 }
      );
    }

    const token = authHeader.substring(7);
    const clientIp = request.headers.get('x-forwarded-for') || 'unknown';
    const userAgent = request.headers.get('user-agent') || 'unknown';

    // Authenticate financial operation
    const securityContext = await FinancialSecurityBindings.authenticateFinancialOperation(
      token,
      clientIp,
      userAgent,
      'balance_check'
    );

    if (!securityContext) {
      return NextResponse.json(
        { success: false, error: 'Authentication failed' },
        { status: 401 }
      );
    }

    // Extract account ID from query parameters
    const url = new URL(request.url);
    const accountId = url.searchParams.get('accountId');

    if (!accountId) {
      return NextResponse.json(
        { success: false, error: 'Account ID is required' },
        { status: 400 }
      );
    }

    // Check if circuit breaker is active
    const circuitBreakerActive = await FinancialSecurityBindings.isCircuitBreakerActive();
    if (circuitBreakerActive) {
      return NextResponse.json(
        { 
          success: false, 
          error: 'System temporarily unavailable due to security maintenance' 
        },
        { status: 503 }
      );
    }

    // Get the balance
    const balance = await FinancialCore.getBalance(
      accountId,
      securityContext.userId,
      securityContext.ipAddress
    );

    if (balance) {
      const response: BalanceResponse = {
        success: true,
        accountId: balance.accountId,
        balance: balance.currentBalance,
        currency: 'USD' // Default currency - in real implementation, this would be configurable
      };

      return NextResponse.json(response, { status: 200 });
    } else {
      const response: BalanceResponse = {
        success: false,
        error: 'Account not found or balance unavailable'
      };

      return NextResponse.json(response, { status: 404 });
    }
  } catch (error) {
    console.error('Balance API error:', error);

    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}

// POST endpoint for batch balance checks
export async function POST(request: NextRequest) {
  try {
    // Extract auth token from headers
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json(
        { success: false, error: 'Authorization token required' },
        { status: 401 }
      );
    }

    const token = authHeader.substring(7);
    const clientIp = request.headers.get('x-forwarded-for') || 'unknown';
    const userAgent = request.headers.get('user-agent') || 'unknown';

    // Authenticate financial operation
    const securityContext = await FinancialSecurityBindings.authenticateFinancialOperation(
      token,
      clientIp,
      userAgent,
      'balance_check'
    );

    if (!securityContext) {
      return NextResponse.json(
        { success: false, error: 'Authentication failed' },
        { status: 401 }
      );
    }

    // Parse request body
    const body = await request.json();
    const { accountIds }: { accountIds: string[] } = body;

    if (!accountIds || !Array.isArray(accountIds) || accountIds.length === 0) {
      return NextResponse.json(
        { success: false, error: 'Account IDs array is required' },
        { status: 400 }
      );
    }

    // Check if circuit breaker is active
    const circuitBreakerActive = await FinancialSecurityBindings.isCircuitBreakerActive();
    if (circuitBreakerActive) {
      return NextResponse.json(
        { 
          success: false, 
          error: 'System temporarily unavailable due to security maintenance' 
        },
        { status: 503 }
      );
    }

    // Get balances for all requested accounts
    const balances = [];
    for (const accountId of accountIds) {
      const balance = await FinancialCore.getBalance(
        accountId,
        securityContext.userId,
        securityContext.ipAddress
      );
      
      if (balance) {
        balances.push({
          accountId: balance.accountId,
          balance: balance.currentBalance,
          currency: 'USD'
        });
      }
    }

    return NextResponse.json({
      success: true,
      balances,
      currency: 'USD'
    }, { status: 200 });
  } catch (error) {
    console.error('Batch balance API error:', error);

    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}