/**
 * Bank-Grade Financial Deposits API Endpoint
 * Implements secure fund deposits with post-quantum cryptography
 */

import { NextRequest, NextResponse } from 'next/server';
import { FinancialCore } from '../../../../src/lib/financial-core';
import { FinancialSecurityBindings } from '../../../../src/lib/financial-core/security-bindings';

// Deposit request interface
interface DepositRequest {
  accountId: string;
  amount: number; // Amount in smallest currency unit (e.g., cents)
  description: string;
  referenceId?: string;
}

// Deposit response interface
interface DepositResponse {
  success: boolean;
  transactionId?: string;
  error?: string;
  balanceAfterDeposit?: number;
}

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
      'deposit'
    );

    if (!securityContext) {
      return NextResponse.json(
        { success: false, error: 'Authentication failed' },
        { status: 401 }
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

    // Parse request body
    const body: DepositRequest = await request.json();

    // Validate required fields
    if (!body.accountId || !body.amount || !body.description) {
      return NextResponse.json(
        { success: false, error: 'Missing required fields: accountId, amount, description' },
        { status: 400 }
      );
    }

    // Validate amount
    if (body.amount <= 0) {
      return NextResponse.json(
        { success: false, error: 'Deposit amount must be positive' },
        { status: 400 }
      );
    }

    // Perform the deposit
    const result = await FinancialCore.deposit(
      body.accountId,
      body.amount,
      body.description,
      securityContext.userId,
      securityContext.ipAddress,
      body.referenceId
    );

    if (result.success) {
      // Get balance after successful deposit
      const balance = await FinancialCore.getBalance(body.accountId, securityContext.userId, securityContext.ipAddress);

      const response: DepositResponse = {
        success: true,
        transactionId: result.transactionId,
        balanceAfterDeposit: balance?.currentBalance || 0
      };

      return NextResponse.json(response, { status: 200 });
    } else {
      const response: DepositResponse = {
        success: false,
        error: result.error || 'Deposit failed'
      };

      return NextResponse.json(response, { status: 400 });
    }
  } catch (error) {
    console.error('Deposit API error:', error);

    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}