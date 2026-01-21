/**
 * Bank-Grade Financial Withdrawals API Endpoint
 * Implements secure fund withdrawals with post-quantum cryptography
 */

import { NextRequest, NextResponse } from 'next/server';
import { FinancialCore } from '../../../../src/lib/financial-core';
import { FinancialSecurityBindings } from '../../../../src/lib/financial-core/security-bindings';

// Withdrawal request interface
interface WithdrawalRequest {
  accountId: string;
  amount: number; // Amount in smallest currency unit (e.g., cents)
  description: string;
  referenceId?: string;
}

// Withdrawal response interface
interface WithdrawalResponse {
  success: boolean;
  transactionId?: string;
  error?: string;
  balanceAfterWithdrawal?: number;
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
      'withdrawal'
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
    const body: WithdrawalRequest = await request.json();

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
        { success: false, error: 'Withdrawal amount must be positive' },
        { status: 400 }
      );
    }

    // Perform the withdrawal
    const result = await FinancialCore.withdraw(
      body.accountId,
      body.amount,
      body.description,
      securityContext.userId,
      securityContext.ipAddress,
      body.referenceId
    );

    if (result.success) {
      // Get balance after successful withdrawal
      const balance = await FinancialCore.getBalance(body.accountId, securityContext.userId, securityContext.ipAddress);

      const response: WithdrawalResponse = {
        success: true,
        transactionId: result.transactionId,
        balanceAfterWithdrawal: balance?.currentBalance || 0
      };

      return NextResponse.json(response, { status: 200 });
    } else {
      const response: WithdrawalResponse = {
        success: false,
        error: result.error || 'Withdrawal failed'
      };

      return NextResponse.json(response, { status: 400 });
    }
  } catch (error) {
    console.error('Withdrawal API error:', error);

    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}