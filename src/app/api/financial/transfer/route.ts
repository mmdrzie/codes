/**
 * Bank-Grade Financial Transfer API Endpoint
 * Implements secure fund transfers with post-quantum cryptography
 */

import { NextRequest, NextResponse } from 'next/server';
import { FinancialCore } from '../../../../src/lib/financial-core';
import { FinancialSecurityBindings } from '../../../../src/lib/financial-core/security-bindings';

// Transfer request interface
interface TransferRequest {
  fromAccountId: string;
  toAccountId: string;
  amount: number; // Amount in smallest currency unit (e.g., cents)
  description: string;
  referenceId?: string;
}

// Transfer response interface
interface TransferResponse {
  success: boolean;
  transactionId?: string;
  error?: string;
  balanceAfterTransfer?: {
    fromAccount: number;
    toAccount: number;
  };
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
      'transfer'
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
    const body: TransferRequest = await request.json();

    // Validate required fields
    if (!body.fromAccountId || !body.toAccountId || !body.amount || !body.description) {
      return NextResponse.json(
        { success: false, error: 'Missing required fields: fromAccountId, toAccountId, amount, description' },
        { status: 400 }
      );
    }

    // Validate amount
    if (body.amount <= 0) {
      return NextResponse.json(
        { success: false, error: 'Transfer amount must be positive' },
        { status: 400 }
      );
    }

    // Perform the transfer
    const result = await FinancialCore.transferFunds(
      body.fromAccountId,
      body.toAccountId,
      body.amount,
      body.description,
      securityContext.userId,
      securityContext.ipAddress,
      body.referenceId
    );

    if (result.success) {
      // Get balances after successful transfer
      const fromBalance = await FinancialCore.getBalance(body.fromAccountId);
      const toBalance = await FinancialCore.getBalance(body.toAccountId);

      const response: TransferResponse = {
        success: true,
        transactionId: result.transactionId,
        balanceAfterTransfer: {
          fromAccount: fromBalance?.currentBalance || 0,
          toAccount: toBalance?.currentBalance || 0
        }
      };

      return NextResponse.json(response, { status: 200 });
    } else {
      const response: TransferResponse = {
        success: false,
        error: result.error || 'Transfer failed'
      };

      return NextResponse.json(response, { status: 400 });
    }
  } catch (error) {
    console.error('Transfer API error:', error);

    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}