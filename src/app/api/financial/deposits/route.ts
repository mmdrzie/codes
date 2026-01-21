import { NextRequest } from 'next/server';
import { FinancialCore } from '../../../../src/lib/financial-core';
import { logger } from '../../../../src/lib/logger';

// Deposit request interface
interface DepositRequest {
  accountId: string;
  amount: number;
  description: string;
  referenceId?: string;
}

// Deposit response interface
interface DepositResponse {
  success: boolean;
  transactionId?: string;
  balanceAfterDeposit?: number;
  error?: string;
}

export async function POST(request: NextRequest) {
  try {
    // Extract auth token from headers
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return Response.json(
        { success: false, error: 'Authorization token required' },
        { status: 401 }
      );
    }

    const clientIp = request.headers.get('x-forwarded-for') || 'unknown';
    const userAgent = request.headers.get('user-agent') || 'unknown';

    // Parse request body
    const body: DepositRequest = await request.json();

    // Validate required fields
    if (!body.accountId || body.amount == null || !body.description) {
      return Response.json(
        { success: false, error: 'Missing required fields: accountId, amount, description' },
        { status: 400 }
      );
    }

    // Validate account ID format
    if (!/^[a-zA-Z0-9_-]+$/.test(body.accountId)) {
      return Response.json(
        { success: false, error: 'Invalid account ID format' },
        { status: 400 }
      );
    }

    // Validate amount
    if (body.amount <= 0) {
      return Response.json(
        { success: false, error: 'Deposit amount must be positive' },
        { status: 400 }
      );
    }

    // Validate amount precision (max 2 decimal places for currency)
    if (Math.round(body.amount * 100) !== body.amount * 100) {
      return Response.json(
        { success: false, error: 'Amount must have maximum 2 decimal places' },
        { status: 400 }
      );
    }

    // Perform the deposit
    const result = await FinancialCore.deposit(
      body.accountId,
      body.amount,
      body.description,
      'user_id_from_token',
      clientIp,
      body.referenceId
    );

    if (result.success) {
      // Get balance after successful deposit
      const balance = await FinancialCore.getBalance(body.accountId);
      
      const response: DepositResponse = {
        success: true,
        transactionId: result.transactionId,
        balanceAfterDeposit: balance?.currentBalance
      };

      logger.info('Deposit processed successfully', {
        accountId: body.accountId,
        amount: body.amount,
        transactionId: result.transactionId,
        userId: 'user_id_from_token'
      });

      return Response.json(response, { status: 200 });
    } else {
      const response: DepositResponse = {
        success: false,
        error: result.error || 'Deposit failed'
      };

      logger.warn('Deposit failed', {
        accountId: body.accountId,
        amount: body.amount,
        error: result.error,
        userId: 'user_id_from_token'
      });

      return Response.json(response, { status: 400 });
    }
  } catch (error) {
    logger.error('Deposit API error:', error);

    return Response.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function GET(request: NextRequest) {
  try {
    // Extract auth token from headers
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return Response.json(
        { success: false, error: 'Authorization token required' },
        { status: 401 }
      );
    }

    // Extract query parameters
    const url = new URL(request.url);
    const accountId = url.searchParams.get('accountId');
    const referenceId = url.searchParams.get('referenceId');

    if (!accountId) {
      return Response.json(
        { success: false, error: 'Account ID required' },
        { status: 400 }
      );
    }

    // For now, just return a placeholder response
    // In a real system, this would fetch deposit records for the account
    return Response.json({
      success: true,
      deposits: [],
      count: 0,
      accountId
    });
  } catch (error) {
    logger.error('Deposit records retrieval error:', error);

    return Response.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}