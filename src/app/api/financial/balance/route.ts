import { NextRequest } from 'next/server';
import { FinancialCore } from '../../../../src/lib/financial-core';
import { logger } from '../../../../src/lib/logger';

// Balance response interface
interface BalanceResponse {
  success: boolean;
  accountId?: string;
  balance?: number;
  error?: string;
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

    const clientIp = request.headers.get('x-forwarded-for') || 'unknown';
    const userAgent = request.headers.get('user-agent') || 'unknown';

    // Extract account ID from query params
    const url = new URL(request.url);
    const accountId = url.searchParams.get('accountId');

    if (!accountId) {
      return Response.json(
        { success: false, error: 'Account ID required' },
        { status: 400 }
      );
    }

    // Validate account ID format (basic validation)
    if (!/^[a-zA-Z0-9_-]+$/.test(accountId)) {
      return Response.json(
        { success: false, error: 'Invalid account ID format' },
        { status: 400 }
      );
    }

    // Get balance (in a real system, you would validate the user has permission to access this account)
    const balance = await FinancialCore.getBalance(accountId, 'user_id_from_token', clientIp);

    if (balance) {
      const response: BalanceResponse = {
        success: true,
        accountId: balance.accountId,
        balance: balance.currentBalance
      };

      logger.info('Balance retrieved successfully', {
        accountId,
        balance: balance.currentBalance,
        userId: 'user_id_from_token'
      });

      return Response.json(response);
    } else {
      return Response.json(
        { success: false, error: 'Account not found' },
        { status: 404 }
      );
    }
  } catch (error) {
    logger.error('Balance retrieval error:', error);
    
    return Response.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
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

    const body = await request.json();
    const { accountId } = body;

    if (!accountId) {
      return Response.json(
        { success: false, error: 'Account ID required' },
        { status: 400 }
      );
    }

    // Validate account ID format (basic validation)
    if (!/^[a-zA-Z0-9_-]+$/.test(accountId)) {
      return Response.json(
        { success: false, error: 'Invalid account ID format' },
        { status: 400 }
      );
    }

    // Get balance
    const balance = await FinancialCore.getBalance(accountId, 'user_id_from_token', request.headers.get('x-forwarded-for') || 'unknown');

    if (balance) {
      const response: BalanceResponse = {
        success: true,
        accountId: balance.accountId,
        balance: balance.currentBalance
      };

      return Response.json(response);
    } else {
      return Response.json(
        { success: false, error: 'Account not found' },
        { status: 404 }
      );
    }
  } catch (error) {
    logger.error('Balance retrieval error:', error);
    
    return Response.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}