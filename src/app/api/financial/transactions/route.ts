import { NextRequest } from 'next/server';
import { TransactionEngine, RiskControls } from '../../../../../src/lib/financial-core/transaction-engine';
import { DoubleEntryLedger, TransactionType } from '../../../../../src/lib/financial-core/ledger';
import { logger } from '../../../../../src/lib/logger';
import { SecurityMonitor } from '../../../../../src/lib/security-monitoring';

export async function POST(request: NextRequest) {
  try {
    const authHeader = request.headers.get('authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return Response.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const { 
      type, 
      amount, 
      fromAccountId, 
      toAccountId, 
      description,
      referenceId 
    } = body;

    // Validate required fields
    if (!type || amount == null || !description) {
      return Response.json(
        { error: 'Missing required fields: type, amount, description' },
        { status: 400 }
      );
    }

    // Validate transaction type
    const validTypes = Object.values(TransactionType);
    if (!validTypes.includes(type as TransactionType)) {
      return Response.json(
        { error: `Invalid transaction type. Valid types: ${validTypes.join(', ')}` },
        { status: 400 }
      );
    }

    // Validate amount is positive
    if (amount <= 0) {
      return Response.json(
        { error: 'Amount must be positive' },
        { status: 400 }
      );
    }

    // Apply risk controls
    const riskControls: RiskControls = {
      dailyLimit: 1000000, // $10,000 in cents
      velocityLimit: 10,   // 10 transactions per minute
      amountThreshold: 100000 // $1,000 threshold for enhanced monitoring
    };

    // Create transaction object
    const transaction = {
      id: `txn_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      type: type as TransactionType,
      amount: amount,
      entries: [
        {
          accountId: fromAccountId,
          amount: -Math.abs(amount),
          description: `Transfer out: ${description}`
        },
        {
          accountId: toAccountId,
          amount: Math.abs(amount),
          description: `Transfer in: ${description}`
        }
      ],
      description: description,
      timestamp: Date.now(),
      userId: 'extracted_from_token', // Would come from validated token
      referenceId: referenceId,
      correlationId: `corr_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    };

    // Validate transaction integrity
    const validation = TransactionEngine.validateTransaction(transaction);
    if (!validation.valid) {
      return Response.json(
        { error: 'Transaction validation failed', details: validation.errors },
        { status: 400 }
      );
    }

    // Execute transaction with retry logic
    const result = await TransactionEngine.executeTransactionWithRetry(
      transaction,
      riskControls
    );

    if (result.success) {
      logger.info('Financial transaction processed successfully', {
        transactionId: result.transactionId,
        amount: transaction.amount,
        type: transaction.type
      });

      // Log successful transaction
      await SecurityMonitor.logAuthSuccess(
        'user_id_from_token',
        {
          ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
          userAgent: request.headers.get('user-agent') || 'unknown',
          metadata: {
            transactionId: result.transactionId,
            amount: transaction.amount,
            type: transaction.type
          }
        }
      );

      return Response.json({
        success: true,
        transactionId: result.transactionId,
        state: result.state,
        processedAt: result.processedAt
      });
    } else {
      logger.error('Financial transaction failed', {
        transactionId: transaction.id,
        error: result.error
      });

      return Response.json(
        { 
          error: 'Transaction failed',
          message: result.error || 'Unknown error'
        },
        { status: 400 }
      );
    }
  } catch (error) {
    logger.error('Financial transaction processing error', {
      error: (error as Error).message,
      stack: (error as Error).stack
    });

    return Response.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function GET(request: NextRequest) {
  try {
    const url = new URL(request.url);
    const accountId = url.searchParams.get('accountId');

    if (!accountId) {
      return Response.json(
        { error: 'accountId parameter required' },
        { status: 400 }
      );
    }

    // Get account statement
    const statement = await DoubleEntryLedger.getAccountStatement(accountId);
    
    return Response.json({
      success: true,
      accountId,
      statement,
      count: statement.length
    });
  } catch (error) {
    logger.error('Account statement retrieval error', {
      error: (error as Error).message
    });

    return Response.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}