import { NextRequest } from 'next/server';
import { AlertManager } from '../../../../../src/lib/monitoring/alert-manager';

// Initialize alert manager
const alertManager = new AlertManager();

// GET /api/admin/monitoring/alerts - List active alerts
export async function GET(request: NextRequest) {
  try {
    // Extract query parameters
    const url = new URL(request.url);
    const page = parseInt(url.searchParams.get('page') || '1');
    const limit = parseInt(url.searchParams.get('limit') || '50');
    const severity = url.searchParams.get('severity') as 'INFO' | 'WARN' | 'HIGH' | 'CRITICAL' | null;
    const status = url.searchParams.get('status') as 'active' | 'acknowledged' | 'resolved' | null;

    // Get alerts based on filters
    let alerts;
    if (status === 'active') {
      alerts = await alertManager.getActiveAlerts();
    } else {
      alerts = await alertManager.getAlerts(page, limit, severity || undefined);
    }

    // Filter by status if specified
    if (status && status !== 'active') {
      alerts = alerts.filter(alert => {
        switch (status) {
          case 'acknowledged': return alert.acknowledged === true;
          case 'resolved': return alert.resolved === true;
          default: return true;
        }
      });
    }

    // Get alert statistics
    const stats = await alertManager.getAlertStats();

    return Response.json({
      success: true,
      data: alerts,
      pagination: {
        page,
        limit,
        total: stats.total,
        totalPages: Math.ceil(stats.total / limit)
      },
      stats
    });
  } catch (error) {
    console.error('[MONITORING_API] Error fetching alerts:', error);
    return Response.json(
      { 
        success: false, 
        error: 'Failed to fetch alerts',
        message: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    );
  }
}

// POST /api/admin/monitoring/alerts/:id/acknowledge - Acknowledge alert
export async function POST(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    // Extract alert ID from URL
    const url = new URL(request.url);
    const pathParts = url.pathname.split('/');
    const alertId = pathParts[pathParts.length - 2]; // Get the ID from the URL

    // Extract user info from request (in a real implementation, this would come from auth)
    // For now, we'll use a placeholder
    const userData = await request.json().catch(() => ({}));
    const acknowledgedBy = userData.userEmail || 'system';

    // Acknowledge the alert
    const success = await alertManager.acknowledgeAlert(alertId, acknowledgedBy);

    if (!success) {
      return Response.json(
        { 
          success: false, 
          error: 'Alert not found' 
        },
        { status: 404 }
      );
    }

    // Get the updated alert
    const updatedAlert = await alertManager.getAlertById(alertId);

    return Response.json({
      success: true,
      data: updatedAlert
    });
  } catch (error) {
    console.error('[MONITORING_API] Error acknowledging alert:', error);
    return Response.json(
      { 
        success: false, 
        error: 'Failed to acknowledge alert',
        message: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    );
  }
}

// POST /api/admin/monitoring/alerts/:id/resolve - Resolve alert
export async function PATCH(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    // Extract alert ID from URL
    const url = new URL(request.url);
    const pathParts = url.pathname.split('/');
    const alertId = pathParts[pathParts.length - 2]; // Get the ID from the URL

    // Extract user info from request (in a real implementation, this would come from auth)
    const userData = await request.json().catch(() => ({}));
    const resolvedBy = userData.userEmail || 'system';

    // Resolve the alert
    const success = await alertManager.resolveAlert(alertId, resolvedBy);

    if (!success) {
      return Response.json(
        { 
          success: false, 
          error: 'Alert not found' 
        },
        { status: 404 }
      );
    }

    // Get the updated alert
    const updatedAlert = await alertManager.getAlertById(alertId);

    return Response.json({
      success: true,
      data: updatedAlert
    });
  } catch (error) {
    console.error('[MONITORING_API] Error resolving alert:', error);
    return Response.json(
      { 
        success: false, 
        error: 'Failed to resolve alert',
        message: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    );
  }
}

// GET /api/admin/monitoring/dashboard - Security dashboard data
export async function OPTIONS(request: NextRequest) {
  // Handle CORS preflight
  return new Response(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PATCH, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    },
  });
}