import { NextResponse } from 'next/server';
import { getAccessToken } from '@/lib/cookies';
import { verifyAccessToken } from '@/lib/tokenUtils';

export async function GET() {
  const token = await getAccessToken();
  if (!token) {
    return NextResponse.json({ loggedIn: false }, { status: 200 });
  }

  const payload = verifyAccessToken(token);
  if (!payload) {
    return NextResponse.json({ loggedIn: false, shouldLogout: true }, { status: 401 });
  }

  return NextResponse.json(
    {
      loggedIn: true,
      user: {
        id: payload.userId,
        email: payload.email,
        tenantId: payload.tenantId,
        walletAddress: payload.walletAddress,
        role: payload.role,
        authMethod: payload.authMethod,
      },
    },
    { status: 200 }
  );
}

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
