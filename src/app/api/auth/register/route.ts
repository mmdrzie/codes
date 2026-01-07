import { NextRequest, NextResponse } from 'next/server';
import { registerSchema } from '@/lib/validation';
import { hashPassword } from '@/lib/security';
import { generateTokenPair } from '@/lib/tokenUtils';
import { setAuthCookies } from '@/lib/cookies';
import { checkRateLimit, getIdentifier } from '@/lib/rateLimit';
import { getClientIp, getUserAgent } from '@/lib/helpers';
import { createSession } from '@/lib/sessionUtils';
import { getAdminDb } from '@/lib/firebase';

export async function POST(request: NextRequest) {
  const identifier = getIdentifier(request);
  const rl = checkRateLimit(identifier, 'register');
  if (!rl.allowed) {
    return NextResponse.json({ error: rl.message || 'Rate limit exceeded', resetAt: rl.resetAt }, { status: 429 });
  }

  const body = await request.json();
  const validation = registerSchema.safeParse(body);
  if (!validation.success) {
    return NextResponse.json(
      {
        error: 'Invalid input',
        details: validation.error.issues.map((e) => ({ field: e.path.join('.'), message: e.message })),
      },
      { status: 400 }
    );
  }

  const { email, password } = validation.data;

  const db = getAdminDb();

  // Check existing user
  const existing = await db.collection('users').where('email', '==', email).limit(1).get();
  if (!existing.empty) {
    // Do not reveal whether email exists
    return NextResponse.json({ error: 'Unable to create account' }, { status: 400 });
  }

  const passwordHash = await hashPassword(password);

  const userDoc = {
    email,
    passwordHash,
    status: 'active',
    authMethod: 'password',
    createdAt: new Date(),
    updatedAt: new Date(),
    lastLogin: new Date(),
    lastLoginIp: getClientIp(request),
    failedLoginAttempts: 0,
  };

  const ref = await db.collection('users').add(userDoc);
  const userId = ref.id;

  const tokens = generateTokenPair({
    userId,
    tenantId: undefined,
    email,
    authMethod: 'password',
    role: 'user',
  });

  const sessionId = createSession(userId, undefined, {
    ipAddress: getClientIp(request),
    userAgent: getUserAgent(request),
  });

  const response = NextResponse.json(
    {
      success: true,
      user: { id: userId, email },
      expiresIn: tokens.expiresIn,
    },
    { status: 201 }
  );

  await setAuthCookies(tokens.accessToken, tokens.refreshToken, sessionId, response);
  return response;
}

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
