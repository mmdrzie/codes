import { verifySessionCookie } from '@/lib/sessionUtils';

export function withTenantGuard(handler: Function) {
  return async (req: Request, ctx: any) => {
    const cookie = req.headers
      .get('cookie')
      ?.match(/__session=([^;]+)/)?.[1];

    const user = cookie ? await verifySessionCookie(cookie) : null;

    if (!user) {
      return new Response('Unauthorized', { status: 401 });
    }

    if (ctx.params?.tenantId && ctx.params.tenantId !== user.tenantId) {
      return new Response('Forbidden', { status: 403 });
    }

    return handler(req, ctx, user);
  };
}
