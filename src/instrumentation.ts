// Next.js calls register() once per server instance, before it serves requests.
// Failing here makes a misconfigured deploy crash at boot instead of at the first request,
// and keeps `next build` independent of runtime env.
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME !== 'nodejs') return;
  const { getEnv } = await import('@/shared/config/env');
  getEnv();
}
