export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export { listClientUsersHandler as GET } from '@/modules/identity/presentation/list-client-users.handler';
export { provisionClientUserHandler as POST } from '@/modules/identity/presentation/provision-client-user.handler';
