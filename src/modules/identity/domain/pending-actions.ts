// The rule itself lives in the kernel, because the HTTP pipeline's principal resolver needs it too
// and `shared/` may not import a module. Identity's domain exposes it under its own name.
export { computePendingActions, type PendingActionsInput } from '@/shared/kernel';
