/**
 * The canonical form of an e-mail address for login and provisioning (E-11): trimmed, in Unicode
 * NFC and lowercase, in that order. `  Maria@Cliente.COM ` and `maria@cliente.com` are the same
 * account, for sign-in, for the per-account rate limit and for the duplicate check.
 */
export function normalizeEmail(raw: string): string {
  return raw.trim().normalize('NFC').toLowerCase();
}
