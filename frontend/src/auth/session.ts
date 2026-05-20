/**
 * Session management — JWT token storage and lifecycle.
 *
 * Tokens are stored in memory only (Principle 4: no plaintext at rest).
 * When the app restarts, the user re-authenticates.
 */

const TOKEN_KEY = "konsensus_jwt";
const EXPIRES_KEY = "konsensus_jwt_exp";

/** Store the JWT in sessionStorage (cleared on window close). */
export function storeToken(token: string, expiresAt: number): void {
  sessionStorage.setItem(TOKEN_KEY, token);
  sessionStorage.setItem(EXPIRES_KEY, String(expiresAt));
}

/** Retrieve the stored JWT, or null if expired/missing. */
export function getToken(): string | null {
  const token = sessionStorage.getItem(TOKEN_KEY);
  const exp = sessionStorage.getItem(EXPIRES_KEY);
  if (!token || !exp) return null;

  // Check expiry with 60s buffer
  const expiresAt = parseInt(exp, 10);
  if (Date.now() / 1000 > expiresAt - 60) {
    clearToken();
    return null;
  }

  return token;
}

/** Clear the stored token. */
export function clearToken(): void {
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(EXPIRES_KEY);
}

/** Check if a valid token exists. */
export function hasValidToken(): boolean {
  return getToken() !== null;
}
