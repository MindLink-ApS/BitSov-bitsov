/**
 * Safe localStorage wrappers.
 *
 * All functions swallow storage errors (quota exceeded, private-browsing
 * restrictions, etc.) so callers never need inline try/catch blocks.
 */

/** JSON-parse a stored value; returns `fallback` on any error or absence. */
export function loadJSON<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw !== null ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

/** JSON-stringify and store a value; silently ignores quota errors. */
export function saveJSON<T>(key: string, value: T): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Quota exceeded or storage unavailable
  }
}

/** Load a raw string value; returns `null` if the key is absent or on error. */
export function loadString(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

/** Store a raw string value; silently ignores errors. */
export function saveString(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    // Storage unavailable
  }
}

/** Remove a key; silently ignores errors. */
export function removeItem(key: string): void {
  try {
    localStorage.removeItem(key);
  } catch {
    // Storage unavailable
  }
}
