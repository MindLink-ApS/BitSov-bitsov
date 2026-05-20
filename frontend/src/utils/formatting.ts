/**
 * Shared formatting utilities — used across all frontend components.
 *
 * Centralises truncateId, formatRelativeTime, formatDate, formatMsat, and
 * formatFileSize so that each component imports once rather than redefining
 * the same helpers inline.
 */

/**
 * Truncate a long ID for display: first `head` chars … last `tail` chars.
 * Returns the string unchanged when it is already short enough.
 */
export function truncateId(id: string, head = 8, tail = 8): string {
  if (id.length <= head + tail + 3) return id;
  return `${id.slice(0, head)}...${id.slice(-tail)}`;
}

/**
 * Format a millisecond timestamp as a human-friendly relative time string.
 * Examples: "just now" / "5m ago" / "2h ago" / "yesterday 14:30" / "Mon 09:00" / "Jan 1"
 */
export function formatRelativeTime(timestamp: number): string {
  const now = Date.now();
  const diff = now - timestamp;
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;

  const d = new Date(timestamp);
  const yesterday = new Date();
  yesterday.setDate(yesterday.getDate() - 1);

  if (d.toDateString() === yesterday.toDateString()) {
    return `yesterday ${d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
  }
  if (diff < 604_800_000) {
    return (
      d.toLocaleDateString([], { weekday: "short" }) +
      " " +
      d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    );
  }
  return d.toLocaleDateString([], { month: "short", day: "numeric" });
}

/**
 * Format a timestamp (milliseconds or Unix seconds) as a date string.
 * Today → time only ("14:30").
 * This week → weekday + time ("Mon 14:30").
 * Older → short date ("Jan 1, 2025").
 */
export function formatDate(ts: number): string {
  // Normalise Unix-second timestamps to milliseconds
  const tsMs = ts < 1e12 ? ts * 1000 : ts;
  const d = new Date(tsMs);
  const now = new Date();
  const diff = now.getTime() - tsMs;
  if (diff < 86_400_000 && d.getDate() === now.getDate()) {
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
  if (diff < 604_800_000) {
    return d.toLocaleDateString([], { weekday: "short", hour: "2-digit", minute: "2-digit" });
  }
  return d.toLocaleDateString([], { month: "short", day: "numeric", year: "numeric" });
}

export { formatMsat } from "../stores/payments";
export { formatFileSize } from "../stores/files";

// ── Identity display helpers ─────────────────────────────────────────────
// Imported lazily to avoid circular-dependency issues at module init time.
// Both `contacts` and `peers` are SolidJS reactive stores, so calling
// displayName() inside JSX automatically tracks their values.

import { contacts } from "../stores/contacts";
import { peers } from "../stores/peers";

/**
 * Resolve the best human-readable name for a node ID.
 *
 * Priority order (first match wins):
 * 1. Blocked contact  → "(Blocked)"
 * 2. Local alias      → alias string (private, never shared)
 * 3. Self-claimed name → name from peer's last received profile
 * 4. Peer label       → label stored in the peers table
 * 5. Hex fallback     → first 6 + last 4 chars, e.g. "ab12cd…ef90"
 *
 * Reactive in SolidJS: calling inside JSX or a createEffect will
 * re-run automatically when contacts or peers change.
 */
export function displayName(nodeId: string): string {
  const contact = contacts.find((c) => c.node_id === nodeId);
  if (contact?.blocked) return "(Blocked)";
  if (contact?.local_alias) return contact.local_alias;
  if (contact?.claimed_name) return contact.claimed_name;
  const peer = peers.find((p) => p.node_id === nodeId);
  if (peer?.label) return peer.label;
  return truncateId(nodeId, 6, 4);
}

/**
 * Like displayName, but appends the last 4 hex chars of the node ID when
 * two contacts would otherwise resolve to the same visible string.
 * Example: "Maya (0dc0)"
 *
 * Only compares against the contacts list (peers without a contact record
 * are unlikely to share names and are expensive to scan for collisions).
 */
export function disambiguateName(nodeId: string): string {
  const name = displayName(nodeId);
  const collision = contacts.some(
    (c) => c.node_id !== nodeId && displayName(c.node_id) === name,
  );
  return collision ? `${name} (${nodeId.slice(-4)})` : name;
}
