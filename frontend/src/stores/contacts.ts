/**
 * Contacts store — reactive list of peers whose profile has been received.
 *
 * Polls every 30 seconds and also refreshes when a KIND_CONTACT (102) or
 * KIND_PROFILE-related WebSocket envelope arrives.
 */

import { createStore, produce } from "solid-js/store";
import { api, ws } from "./auth";
import { MessageKind } from "../api/types";
import type { ContactResponse, PatchContactRequest } from "../api/types";

// ── Reactive state ────────────────────────────────────────────────────────

const [contacts, setContacts] = createStore<ContactResponse[]>([]);

export { contacts };

// ── Actions ───────────────────────────────────────────────────────────────

let _refreshing = false;

/** Fetch the full contact list from the API. No-ops if a fetch is in flight. */
export async function refreshContacts(): Promise<void> {
  if (_refreshing) return;
  _refreshing = true;
  try {
    const rows = await api.listContacts();
    setContacts(rows);
  } catch {
    // Contacts endpoint is available only after at least one profile exchange.
    // Swallow silently so the app works before any profiles are received.
  } finally {
    _refreshing = false;
  }
}

/** Patch local-only fields on a contact (alias, muted, blocked, notes, tags). */
export async function patchContact(
  nodeId: string,
  req: PatchContactRequest,
): Promise<ContactResponse | null> {
  try {
    const updated = await api.patchContact(nodeId, req);
    setContacts(
      produce((list) => {
        const idx = list.findIndex((c) => c.node_id === nodeId);
        if (idx >= 0) {
          list[idx] = updated;
        } else {
          list.push(updated);
        }
      }),
    );
    return updated;
  } catch {
    return null;
  }
}

/** Send our profile to a peer to prompt them to send theirs back. */
export async function refreshProfile(nodeId: string): Promise<boolean> {
  try {
    await api.refreshProfile(nodeId);
    // Re-poll after a short delay so the inbound profile is captured.
    setTimeout(() => void refreshContacts(), 2500);
    return true;
  } catch {
    return false;
  }
}

/** Synchronous lookup by node ID from the in-memory store. */
export function getContact(nodeId: string): ContactResponse | undefined {
  return contacts.find((c) => c.node_id === nodeId);
}

// ── Polling + WS refresh ──────────────────────────────────────────────────

/**
 * Start background polling (30 s) and WS-triggered refreshes.
 * Call once from Layout.tsx onMount after authentication succeeds.
 * Returns a cleanup function to stop polling.
 */
export function initContacts(): () => void {
  void refreshContacts();

  const interval = setInterval(() => void refreshContacts(), 30_000);

  // Subscribe to the WS — refresh when a CONTACT or profile-exchange
  // envelope arrives so the store stays current without waiting for the
  // next poll tick.
  const unsubscribeWs = ws.onMessage((envelope) => {
    if (
      envelope.kind === MessageKind.CONTACT ||
      // Profile messages are kind 950 (KEY_EXCHANGE) area; the profile handler
      // sends kind = KIND_PROFILE which we don't have as a constant in the
      // frontend yet — use a reasonable catch-all for the 900+ range where
      // profile/presence messages live.
      envelope.kind >= 900
    ) {
      void refreshContacts();
    }
  });

  return () => {
    clearInterval(interval);
    unsubscribeWs();
  };
}
