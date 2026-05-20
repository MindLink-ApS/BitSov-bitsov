/**
 * Per-peer reaction policy store.
 *
 * Persists to localStorage. When `hideReactions` is true for a peer,
 * the ReactionStrip is hidden for messages from that peer.
 */

import { createSignal } from "solid-js";
import { loadJSON, saveJSON } from "../utils/storage";

const REACTION_POLICY_KEY = "bitsov_reaction_policies";

interface ReactionPolicies {
  /** peer node_id → whether reactions are hidden */
  hideReactions: Record<string, boolean>;
}

function loadPolicies(): ReactionPolicies {
  return loadJSON<ReactionPolicies>(REACTION_POLICY_KEY, { hideReactions: {} });
}

function savePolicies(policies: ReactionPolicies): void {
  saveJSON(REACTION_POLICY_KEY, policies);
}

/** Reactive signal holding the current policies. */
const [reactionPolicies, setReactionPolicies] = createSignal<ReactionPolicies>(loadPolicies());

/** Returns true if reactions should be hidden for messages from this peer. */
export function getHideReactions(peerId: string): boolean {
  return reactionPolicies().hideReactions[peerId] ?? false;
}

/** Set or clear the hide-reactions flag for a peer. Persists to localStorage. */
export function setHideReactions(peerId: string, hide: boolean): void {
  const updated: ReactionPolicies = {
    hideReactions: { ...reactionPolicies().hideReactions, [peerId]: hide },
  };
  setReactionPolicies(updated);
  savePolicies(updated);
}
