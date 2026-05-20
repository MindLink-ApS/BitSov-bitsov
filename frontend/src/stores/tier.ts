/**
 * Tier store — tracks the user's selected sovereignty tier.
 *
 * Tiers:
 * - cloud: hosted node, easiest setup (amber banner)
 * - light: local node, hosted Lightning (green banner)
 * - full: fully sovereign (green + lock banner)
 *
 * Persisted in localStorage so the UI reflects the tier across sessions.
 */

import { createSignal } from "solid-js";
import { loadString, saveString } from "../utils/storage";

export type NodeTier = "cloud" | "light" | "full";

const TIER_KEY = "konsensus_tier";

function getStoredTier(): NodeTier {
  const stored = loadString(TIER_KEY);
  if (stored === "cloud" || stored === "light" || stored === "full") {
    return stored;
  }
  return "light";
}

const [tier, setTierSignal] = createSignal<NodeTier>(getStoredTier());

/** Update the tier and persist to localStorage. */
export function setTier(t: NodeTier): void {
  setTierSignal(t);
  saveString(TIER_KEY, t);
}

/** Tier metadata for display. */
export function tierInfo(t: NodeTier): { label: string; desc: string; sovereignty: string } {
  switch (t) {
    case "cloud":
      return {
        label: "Cloud",
        desc: "Hosted node by MindLink. Easiest setup. Your identity is yours, but data is hosted.",
        sovereignty: "Managed",
      };
    case "light":
      return {
        label: "Light Node",
        desc: "Your device, hosted Lightning. Your keys and data stay local.",
        sovereignty: "Sovereign",
      };
    case "full":
      return {
        label: "Full Node",
        desc: "Maximum sovereignty. Your keys, your Lightning channels, your chain data.",
        sovereignty: "Fully Sovereign",
      };
  }
}

export { tier };
