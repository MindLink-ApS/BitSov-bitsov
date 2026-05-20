/** Tier selection cards — used in onboarding Step 0.
 *
 * Three cards (Relay / Light / Full) with descriptions and sovereignty levels.
 * The selected tier is stored in the tier store and drives banner color + defaults.
 */

import { For } from "solid-js";
import type { NodeTier } from "../stores/tier";
import { tier, setTier } from "../stores/tier";
import { IconGlobe, IconShield, IconLock } from "./Icons";
import type { JSX } from "solid-js";

interface TierOption {
  id: NodeTier;
  icon: (p?: Record<string, unknown>) => JSX.Element;
  title: string;
  subtitle: string;
  features: string[];
  recommended?: boolean;
}

const TIERS: TierOption[] = [
 {
    id: "cloud",
    icon: IconGlobe,
    title: "Relay",
    subtitle: "Paired remote access",
    features: [
      "Reachability without operator-held keys",
      "Your identity keys stay on your device",
      "Relay stores ciphertext only",
      "Upgrade to Light or Full anytime",
    ],
  },
  {
    id: "light",
    icon: IconShield,
    title: "Light Node",
    subtitle: "Your device, your provider",
    features: [
      "Your keys never leave your device",
      "Your data stored locally",
      "Configure LDK, LNbits, or another provider",
      "Recommended for most users",
    ],
    recommended: true,
  },
  {
    id: "full",
    icon: IconLock,
    title: "Full Node",
    subtitle: "Maximum sovereignty",
    features: [
      "Your keys, your Lightning channels",
      "Your own chain data (Esplora)",
      "Encrypted storage by default",
      "Complete independence from MindLink",
    ],
  },
];

export default function TierSelection() {
  return (
    <div class="tier-selection">
      <For each={TIERS}>
        {(t) => (
          <button
            class={`tier-card ${tier() === t.id ? "tier-card-selected" : ""} ${t.recommended ? "tier-card-recommended" : ""}`}
            onClick={() => setTier(t.id)}
          >
            {t.recommended && <div class="tier-recommended-badge">Recommended</div>}
            <div class="tier-card-icon">{t.icon({ size: 28 })}</div>
            <div class="tier-card-title">{t.title}</div>
            <div class="tier-card-subtitle">{t.subtitle}</div>
            <ul class="tier-card-features">
              <For each={t.features}>
                {(f) => <li>{f}</li>}
              </For>
            </ul>
            <div class={`tier-card-indicator ${tier() === t.id ? "active" : ""}`}>
              {tier() === t.id ? "Selected" : "Select"}
            </div>
          </button>
        )}
      </For>
    </div>
  );
}
