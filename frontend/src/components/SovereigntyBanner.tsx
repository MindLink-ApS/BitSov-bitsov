/** Sovereignty banner — persistent indicator of the user's tier.
 *
 * - Cloud: amber banner — "Managed by MindLink"
 * - Light: green banner — "Sovereign"
 * - Full: green + lock icon — "Fully Sovereign"
 *
 * Shown below the connection banner in the main content area.
 * Clicking it navigates to Settings where the user can change tier.
 */

import { Show } from "solid-js";
import { tier, tierInfo } from "../stores/tier";
import { IconGlobe, IconShield, IconLock } from "./Icons";

export default function SovereigntyBanner() {
  const info = () => tierInfo(tier());
  const currentTier = () => tier();

  return (
    <div
      class={`sovereignty-banner sovereignty-banner-${currentTier()}`}
      title={`Sovereignty tier: ${info().label} — ${info().sovereignty}`}
    >
      <span class="sovereignty-banner-icon">
        <Show when={currentTier() === "cloud"}>
          <IconGlobe size={12} />
        </Show>
        <Show when={currentTier() === "light"}>
          <IconShield size={12} />
        </Show>
        <Show when={currentTier() === "full"}>
          <IconLock size={12} />
        </Show>
      </span>
      <span class="sovereignty-banner-text">{info().sovereignty}</span>
      <Show when={currentTier() === "cloud"}>
        <span class="sovereignty-banner-hint">Upgrade in Settings</span>
      </Show>
    </div>
  );
}
