/**
 * TrustIndicator — Shield-Bolt trust badge component.
 *
 * 3 states:
 * - sovereign: green shield + lock icon (full sovereign node, E2EE verified)
 * - encrypted: blue shield + bolt icon (E2EE active, not fully sovereign)
 * - unverified: gray shield + warning icon (no E2EE session)
 */

import { Show } from "solid-js";

export type TrustLevel = "sovereign" | "encrypted" | "unverified";

interface TrustIndicatorProps {
  level: TrustLevel;
  /** Compact mode — icon only, no label. Default: false */
  compact?: boolean;
}

const TRUST_CONFIG = {
  sovereign: {
    label: "Sovereign",
    description: "End-to-end encrypted, fully sovereign node",
    colorClass: "trust-sovereign",
  },
  encrypted: {
    label: "Encrypted",
    description: "End-to-end encrypted connection",
    colorClass: "trust-encrypted",
  },
  unverified: {
    label: "Unverified",
    description: "No active E2EE session",
    colorClass: "trust-unverified",
  },
};

function ShieldIcon(props: { level: TrustLevel }) {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      {/* Shield outline */}
      <path
        d="M8 1L2 3.5V7.5C2 11.08 4.56 14.34 8 15C11.44 14.34 14 11.08 14 7.5V3.5L8 1Z"
        fill="currentColor"
        opacity="0.15"
        stroke="currentColor"
        stroke-width="1.2"
        stroke-linejoin="round"
      />
      {/* Inner icon */}
      <Show when={props.level === "sovereign"}>
        {/* Lock */}
        <rect x="6" y="7.5" width="4" height="3.5" rx="0.5" fill="currentColor" opacity="0.8" />
        <path d="M7 7.5V6.5C7 5.67 7.45 5 8 5C8.55 5 9 5.67 9 6.5V7.5" stroke="currentColor" stroke-width="1" fill="none" />
      </Show>
      <Show when={props.level === "encrypted"}>
        {/* Lightning bolt */}
        <path d="M9 4L6.5 8.5H8L7 12L10 7.5H8.2L9 4Z" fill="currentColor" opacity="0.9" />
      </Show>
      <Show when={props.level === "unverified"}>
        {/* Warning mark */}
        <path d="M8 5.5V8.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" />
        <circle cx="8" cy="10.5" r="0.7" fill="currentColor" />
      </Show>
    </svg>
  );
}

export default function TrustIndicator(props: TrustIndicatorProps) {
  const config = () => TRUST_CONFIG[props.level];

  return (
    <span
      class={`trust-indicator ${config().colorClass}`}
      title={config().description}
      aria-label={config().description}
    >
      <ShieldIcon level={props.level} />
      <Show when={!props.compact}>
        <span class="trust-label">{config().label}</span>
      </Show>
    </span>
  );
}
