/**
 * Avatar — circular avatar with image (from avatar_blake3) or initials fallback.
 */

import { Show } from "solid-js";
import { contacts } from "../../stores/contacts";
import { api } from "../../stores/auth";
import { displayName } from "../../utils/formatting";

interface AvatarProps {
  nodeId: string;
  /** Diameter in px (default: 32). */
  size?: number;
  class?: string;
}

/** Derive 1–2 initials from the best available display name. */
function initials(nodeId: string): string {
  const name = displayName(nodeId);
  // Blocked or hex fallback → use "?"
  if (name.startsWith("(")) return "?";
  const parts = name.trim().split(/\s+/);
  if (parts.length >= 2) {
    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  }
  return name.slice(0, 2).toUpperCase();
}

export default function Avatar(props: AvatarProps) {
  const size = () => props.size ?? 32;
  const contact = () => contacts.find((c) => c.node_id === props.nodeId);

  const avatarUrl = () => {
    const hash = contact()?.avatar_blake3;
    if (!hash) return null;
    return `${api.getBaseUrl()}/api/v1/avatars/${hash}`;
  };

  return (
    <div
      class={`avatar${props.class ? ` ${props.class}` : ""}`}
      style={{
        width: `${size()}px`,
        height: `${size()}px`,
        "min-width": `${size()}px`,
        "border-radius": "50%",
        overflow: "hidden",
        display: "flex",
        "align-items": "center",
        "justify-content": "center",
        background: "var(--color-surface-raised, #2a2a3a)",
        "font-size": `${Math.round(size() * 0.38)}px`,
        "font-weight": "600",
        color: "var(--color-accent, #7c5af0)",
        "user-select": "none",
      }}
      title={displayName(props.nodeId)}
    >
      <Show
        when={avatarUrl()}
        fallback={<span aria-hidden="true">{initials(props.nodeId)}</span>}
      >
        {(url) => (
          <img
            src={url()}
            alt=""
            style={{ width: "100%", height: "100%", "object-fit": "cover" }}
            onError={(e) => {
              // Hide broken image; initials fallback is rendered in the Show fallback.
              (e.currentTarget as HTMLImageElement).style.display = "none";
            }}
          />
        )}
      </Show>
    </div>
  );
}
