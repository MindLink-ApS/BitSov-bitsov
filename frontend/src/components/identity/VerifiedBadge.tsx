/**
 * VerifiedBadge — small checkmark badge indicating the number of verified
 * external identity claims (domain, GitHub, etc.) on a contact's profile.
 */

interface VerifiedBadgeProps {
  /** Array of verified_identities from ContactResponse. */
  identities: unknown[];
  class?: string;
}

export default function VerifiedBadge(props: VerifiedBadgeProps) {
  const count = () => props.identities.length;
  const label = () =>
    `${count()} verified identity claim${count() !== 1 ? "s" : ""}`;

  return (
    <span
      class={`verified-badge${props.class ? ` ${props.class}` : ""}`}
      title={label()}
      aria-label={label()}
      style={{
        display: "inline-flex",
        "align-items": "center",
        "justify-content": "center",
        width: "14px",
        height: "14px",
        "border-radius": "50%",
        background: "var(--color-success, #22c55e)",
        color: "#fff",
        "font-size": "9px",
        "font-weight": "700",
        "vertical-align": "middle",
        "margin-left": "4px",
        "flex-shrink": "0",
      }}
      aria-hidden="false"
    >
      ✓
    </span>
  );
}
