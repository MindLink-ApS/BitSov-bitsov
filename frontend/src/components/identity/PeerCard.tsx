/**
 * PeerCard — compact card showing avatar, display name, connection status,
 * and verified-identity badge for a peer node.
 */

import { Show } from "solid-js";
import { peers } from "../../stores/peers";
import { contacts } from "../../stores/contacts";
import { disambiguateName } from "../../utils/formatting";
import { truncateId } from "../../utils/formatting";
import Avatar from "./Avatar";
import DisplayName from "./DisplayName";
import VerifiedBadge from "./VerifiedBadge";

interface PeerCardProps {
  nodeId: string;
  /** Compact mode: smaller avatar, no node ID line. Default: false. */
  compact?: boolean;
  class?: string;
}

export default function PeerCard(props: PeerCardProps) {
  const peer = () => peers.find((p) => p.node_id === props.nodeId);
  const contact = () => contacts.find((c) => c.node_id === props.nodeId);
  const verifiedIds = () => {
    const ids = contact()?.verified_identities;
    return Array.isArray(ids) && ids.length > 0 ? ids : null;
  };

  // disambiguateName so two contacts named "Maya" show as "Maya (0dc0)"
  const name = () => disambiguateName(props.nodeId);

  const avatarSize = () => (props.compact ? 28 : 40);

  return (
    <div
      class={`peer-card${props.compact ? " peer-card-compact" : ""}${props.class ? ` ${props.class}` : ""}`}
      style={{
        display: "flex",
        "align-items": "center",
        gap: "8px",
      }}
    >
      <Avatar nodeId={props.nodeId} size={avatarSize()} />

      <div style={{ flex: 1, "min-width": 0 }}>
        <div
          style={{
            display: "flex",
            "align-items": "center",
            gap: "4px",
          }}
        >
          <DisplayName nodeId={props.nodeId} class="truncate text-sm font-medium" />
          <Show when={verifiedIds()}>
            {(ids) => <VerifiedBadge identities={ids()} />}
          </Show>
        </div>
        <Show when={!props.compact}>
          <div
            class="mono text-xs text-muted truncate"
            title={props.nodeId}
          >
            {truncateId(props.nodeId)}
          </div>
        </Show>
      </div>

      {/* Connection status dot */}
      <Show when={peer()}>
        {(p) => (
          <span
            class={`status-dot ${p().connected ? "status-dot-online" : "status-dot-offline"}`}
            title={p().connected ? "Online" : "Offline"}
            style={{ "flex-shrink": "0" }}
          />
        )}
      </Show>
    </div>
  );
}
