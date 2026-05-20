/**
 * PeerRow — a single row in the People (contacts) view.
 *
 * Displays ambient online/offline status with a colored dot and "last seen" text.
 * Integrates Avatar and DisplayName for a rich, sovereign identity feel.
 */

import { Show } from "solid-js";
import { PeerResponse } from "../api/types";
import { contacts } from "../stores/contacts";
import { formatRelativeTime, truncateId } from "../utils/formatting";
import { IconLock } from "./Icons";
import Avatar from "./identity/Avatar";
import DisplayName from "./identity/DisplayName";

interface PeerRowProps {
  peer: PeerResponse;
  sessionActive: boolean;
  actionLoading: boolean;
  onEdit: () => void;
  onConnect: () => void;
  onDiscover: () => void;
  onRemove: () => void;
}

export default function PeerRow(props: PeerRowProps) {
  const contact = () => contacts.find((c) => c.node_id === props.peer.node_id);
  const lastSeen = () => contact()?.updated_at;

  return (
    <div class="peer-card animate-fade-in">
      {/* Status indicator */}
      <div class="flex items-center mr-12" style={{ position: "relative" }}>
        <Avatar nodeId={props.peer.node_id} size={36} />
        <span
          class={`status-dot ${props.peer.connected ? "status-dot-online" : "status-dot-offline"}`}
          style={{
            position: "absolute",
            bottom: "-2px",
            right: "-2px",
            border: "2px solid var(--bg-primary)",
            width: "10px",
            height: "10px",
          }}
          title={props.peer.connected ? "Online" : "Offline"}
        />
      </div>

      {/* Info */}
      <div class="flex-1 min-w-0">
        <div class="flex items-center gap-8">
          <DisplayName nodeId={props.peer.node_id} class="font-medium" />
          
          <Show when={props.sessionActive}>
            <span class="badge badge-e2ee" title="E2EE session active">
              <IconLock size={10} /> E2EE
            </span>
          </Show>
          <Show when={props.peer.connected && props.peer.tier}>
            <span class="badge badge-tier" title={`Sovereignty tier: ${props.peer.tier}`}>
              {props.peer.tier}
            </span>
          </Show>
        </div>

        {/* Ambient status / ID line */}
        <div class="flex items-center gap-6 mt-2 overflow-hidden">
          <span class="mono text-xs text-muted truncate" title={props.peer.node_id}>
            {truncateId(props.peer.node_id, 12, 12)}
          </span>
          <Show when={!props.peer.connected && lastSeen()}>
            <span class="text-xs text-muted" style={{ opacity: 0.5 }}>•</span>
            <span class="text-xs text-muted whitespace-nowrap">
              Last seen {formatRelativeTime(new Date(lastSeen()!).getTime())}
            </span>
          </Show>
        </div>

        <div class="text-xs text-muted mt-2">
          {props.peer.addr}
        </div>
      </div>

      {/* Actions */}
      <div class="flex gap-6 ml-12">
        <button
          class="btn btn-secondary btn-sm"
          disabled={props.actionLoading}
          onClick={props.onEdit}
          aria-label="Edit peer"
        >
          Edit
        </button>
        <Show when={!props.peer.connected}>
          <button
            class="btn btn-secondary btn-sm"
            disabled={props.actionLoading}
            onClick={props.onConnect}
          >
            Connect
          </button>
        </Show>
        <Show when={props.peer.connected}>
          <button
            class="btn btn-secondary btn-sm"
            disabled={props.actionLoading}
            onClick={props.onDiscover}
            title="Request this peer's known peers"
            aria-label="Discover peers from this node"
          >
            Discover
          </button>
        </Show>
        <button
          class="btn btn-danger btn-sm"
          disabled={props.actionLoading}
          onClick={props.onRemove}
        >
          Remove
        </button>
      </div>
    </div>
  );
}
