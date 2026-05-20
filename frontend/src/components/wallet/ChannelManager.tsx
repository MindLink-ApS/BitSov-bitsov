/**
 * ChannelManager — Lightning channel list with close/force-close controls
 * and per-channel stats (uptime, routed volume, fees earned).
 *
 * Used by the Wallet view to render the "Payment Routes" section.
 */

import {
  createSignal,
  For,
  Show,
  createResource,
  type Accessor,
} from "solid-js";
import { api } from "../../stores/auth";
import { toast } from "../../stores/toast";
import { formatMsat } from "../../stores/payments";
import type { ChannelResponse, ChannelStatsResponse } from "../../api/types";
import {
  IconX,
  IconWarning,
  IconActivity,
  IconClock,
} from "../Icons";

// ─── Helpers ───────────────────────────────────────────────────────────────

function formatUptime(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
  return `${Math.floor(secs / 86400)}d ${Math.floor((secs % 86400) / 3600)}h`;
}

// ─── Close Confirm Modal ───────────────────────────────────────────────────

interface CloseModalProps {
  channel: ChannelResponse;
  onConfirm: (force: boolean) => Promise<void>;
  onCancel: () => void;
}

function CloseModal(props: CloseModalProps) {
  const [force, setForce] = createSignal(false);
  const [closing, setClosing] = createSignal(false);

  async function handleConfirm() {
    setClosing(true);
    try {
      await props.onConfirm(force());
    } finally {
      setClosing(false);
    }
  }

  return (
    <div
      class="modal-backdrop"
      onClick={(e) => { if (e.target === e.currentTarget) props.onCancel(); }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="close-channel-title"
    >
      <div class="modal-panel card" style={{ "max-width": "420px", width: "100%" }}>
        <div class="card-header flex items-center justify-between">
          <span id="close-channel-title" class="icon-text font-medium">
            <IconWarning size={16} style={{ color: "var(--warning)" }} />
            Close Channel
          </span>
          <button class="btn btn-ghost btn-sm" onClick={props.onCancel} aria-label="Cancel">
            <IconX size={14} />
          </button>
        </div>

        <div class="flex-col gap-12" style={{ padding: "0 0 4px" }}>
          {/* Channel identity */}
          <div class="text-sm text-muted">
            <div class="mono text-xs break-all mb-4">{props.channel.peer_pubkey}</div>
            <Show when={props.channel.short_channel_id}>
              <div class="text-xs">SCID: {props.channel.short_channel_id}</div>
            </Show>
            <div class="text-xs mt-4">Capacity: {formatMsat(props.channel.capacity_msat)}</div>
          </div>

          {/* Force-close toggle */}
          <label
            class="flex items-center gap-8 text-sm"
            style={{
              padding: "10px 12px",
              background: force() ? "var(--warning-dim)" : "var(--bg-secondary)",
              border: `1px solid ${force() ? "var(--warning)" : "var(--border)"}`,
              "border-radius": "var(--radius-sm)",
              cursor: "pointer",
              "user-select": "none",
            }}
          >
            <input
              type="checkbox"
              checked={force()}
              onChange={(e) => setForce(e.currentTarget.checked)}
              style={{ "flex-shrink": "0" }}
            />
            <span>
              <span class="font-medium" style={{ color: force() ? "var(--warning)" : undefined }}>
                Force close
              </span>
              <span class="text-muted" style={{ "font-size": "11px", display: "block", "margin-top": "2px" }}>
                {force()
                  ? "Broadcasts unilateral on-chain close immediately. Funds locked for CSV timelock period."
                  : "Sends cooperative close request to peer. Settles on-chain when peer confirms."}
              </span>
            </span>
          </label>

          {/* Action buttons */}
          <div class="flex gap-8 justify-end">
            <button class="btn btn-ghost btn-sm" onClick={props.onCancel} disabled={closing()}>
              Cancel
            </button>
            <button
              class={`btn btn-sm ${force() ? "btn-danger" : "btn-primary"}`}
              onClick={handleConfirm}
              disabled={closing()}
            >
              {closing()
                ? (force() ? "Force closing..." : "Closing...")
                : (force() ? "Force Close" : "Close Channel")}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Channel Stats Row ─────────────────────────────────────────────────────

interface ChannelStatsRowProps {
  channelId: string;
}

function ChannelStatsRow(props: ChannelStatsRowProps) {
  const [stats] = createResource<ChannelStatsResponse | null, string>(
    () => props.channelId,
    async (id: string) => {
      try {
        return await api.getChannelStats(id);
      } catch {
        return null;
      }
    }
  );

  return (
    <Show when={stats() !== undefined}>
      <div
        class="channel-stats-row flex gap-16 text-xs text-muted"
        style={{ "margin-top": "6px", "padding-top": "6px", "border-top": "1px solid var(--border)" }}
      >
        <Show
          when={!stats.loading && stats() !== null}
          fallback={
            <Show when={stats.loading}>
              <span style={{ color: "var(--text-muted)" }}>Loading stats...</span>
            </Show>
          }
        >
          <span class="icon-text" style={{ gap: "4px" }}>
            <IconClock size={11} />
            {formatUptime(stats()!.uptime_secs)}
          </span>
          <span class="icon-text" style={{ gap: "4px" }}>
            <IconActivity size={11} />
            {formatMsat(stats()!.routed_volume_msat)} routed
          </span>
          <span style={{ color: "var(--success)" }}>
            +{formatMsat(stats()!.fees_earned_msat)} fees
          </span>
        </Show>
      </div>
    </Show>
  );
}

// ─── Channel Item ──────────────────────────────────────────────────────────

interface ChannelItemProps {
  channel: ChannelResponse;
  onClosed: (channelId: string) => void;
}

function ChannelItem(props: ChannelItemProps) {
  const [showModal, setShowModal] = createSignal(false);

  const total = () => props.channel.capacity_msat || 1;
  const localPct = () => Math.round((props.channel.local_balance_msat / total()) * 100);

  async function handleClose(force: boolean) {
    try {
      await api.closeChannel(props.channel.channel_id, force);
      toast.success(force ? "Force-close broadcast" : "Cooperative close initiated");
      setShowModal(false);
      props.onClosed(props.channel.channel_id);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to close channel");
      throw err; // keep modal open via re-throw
    }
  }

  return (
    <>
      <div class="channel-item">
        {/* Header row: status + SCID + capacity + close button */}
        <div class="channel-item-header">
          <div class="flex items-center gap-8">
            <span class={`status-dot ${props.channel.active ? "status-dot-online" : "status-dot-offline"}`} />
            <span class="text-sm font-medium">
              {props.channel.active ? "Active" : "Inactive"}
            </span>
            <Show when={props.channel.short_channel_id}>
              <span class="text-xs text-muted">{props.channel.short_channel_id}</span>
            </Show>
          </div>
          <div class="flex items-center gap-8">
            <span class="text-sm text-accent">{formatMsat(props.channel.capacity_msat)}</span>
            <button
              class="btn btn-ghost btn-sm"
              style={{ padding: "2px 6px", "font-size": "11px", color: "var(--text-muted)" }}
              onClick={() => setShowModal(true)}
              title="Close channel"
              aria-label="Close channel"
            >
              Close
            </button>
          </div>
        </div>

        {/* Peer pubkey */}
        <div class="channel-item-pubkey">
          {props.channel.peer_pubkey.slice(0, 16)}...{props.channel.peer_pubkey.slice(-8)}
        </div>

        {/* Capacity bar */}
        <div class="channel-capacity-bar" title={`Local: ${localPct()}%`}>
          <div class="channel-capacity-local" style={{ width: `${localPct()}%` }} />
        </div>

        {/* Balance labels */}
        <div class="channel-capacity-labels">
          <span>Local: {formatMsat(props.channel.local_balance_msat)}</span>
          <span>Remote: {formatMsat(props.channel.remote_balance_msat)}</span>
        </div>

        {/* Stats row */}
        <ChannelStatsRow channelId={props.channel.channel_id} />
      </div>

      {/* Close confirm modal */}
      <Show when={showModal()}>
        <CloseModal
          channel={props.channel}
          onConfirm={handleClose}
          onCancel={() => setShowModal(false)}
        />
      </Show>
    </>
  );
}

// ─── ChannelManager ────────────────────────────────────────────────────────

export interface ChannelManagerProps {
  channels: Accessor<ChannelResponse[]>;
  onChannelClosed?: (channelId: string) => void;
}

export default function ChannelManager(props: ChannelManagerProps) {
  // Track optimistically removed channels (closed) so they disappear immediately
  const [closedIds, setClosedIds] = createSignal<Set<string>>(new Set());

  function handleClosed(channelId: string) {
    setClosedIds((prev) => new Set([...prev, channelId]));
    props.onChannelClosed?.(channelId);
  }

  const visibleChannels = () =>
    props.channels().filter((ch) => !closedIds().has(ch.channel_id));

  return (
    <div class="channel-list">
      <For each={visibleChannels()}>
        {(ch) => <ChannelItem channel={ch} onClosed={handleClosed} />}
      </For>
    </div>
  );
}
