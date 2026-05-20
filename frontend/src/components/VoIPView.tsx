/**
 * VoIP — Sovereign peer-to-peer calling interface.
 * Preview view: full UI rendered but call initiation disabled.
 * Uses KIND_REALTIME_SIGNAL (400–499) range when backend is ready.
 *
 * Architecture notes:
 * - Calls are payment-gated (per-minute Lightning micro-payments)
 * - All signaling is E2EE over the node's existing transport layer
 * - No central server: peer nodes negotiate directly via mesh
 */

import { createSignal, Show, For, onCleanup, createEffect } from "solid-js";
import { peers } from "../stores/peers";
import type { PeerResponse } from "../api/types";
import {
  IconPhone,
  IconUser,
  IconClock,
  IconX,
  IconPreview,
  IconMic,
  IconMicOff,
  IconVideo,
  IconVideoOff,
  IconPhoneIncoming,
  IconPhoneOutgoing,
  IconPhoneMissed,
} from "./Icons";
import { formatRelativeTime } from "../utils/formatting";

// ── Types ──────────────────────────────────────────────────────────────

type CallDirection = "incoming" | "outgoing";
type CallState = "idle" | "ringing" | "active" | "ended";

interface CallHistoryEntry {
  id: string;
  peerId: string;
  peerLabel: string;
  direction: CallDirection;
  durationSecs: number | null;   // null = missed
  timestamp: number;
}

// ── Mock Data ──────────────────────────────────────────────────────────

const MOCK_HISTORY: CallHistoryEntry[] = [
  {
    id: "h1",
    peerId: "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12",
    peerLabel: "Alice",
    direction: "incoming",
    durationSecs: 312,
    timestamp: Date.now() - 1_800_000,
  },
  {
    id: "h2",
    peerId: "bb22dd44ff66bb22dd44ff66bb22dd44ff66bb22dd44ff66bb22dd44ff66bb22",
    peerLabel: "Bob",
    direction: "outgoing",
    durationSecs: 74,
    timestamp: Date.now() - 3_600_000,
  },
  {
    id: "h3",
    peerId: "cc33ee55aa77cc33ee55aa77cc33ee55aa77cc33ee55aa77cc33ee55aa77cc33",
    peerLabel: "node-beta",
    direction: "incoming",
    durationSecs: null,
    timestamp: Date.now() - 7_200_000,
  },
  {
    id: "h4",
    peerId: "dd44ff66bb88dd44ff66bb88dd44ff66bb88dd44ff66bb88dd44ff66bb88dd44",
    peerLabel: "Carol",
    direction: "outgoing",
    durationSecs: 1820,
    timestamp: Date.now() - 86_400_000,
  },
];

// ── Helpers ────────────────────────────────────────────────────────────

function truncId(id: string, head = 8, tail = 4): string {
  if (id.length <= head + tail + 3) return id;
  return `${id.slice(0, head)}...${id.slice(-tail)}`;
}

function peerInitials(peer: PeerResponse | null, fallback = "??"): string {
  if (!peer) return fallback.toUpperCase();
  const src = peer.label ?? peer.node_id;
  return src.slice(0, 2).toUpperCase();
}

function formatDuration(secs: number): string {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  if (h > 0) return `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  return `${m}:${String(s).padStart(2, "0")}`;
}


// ── Active Call Panel ──────────────────────────────────────────────────

function ActiveCallPanel(props: {
  peer: PeerResponse | null;
  peerLabel: string;
  muted: boolean;
  videoEnabled: boolean;
  callSeconds: number;
  onToggleMute: () => void;
  onToggleVideo: () => void;
  onHangUp: () => void;
}) {
  return (
    <div class="voip-active-call animate-fade-in-scale">
      {/* Peer avatar */}
      <div class="voip-call-avatar-wrap">
        <div class="voip-call-avatar">
          {peerInitials(props.peer, props.peerLabel)}
        </div>
        <div class="voip-call-avatar-ring" />
      </div>

      {/* Peer name + duration */}
      <div class="voip-call-info">
        <div class="voip-call-peer-name">
          {props.peer?.label ?? props.peerLabel}
        </div>
        <div class="voip-call-meta">
          <span class="voip-call-state-dot" />
          <span class="text-sm text-success">{formatDuration(props.callSeconds)}</span>
        </div>
        <div class="text-xs text-muted mt-2">
          {truncId(props.peer?.node_id ?? "", 12, 6)}
        </div>
      </div>

      {/* Preview notice */}
      <div class="voip-preview-notice">
        <IconPreview size={12} />
        Preview — call signaling via KIND_REALTIME_SIGNAL (400–499) not yet active
      </div>

      {/* Call controls */}
      <div class="voip-call-controls">
        <button
          class={`voip-ctrl-btn ${props.muted ? "voip-ctrl-active" : ""}`}
          onClick={props.onToggleMute}
          title={props.muted ? "Unmute" : "Mute"}
          aria-label={props.muted ? "Unmute microphone" : "Mute microphone"}
        >
          {props.muted
            ? <IconMicOff size={20} />
            : <IconMic size={20} />
          }
          <span class="voip-ctrl-label">{props.muted ? "Unmute" : "Mute"}</span>
        </button>

        <button
          class="voip-ctrl-btn voip-ctrl-end"
          onClick={props.onHangUp}
          title="End call"
          aria-label="End call"
        >
          <IconPhone size={22} style={{ transform: "rotate(135deg)" }} />
          <span class="voip-ctrl-label">End</span>
        </button>

        <button
          class={`voip-ctrl-btn ${!props.videoEnabled ? "voip-ctrl-active" : ""}`}
          onClick={props.onToggleVideo}
          title={props.videoEnabled ? "Turn off camera" : "Turn on camera"}
          aria-label={props.videoEnabled ? "Disable video" : "Enable video"}
        >
          {props.videoEnabled
            ? <IconVideo size={20} />
            : <IconVideoOff size={20} />
          }
          <span class="voip-ctrl-label">{props.videoEnabled ? "Video" : "No Video"}</span>
        </button>
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────

export default function VoIPView() {
  const [callState, setCallState] = createSignal<CallState>("idle");
  const [activePeerId, setActivePeerId] = createSignal<string | null>(null);
  const [muted, setMuted] = createSignal(false);
  const [videoEnabled, setVideoEnabled] = createSignal(false);
  const [callSeconds, setCallSeconds] = createSignal(0);

  let callTimer: ReturnType<typeof setInterval> | undefined;

  // Tick the call timer when a call is active
  createEffect(() => {
    if (callState() === "active") {
      callTimer = setInterval(() => {
        setCallSeconds(s => s + 1);
      }, 1_000);
    } else {
      if (callTimer !== undefined) {
        clearInterval(callTimer);
        callTimer = undefined;
      }
      if (callState() === "idle") {
        setCallSeconds(0);
      }
    }
  });

  onCleanup(() => {
    if (callTimer !== undefined) clearInterval(callTimer);
  });

  const activePeer = () =>
    peers.find(p => p.node_id === activePeerId()) ?? null;

  // Preview: simulate call initiation (no real backend call)
  const handleCall = (peer: PeerResponse) => {
    setActivePeerId(peer.node_id);
    setMuted(false);
    setVideoEnabled(false);
    setCallSeconds(0);
    // Simulate "ringing" then "connected" after 1.5 s
    setCallState("ringing");
    setTimeout(() => setCallState("active"), 1_500);
  };

  const handleHangUp = () => {
    setCallState("ended");
    setTimeout(() => {
      setCallState("idle");
      setActivePeerId(null);
    }, 800);
  };

  const peerLabelFor = (peerId: string): string => {
    const found = peers.find(p => p.node_id === peerId);
    return found?.label ?? truncId(peerId, 8, 4);
  };

  return (
    <div class="page voip-page content-max">
      {/* Header */}
      <div class="page-header">
        <h2 class="page-title flex items-center gap-8">
          <IconPhone size={20} /> Calling
          <span class="preview-badge">
            <IconPreview size={10} /> Preview
          </span>
        </h2>
      </div>

      {/* Active / Ringing Call Panel */}
      <Show when={callState() !== "idle"}>
        <div class="card voip-active-card mb-16">
          <Show
            when={callState() === "active"}
            fallback={
              <div class="voip-ringing animate-fade-in">
                <div class="voip-ringing-avatar">
                  {peerInitials(activePeer(), peerLabelFor(activePeerId() ?? ""))}
                </div>
                <div class="voip-ringing-label">
                  {activePeer()?.label ?? peerLabelFor(activePeerId() ?? "")}
                </div>
                <div class="text-sm text-muted">
                  {callState() === "ringing" ? "Ringing..." : "Call ended"}
                </div>
                <Show when={callState() === "ringing"}>
                  <button
                    class="btn btn-danger btn-sm mt-12"
                    onClick={handleHangUp}
                  >
                    <IconX size={14} /> Cancel
                  </button>
                </Show>
              </div>
            }
          >
            <ActiveCallPanel
              peer={activePeer()}
              peerLabel={peerLabelFor(activePeerId() ?? "")}
              muted={muted()}
              videoEnabled={videoEnabled()}
              callSeconds={callSeconds()}
              onToggleMute={() => setMuted(m => !m)}
              onToggleVideo={() => setVideoEnabled(v => !v)}
              onHangUp={handleHangUp}
            />
          </Show>
        </div>
      </Show>

      {/* Contacts / Call List */}
      <div class="card mb-16">
        <div class="card-header flex items-center gap-8">
          <IconUser size={16} /> Peers
        </div>

        <Show
          when={peers.length > 0}
          fallback={
            <div class="empty-state-compact">
              <div class="text-center">
                <div style={{ opacity: "0.35" }} class="mb-8">
                  <IconUser size={36} />
                </div>
                <div class="text-sm text-muted">No peers configured</div>
                <div class="text-xs text-muted mt-4">
                  Add peers in Settings to start calling
                </div>
              </div>
            </div>
          }
        >
          <div class="voip-peer-list">
            <For each={peers}>
              {(peer) => (
                <div class="voip-peer-item">
                  {/* Avatar */}
                  <div class="voip-peer-avatar">
                    {peerInitials(peer)}
                  </div>

                  {/* Identity */}
                  <div class="voip-peer-info">
                    <div class="text-sm font-semibold">
                      {peer.label ?? truncId(peer.node_id, 10, 5)}
                    </div>
                    <div class="text-xs text-muted mono">
                      {truncId(peer.node_id, 12, 6)}
                    </div>
                  </div>

                  {/* Status */}
                  <div class="voip-peer-status">
                    <span
                      class={`status-dot ${peer.connected ? "status-dot-online" : "status-dot-offline"}`}
                    />
                    <span class="text-xs text-muted">
                      {peer.connected ? "Online" : "Offline"}
                    </span>
                  </div>

                  {/* Call button — disabled in preview */}
                  <div
                    title="Preview — coming soon. Call initiation requires KIND_REALTIME_SIGNAL backend."
                    class="cursor-not-allowed"
                  >
                    <button
                      class="voip-call-btn pointer-events-none"
                      disabled={true}
                      aria-label={`Call ${peer.label ?? peer.node_id}`}
                    >
                      <IconPhone size={15} />
                      <span>Call</span>
                    </button>
                  </div>
                </div>
              )}
            </For>
          </div>
        </Show>
      </div>

      {/* Call History */}
      <div class="card">
        <div class="card-header flex items-center gap-8">
          <IconClock size={16} /> Recent Calls
          <span class="text-xs text-muted ml-auto" style={{ "font-weight": "400", "text-transform": "none", "letter-spacing": "0" }}>
            Mock data — preview
          </span>
        </div>

        <div class="voip-history-list">
          <For each={MOCK_HISTORY}>
            {(entry) => {
              const isMissed = entry.durationSecs === null;
              const isIncoming = entry.direction === "incoming";

              return (
                <div class={`voip-history-item ${isMissed ? "voip-history-missed" : ""}`}>
                  {/* Direction icon */}
                  <div class="voip-history-icon">
                    {isMissed
                      ? <IconPhoneMissed size={16} class="text-error" />
                      : isIncoming
                        ? <IconPhoneIncoming size={16} class="text-success" />
                        : <IconPhoneOutgoing size={16} class="text-secondary" />
                    }
                  </div>

                  {/* Peer info */}
                  <div class="voip-history-info">
                    <div class="text-sm font-semibold">
                      {entry.peerLabel}
                    </div>
                    <div class="text-xs text-muted">
                      {isMissed
                        ? "Missed call"
                        : `${isIncoming ? "Incoming" : "Outgoing"} · ${formatDuration(entry.durationSecs!)}`
                      }
                    </div>
                  </div>

                  {/* Timestamp */}
                  <div class="voip-history-time">
                    <span class="text-xs text-muted">{formatRelativeTime(entry.timestamp)}</span>
                  </div>

                  {/* Callback button — disabled in preview */}
                  <div
                    title="Preview — coming soon"
                    class="cursor-not-allowed"
                  >
                    <button
                      class="voip-history-call-btn pointer-events-none"
                      disabled={true}
                      aria-label={`Call back ${entry.peerLabel}`}
                    >
                      <IconPhone size={13} />
                    </button>
                  </div>
                </div>
              );
            }}
          </For>
        </div>
      </div>

      {/* Footer note */}
      <div class="text-xs text-muted text-center mt-16" style={{ "padding-bottom": "8px" }}>
        Calls are payment-gated via Lightning micro-payments. All signaling is E2EE over your node's transport layer.
      </div>
    </div>
  );
}
