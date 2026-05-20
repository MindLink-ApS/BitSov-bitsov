/**
 * WalletDetails — Collapsible drawer for Lightning channel state,
 * routing stats, and message pricing.
 */

import { For, Show, type Accessor } from "solid-js";
import { formatMsat } from "../stores/payments";
import type { HealthResponse, ChannelResponse } from "../api/types";
import {
  IconX,
  IconLightning,
  IconArrowDown,
  IconArrowUpRight,
  IconClock,
  IconActivity,
  IconNetwork,
} from "./Icons";
import ChannelManager from "./wallet/ChannelManager";

interface PriceEntry {
  label: string;
  kind: number;
  price: number | null;
}

interface WalletDetailsProps {
  isOpen: boolean;
  onClose: () => void;
  health: HealthResponse | null;
  channels: Accessor<ChannelResponse[]>;
  prices: PriceEntry[];
  totalReceived: number;
  totalSent: number;
  transactionCount: number;
  refreshChannels: () => Promise<void>;
}

export default function WalletDetails(props: WalletDetailsProps) {
  return (
    <Show when={props.isOpen}>
      <div
        class="modal-backdrop"
        onClick={(e) => { if (e.target === e.currentTarget) props.onClose(); }}
        style={{ "z-index": "100" }}
      >
        <div
          class="modal-panel card animate-slide-in-right"
          style={{
            "max-width": "480px",
            width: "100%",
            height: "100%",
            "margin-left": "auto",
            "border-radius": "0",
            overflow: "auto",
            display: "flex",
            "flex-direction": "column",
          }}
        >
          <div class="card-header flex items-center justify-between" style={{ padding: "16px 20px" }}>
            <h3 class="text-lg font-semibold">Wallet Details</h3>
            <button class="btn btn-ghost btn-sm" onClick={props.onClose} aria-label="Close details">
              <IconX size={18} />
            </button>
          </div>

          <div class="flex-1" style={{ padding: "0 20px 20px" }}>
            {/* Stats row */}
            <div class="grid grid-cols-2 gap-12 mb-24">
              <div class="card" style={{ padding: "12px", background: "var(--bg-secondary)" }}>
                <div class="text-xs text-muted mb-4 icon-text">
                  <IconArrowDown size={14} style={{ color: "var(--success)" }} /> Received
                </div>
                <div class="text-sm font-medium">{formatMsat(props.totalReceived)}</div>
              </div>
              <div class="card" style={{ padding: "12px", background: "var(--bg-secondary)" }}>
                <div class="text-xs text-muted mb-4 icon-text">
                  <IconArrowUpRight size={14} style={{ color: "var(--accent)" }} /> Sent
                </div>
                <div class="text-sm font-medium">{formatMsat(props.totalSent)}</div>
              </div>
              <div class="card" style={{ padding: "12px", background: "var(--bg-secondary)" }}>
                <div class="text-xs text-muted mb-4 icon-text">
                  <IconNetwork size={14} /> Channels
                </div>
                <div class="text-sm font-medium">{props.channels().length} active</div>
              </div>
              <div class="card" style={{ padding: "12px", background: "var(--bg-secondary)" }}>
                <div class="text-xs text-muted mb-4 icon-text">
                  <IconLightning size={14} /> Node Status
                </div>
                <div class="text-sm font-medium">
                  <span class={`badge ${props.health?.lightning_payment_capable ? "badge-success" : props.health?.lightning_available ? "badge-warning" : "badge-error"}`}>
                    {props.health?.lightning_payment_capable ? "Active" : props.health?.lightning_available ? "Receive Only" : "N/A"}
                  </span>
                </div>
              </div>
            </div>

            {/* Message Costs */}
            <div class="section-label mb-8">Message Costs</div>
            <div class="card mb-24" style={{ padding: "4px 0" }}>
              <For each={props.prices}>
                {(entry) => (
                  <div class="wallet-price-row" style={{ padding: "8px 12px" }}>
                    <span class="text-sm">{entry.label}</span>
                    <span class="text-sm font-medium text-accent">
                      {entry.price !== null ? formatMsat(entry.price) : "N/A"}
                    </span>
                  </div>
                )}
              </For>
            </div>

            {/* Lightning Channels */}
            <div class="section-label mb-8 icon-text">
              <IconNetwork size={14} /> Payment Routes
            </div>
            <div class="card" style={{ padding: "4px" }}>
              <Show
                when={props.channels().length > 0}
                fallback={
                  <div class="text-sm text-muted text-center" style={{ padding: "16px 0" }}>
                    {props.health?.lightning_available
                      ? props.health?.lightning_payment_capable ? "No channel data available" : "Wallet cannot send payments — fund your wallet"
                      : "Lightning node not connected"}
                  </div>
                }
              >
                <ChannelManager channels={props.channels} onChannelClosed={() => void props.refreshChannels()} />
              </Show>
            </div>
          </div>
        </div>
      </div>
    </Show>
  );
}
