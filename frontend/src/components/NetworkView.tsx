/**
 * Network — Mesh explorer, peer directory, chain data, and node identity.
 * Pulls data from the node's health, pricing, and peer APIs.
 * Chain data is sourced through the node's configured ChainProvider.
 */

import { createSignal, onMount, onCleanup, Show, For, createMemo } from "solid-js";
import { peers } from "../stores/peers";
import { refreshPeers } from "../stores/peers";
import { nodeId, api } from "../stores/auth";
import { balance, formatMsat, refreshBalance } from "../stores/payments";
import type { HealthResponse, PeerPricingResponse, NodePricingInfo } from "../api/types";
import {
  IconNetwork,
  IconGlobe,
  IconPeers,
  IconLightning,
  IconShield,
  IconRefresh,
  IconCopy,
  IconActivity,
  IconClock,
  IconHash,
  IconLock,
} from "./Icons";
import { toast } from "../stores/toast";

// ── Types ──────────────────────────────────────────────────────────────

interface ChainData {
  blockHeight: number;
  blockHash: string;
  feeRateFast: number;   // sat/vB
  feeRateMedium: number;
  feeRateSlow: number;
  mempoolSize: number;    // tx count
  mempoolVSize: number;   // vbytes
  difficulty: number;
  hashrate: number;       // EH/s estimate
}

// ── Helpers ────────────────────────────────────────────────────────────

function truncId(id: string, head = 8, tail = 4): string {
  if (id.length <= head + tail + 3) return id;
  return `${id.slice(0, head)}...${id.slice(-tail)}`;
}

function formatUptime(secs: number): string {
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function formatNumber(n: number): string {
  if (n >= 1_000_000_000) return (n / 1_000_000_000).toFixed(1) + "B";
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 1_000) return (n / 1_000).toFixed(1) + "K";
  return n.toLocaleString();
}

function formatHashrate(h: number): string {
  if (h >= 1e18) return (h / 1e18).toFixed(1) + " EH/s";
  if (h >= 1e15) return (h / 1e15).toFixed(1) + " PH/s";
  if (h >= 1e12) return (h / 1e12).toFixed(1) + " TH/s";
  return h.toFixed(0) + " H/s";
}

function formatDifficulty(d: number): string {
  if (d >= 1e12) return (d / 1e12).toFixed(2) + "T";
  if (d >= 1e9) return (d / 1e9).toFixed(2) + "G";
  return formatNumber(d);
}

function epochProgress(blockHeight: number): number {
  return ((blockHeight % 2016) / 2016) * 100;
}

function halvingProgress(blockHeight: number): number {
  return ((blockHeight % 210000) / 210000) * 100;
}

function nextHalvingBlock(blockHeight: number): number {
  return (Math.floor(blockHeight / 210000) + 1) * 210000;
}

// ── Mesh Visualization (CSS-based) ────────────────────────────────────

function MeshVisualization(props: { health: HealthResponse | null; peerCount: number }) {
  const myId = () => nodeId() ?? "";

  return (
    <div class="network-mesh-viz">
      {/* Central node */}
      <div class="mesh-node mesh-node-self" title={`You: ${myId()}`}>
        <div class="mesh-node-pulse" />
        <div class="mesh-node-core">
          <IconShield size={20} />
        </div>
        <div class="mesh-node-label">You</div>
      </div>

      {/* Connected peers orbiting */}
      <For each={peers.filter(p => p.connected).slice(0, 6)}>
        {(peer, i) => {
          const angle = () => (i() * 360) / Math.min(peers.filter(p => p.connected).length, 6);
          const radius = 90;
          const x = () => Math.cos((angle() - 90) * Math.PI / 180) * radius;
          const y = () => Math.sin((angle() - 90) * Math.PI / 180) * radius;
          return (
            <>
              {/* Connection line */}
              <svg class="mesh-line mesh-line-container">
                <line
                  x1="0" y1="0"
                  x2={x()} y2={y()}
                  stroke="var(--accent)"
                  stroke-width="1"
                  stroke-opacity="0.4"
                  stroke-dasharray="4 2"
                />
              </svg>
              {/* Peer node */}
              <div
                class="mesh-node mesh-node-peer"
                style={{
                  transform: `translate(${x()}px, ${y()}px)`,
                }}
                title={peer.label ?? peer.node_id}
              >
                <div class="mesh-node-core mesh-node-core-peer">
                  <IconPeers size={14} />
                </div>
                <div class="mesh-node-label">
                  {peer.label ?? truncId(peer.node_id, 4, 3)}
                </div>
              </div>
            </>
          );
        }}
      </For>

      {/* Disconnected peers (faded) */}
      <Show when={peers.filter(p => !p.connected).length > 0}>
        <div class="mesh-disconnected-count">
          {peers.filter(p => !p.connected).length} offline
        </div>
      </Show>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────

export default function NetworkView() {
  const [health, setHealth] = createSignal<HealthResponse | null>(null);
  const [chainData, setChainData] = createSignal<ChainData | null>(null);
  const [pricing, setPricing] = createSignal<NodePricingInfo | null>(null);
  const [peerPricing, setPeerPricing] = createSignal<PeerPricingResponse[]>([]);
  const [loading, setLoading] = createSignal(true);
  const [chainLoading, setChainLoading] = createSignal(false);

  let refreshInterval: ReturnType<typeof setInterval>;

  async function fetchHealth() {
    try {
      const h = await api.health();
      setHealth(h);
    } catch (e) {
      console.warn("Health fetch failed:", e);
    }
  }

  async function fetchChainData() {
    setChainLoading(true);
    try {
      // Fetch chain data from the node backend (proxied through ChainProvider).
      const baseUrl = api.getBaseUrl();
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 15000);
      const res = await fetch(`${baseUrl}/api/v1/chain/status`, { signal: controller.signal });
      clearTimeout(timeout);

      if (res.ok) {
        const data = await res.json();
        setChainData({
          blockHeight: data.block_height ?? 0,
          blockHash: "",
          feeRateFast: Math.round(data.fee_rate_fast ?? 0),
          feeRateMedium: Math.round(data.fee_rate_medium ?? 0),
          feeRateSlow: Math.round(data.fee_rate_slow ?? 0),
          mempoolSize: 0,
          mempoolVSize: 0,
          difficulty: 0,
          hashrate: 0,
        });
        if (!data.available) {
          console.warn("Chain data unavailable:", data.error);
        }
      } else {
        console.warn("Chain status endpoint returned:", res.status);
        setChainData(null);
      }
    } catch (e) {
      console.warn("Chain data fetch failed:", e);
      setChainData(null);
    } finally {
      setChainLoading(false);
    }
  }

  async function fetchPricing() {
    try {
      const data = await api.pricing();
      setPricing(data);
    } catch (e) {
      console.warn("Pricing fetch failed:", e);
    }
  }

  async function fetchPeerPricing() {
    try {
      const data = await api.peerPricing();
      setPeerPricing(data);
    } catch (e) {
      console.warn("Peer pricing fetch failed:", e);
    }
  }

  async function refreshAll() {
    setLoading(true);
    await Promise.allSettled([
      fetchHealth(),
      fetchChainData(),
      fetchPricing(),
      fetchPeerPricing(),
      refreshPeers(),
      refreshBalance(),
    ]);
    setLoading(false);
  }

  onMount(() => {
    refreshAll();
    // Refresh chain data every 60 seconds
    refreshInterval = setInterval(() => {
      fetchHealth();
      fetchChainData();
    }, 60_000);
  });

  onCleanup(() => clearInterval(refreshInterval));

  const connectedPeers = createMemo(() => peers.filter(p => p.connected));
  const totalPeers = createMemo(() => peers.length);

  const copyNodeId = () => {
    const id = nodeId();
    if (id) {
      navigator.clipboard.writeText(id).then(() => {
        toast.success("Node ID copied");
      }).catch(() => {
        /* Clipboard unavailable */
      });
    }
  };

  return (
    <div class="page content-max">
      {/* Header */}
      <div class="page-header">
        <h2 class="page-title flex items-center gap-8">
          <IconNetwork size={20} /> Network
        </h2>
        <button
          class="btn btn-ghost btn-sm"
          onClick={refreshAll}
          disabled={loading()}
          title="Refresh network data"
        >
          <IconRefresh size={14} />
        </button>
      </div>

      {/* Mesh Visualization */}
      <div class="card network-viz-card mb-16">
        <div class="card-header flex items-center gap-8">
          <IconGlobe size={16} /> Mesh Topology
        </div>
        <div class="flex items-center justify-center py-16">
          <MeshVisualization health={health()} peerCount={connectedPeers().length} />
        </div>
        <div class="network-mesh-stats">
          <div class="network-stat-mini">
            <span class="text-xs text-muted">Connected</span>
            <span class="text-sm font-semibold">{connectedPeers().length}</span>
          </div>
          <div class="network-stat-mini">
            <span class="text-xs text-muted">Total Peers</span>
            <span class="text-sm font-semibold">{totalPeers()}</span>
          </div>
          <Show when={health()}>
            <div class="network-stat-mini">
              <span class="text-xs text-muted">Encrypted Conversations</span>
              <span class="text-sm font-semibold">{health()!.e2ee_sessions}</span>
            </div>
            <div class="network-stat-mini">
              <span class="text-xs text-muted">Uptime</span>
              <span class="text-sm font-semibold">{formatUptime(health()!.uptime_secs)}</span>
            </div>
          </Show>
        </div>
      </div>

      {/* Two-column layout: Peer Directory + Node Identity */}
      <div class="network-grid">
        {/* Peer Directory */}
        <div class="card" style={{ "min-height": "200px" }}>
          <div class="card-header flex items-center gap-8">
            <IconPeers size={16} /> Peer Directory
          </div>
          <Show when={peers.length > 0} fallback={
            <div class="empty-state-compact">
              <span class="text-sm text-muted">No peers configured</span>
            </div>
          }>
            <div class="network-peer-list">
              <For each={peers}>
                {(peer) => (
                  <div class="network-peer-item">
                    <span class={`status-dot ${peer.connected ? "status-dot-online" : "status-dot-offline"}`} />
                    <div class="network-peer-info">
                      <div class="text-sm font-semibold">
                        {peer.label ?? truncId(peer.node_id)}
                      </div>
                      <div class="text-xs text-muted mono">
                        {truncId(peer.node_id, 12, 6)}
                      </div>
                    </div>
                    <div class="network-peer-status">
                      <span class={`network-peer-badge ${peer.connected ? "badge-online" : "badge-offline"}`}>
                        {peer.connected ? "Online" : "Offline"}
                      </span>
                    </div>
                  </div>
                )}
              </For>
            </div>
          </Show>
        </div>

        {/* Node Identity Card */}
        <div class="card">
          <div class="card-header flex items-center gap-8">
            <IconShield size={16} /> Node Identity
          </div>
          <div class="network-identity">
            {/* Avatar */}
            <div class="network-identity-avatar">
              {(nodeId() ?? "??").slice(0, 2).toUpperCase()}
            </div>

            {/* Node ID */}
            <div class="network-identity-row">
              <span class="text-xs text-muted">Node ID</span>
              <button class="network-id-copy" onClick={copyNodeId} title="Copy full Node ID">
                <span class="mono text-xs">{truncId(nodeId() ?? "", 16, 8)}</span>
                <IconCopy size={12} />
              </button>
            </div>

            {/* Stats */}
            <div class="network-identity-stats">
              <Show when={health()}>
                <div class="network-identity-stat">
                  <IconLock size={14} />
                  <span class="text-xs">Encrypted: {health()!.e2ee_sessions} conversations</span>
                </div>
                <div class="network-identity-stat">
                  <IconLightning size={14} />
                  <span class="text-xs">
                    Lightning: {health()!.lightning_payment_capable ? "Active" : health()!.lightning_available ? "Receive Only" : "Unavailable"}
                  </span>
                </div>
                <div class="network-identity-stat">
                  <IconClock size={14} />
                  <span class="text-xs">Uptime: {formatUptime(health()!.uptime_secs)}</span>
                </div>
              </Show>
              <Show when={balance() !== null}>
                <div class="network-identity-stat">
                  <IconLightning size={14} class="text-accent" />
                  <span class="text-xs text-accent">{formatMsat(balance()!)}</span>
                </div>
              </Show>
            </div>

            {/* Pending deliveries warning */}
            <Show when={health() && health()!.pending_deliveries > 0}>
              <div class="network-pending-warning">
                <IconActivity size={14} />
                <span class="text-xs">{health()!.pending_deliveries} messages being sent</span>
              </div>
            </Show>
          </div>
        </div>
      </div>

      {/* Chain Data Panel */}
      <div class="card mt-16">
        <div class="card-header flex items-center justify-between">
          <div class="flex items-center gap-8">
            <IconHash size={16} /> Bitcoin Chain Data
          </div>
          <Show when={chainLoading()}>
            <span class="text-xs text-muted">Updating...</span>
          </Show>
        </div>

        <Show when={chainData()} fallback={
          <div class="empty-state-compact">
            <span class="text-sm text-muted">
              {chainLoading() ? "Loading chain data..." : "Chain data unavailable — check node connection"}
            </span>
          </div>
        }>
          {(data) => (
            <Show when={data().blockHeight > 0} fallback={
              <div class="empty-state-compact">
                <span class="text-sm text-muted">Chain data unavailable — block height is zero</span>
              </div>
            }>
            <>
              {/* Block + Fee stats */}
              <div class="network-chain-grid">
                <div class="network-chain-stat">
                  <span class="network-chain-value">{formatNumber(data().blockHeight)}</span>
                  <span class="text-xs text-muted">Block Height</span>
                </div>
                <div class="network-chain-stat">
                  <span class="network-chain-value text-accent">{data().feeRateFast}</span>
                  <span class="text-xs text-muted">Fast Fee Rate</span>
                </div>
                <div class="network-chain-stat">
                  <span class="network-chain-value">{data().feeRateMedium}</span>
                  <span class="text-xs text-muted">Medium Fee Rate</span>
                </div>
                <div class="network-chain-stat">
                  <span class="network-chain-value">{data().feeRateSlow}</span>
                  <span class="text-xs text-muted">Economy Fee Rate</span>
                </div>
              </div>

              {/* Mempool */}
              <div class="network-chain-section">
                <div class="text-xs text-muted mb-6">Mempool</div>
                <div class="network-chain-grid">
                  <div class="network-chain-stat">
                    <span class="network-chain-value">{formatNumber(data().mempoolSize)}</span>
                    <span class="text-xs text-muted">Transactions</span>
                  </div>
                  <div class="network-chain-stat">
                    <span class="network-chain-value">{formatNumber(Math.round(data().mempoolVSize / 1_000_000))}</span>
                    <span class="text-xs text-muted">MvB</span>
                  </div>
                  <Show when={data().difficulty > 0}>
                    <div class="network-chain-stat">
                      <span class="network-chain-value">{formatDifficulty(data().difficulty)}</span>
                      <span class="text-xs text-muted">Difficulty</span>
                    </div>
                  </Show>
                  <Show when={data().hashrate > 0}>
                    <div class="network-chain-stat">
                      <span class="network-chain-value">{formatHashrate(data().hashrate)}</span>
                      <span class="text-xs text-muted">Hashrate</span>
                    </div>
                  </Show>
                </div>
              </div>

              {/* Epoch progress bars */}
              <div class="network-chain-section">
                <div class="network-epoch-row">
                  <span class="text-xs text-muted">Difficulty Epoch</span>
                  <span class="text-xs text-secondary">{data().blockHeight % 2016} / 2016</span>
                </div>
                <div class="network-progress-bar">
                  <div class="network-progress-fill" style={{ width: `${epochProgress(data().blockHeight)}%` }} />
                </div>
                <div class="network-epoch-row mt-8">
                  <span class="text-xs text-muted">Halving Epoch</span>
                  <span class="text-xs text-secondary">
                    {formatNumber(nextHalvingBlock(data().blockHeight) - data().blockHeight)} blocks remaining
                  </span>
                </div>
                <div class="network-progress-bar">
                  <div class="network-progress-fill network-progress-fill-halving" style={{ width: `${halvingProgress(data().blockHeight)}%` }} />
                </div>
              </div>
            </>
            </Show>
          )}
        </Show>

        <div class="network-chain-footer">
          <span class="text-xs text-muted">Chain data proxied through your node (no browser CORS needed)</span>
        </div>
      </div>

      {/* Node Pricing Info */}
      <Show when={pricing()}>
        {(p) => (
          <div class="card mt-16">
            <div class="card-header flex items-center gap-8">
              <IconLightning size={16} /> Message Costs
            </div>
            <div class="text-xs text-muted mb-12">
              Cost per message type — deducted from your Lightning balance when you send
            </div>
            <div class="network-pricing-grid">
              <div class="network-chain-stat">
                <span class="network-chain-value capitalize">{p().mode}</span>
                <span class="text-xs text-muted">Mode</span>
              </div>
              <div class="network-chain-stat">
                <span class="network-chain-value">{p().trust_level?.replace("_", " ") ?? "N/A"}</span>
                <span class="text-xs text-muted">Trust Level</span>
              </div>
              <Show when={p().ema_fee_rate != null}>
                <div class="network-chain-stat">
                  <span class="network-chain-value text-accent">{(p().ema_fee_rate ?? 0).toFixed(1)}</span>
                  <span class="text-xs text-muted">EMA Fee Rate</span>
                </div>
              </Show>
              <Show when={p().raw_fee_rate != null}>
                <div class="network-chain-stat">
                  <span class="network-chain-value">{(p().raw_fee_rate ?? 0).toFixed(1)}</span>
                  <span class="text-xs text-muted">Raw Fee Rate</span>
                </div>
              </Show>
            </div>
            {/* Category prices */}
            <Show when={Object.keys(p().prices).length > 0}>
              <div class="network-chain-section">
                <div class="text-xs text-muted mb-6">Message Prices</div>
                <div class="network-price-list">
                  <For each={Object.entries(p().prices)}>
                    {([cat, price]) => (
                      <div class="network-price-item">
                        <span class="text-xs capitalize">{cat.replace("_", " ")}</span>
                        <span class="text-xs mono text-accent">{formatMsat(price as number)}</span>
                      </div>
                    )}
                  </For>
                </div>
              </div>
            </Show>
          </div>
        )}
      </Show>

      {/* Peer Pricing Tables */}
      <Show when={peerPricing().length > 0}>
        <div class="card mt-16">
          <div class="card-header flex items-center gap-8">
            <IconPeers size={16} /> Network Rates
          </div>
          <div class="network-peer-pricing-list">
            <For each={peerPricing()}>
              {(pp) => {
                const peerLabel = () => {
                  const p = peers.find((p) => p.node_id === pp.peer_id);
                  return p?.label ?? truncId(pp.peer_id);
                };
                return (
                  <div class="network-peer-pricing-item">
                    <div class="network-peer-pricing-header">
                      <span class="text-sm font-semibold">{peerLabel()}</span>
                      <div class="flex items-center gap-8">
                        <span class="text-xs text-muted">
                          Block #{formatNumber(pp.block_height)}
                        </span>
                        <span class={`badge ${pp.stale ? "badge-warning" : "badge-success"}`}>
                          {pp.stale ? "Stale" : "Fresh"}
                        </span>
                        <span class="text-xs text-muted">
                          {pp.age_secs < 60 ? "<1m ago" :
                           pp.age_secs < 3600 ? `${Math.floor(pp.age_secs / 60)}m ago` :
                           `${Math.floor(pp.age_secs / 3600)}h ago`}
                        </span>
                      </div>
                    </div>
                    <div class="network-peer-pricing-prices">
                      <For each={Object.entries(pp.prices)}>
                        {([cat, price]) => (
                          <div class="network-price-item">
                            <span class="text-xs capitalize">{cat.replace("_", " ")}</span>
                            <span class="text-xs mono text-accent">{formatMsat(price)}</span>
                          </div>
                        )}
                      </For>
                    </div>
                  </div>
                );
              }}
            </For>
          </div>
        </div>
      </Show>
    </div>
  );
}
