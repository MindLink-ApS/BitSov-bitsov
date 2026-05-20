/**
 * DiscoveryView — find nodes, content, and peers through the sovereign mesh.
 *
 * Tabs:
 *   Feed          — chronological announces from subscribed nodes
 *   Search        — full-text search with price + capability filters
 *   Endorsements  — nodes my peers vouch for, with provenance trail + whitelist workflow
 *   Subscriptions — active subscriptions with budget tracking and delivery-mode management
 *
 * NOTE: Feed, Search, Endorsements, and Subscriptions data are served from
 * /api/v1/discovery/* endpoints that are queued for backend implementation.
 * Until those land, the UI renders realistic placeholder data so design can
 * be iterated without waiting for the backend.  Every data-fetch site is
 * marked with a TODO comment that matches the planned endpoint path.
 */

import { createSignal, For, Show, createMemo, onMount } from "solid-js";
import { peers, addPeer } from "../stores/peers";
import { toast } from "../stores/toast";
import { formatMsat } from "../stores/payments";
import { formatRelativeTime, truncateId } from "../utils/formatting";
import {
  IconSearch,
  IconCheck,
  IconShield,
  IconRefresh,
  IconLightning,
  IconUser,
  IconPlus,
  IconTrash,
  IconX,
  IconChevronRight,
} from "./Icons";

// ── Tab type ─────────────────────────────────────────────────────────────────

type Tab = "feed" | "search" | "endorsements" | "subscriptions";

// ── Domain types (mirrors planned /api/v1/discovery/* response shapes) ────────

interface Announcement {
  id: string;
  from_node_id: string;
  from_alias?: string;
  content: string;
  price_msat: number;
  timestamp: number;
  kind: "text" | "profile_update" | "service" | "event";
  tags: string[];
}

interface SearchResult {
  node_id: string;
  display_name?: string;
  content_preview: string;
  price_msat: number;
  capabilities: string[];
  tier?: string;
}

interface EndorsedNode {
  node_id: string;
  display_name?: string;
  endorsed_by: Array<{ node_id: string; alias: string }>;
  notes?: string;
}

interface Subscription {
  id: string;
  peer_node_id: string;
  peer_label?: string;
  budget_msat: number;
  spent_msat: number;
  delivery_mode: "immediate" | "batched" | "on_demand";
  active: boolean;
  created_at: number;
}

// ── Placeholder data ──────────────────────────────────────────────────────────
// Replace each block with api.get("/api/v1/discovery/...") when backend lands.

const PLACEHOLDER_FEED: Announcement[] = [
  {
    id: "a1",
    from_node_id: "02a1b2c3d4e5f60718293a4b5c6d7e8f9001a2b3c4d5e6f7081920a1b2c3d4e5f6",
    from_alias: "alice-node",
    content:
      "Just upgraded to sovereignty tier T2 — Lightning channels are live. Ping me for encrypted file transfers.",
    price_msat: 0,
    timestamp: Date.now() - 1_000 * 60 * 8,
    kind: "profile_update",
    tags: ["upgrade", "t2"],
  },
  {
    id: "a2",
    from_node_id: "03b2c3d4e5f60718293a4b5c6d7e8f9001a2b3c4d5e6f7081920a1b2c3d4e5f607",
    from_alias: "dev-mesh-alpha",
    content:
      "Offering encrypted code-review sessions. 100 sats / hour block. Message me a project overview to start.",
    price_msat: 100_000,
    timestamp: Date.now() - 1_000 * 60 * 37,
    kind: "service",
    tags: ["code-review", "paid"],
  },
  {
    id: "a3",
    from_node_id: "04c3d4e5f60718293a4b5c6d7e8f9001a2b3c4d5e6f7081920a1b2c3d4e5f60708",
    from_alias: "sovereign-medic",
    content: "Second-opinion consultations available over encrypted channel. Health sovereignty matters.",
    price_msat: 50_000,
    timestamp: Date.now() - 1_000 * 60 * 60 * 2,
    kind: "service",
    tags: ["health", "medical", "paid"],
  },
  {
    id: "a4",
    from_node_id: "05d4e5f60718293a4b5c6d7e8f9001a2b3c4d5e6f7081920a1b2c3d4e5f6070809",
    from_alias: "law-node-berlin",
    content: "Published new encrypted article: 'Bitcoin and commercial law in the EU'. Free to subscribers.",
    price_msat: 0,
    timestamp: Date.now() - 1_000 * 60 * 60 * 5,
    kind: "text",
    tags: ["law", "bitcoin", "article"],
  },
];

const PLACEHOLDER_SEARCH: SearchResult[] = [
  {
    node_id: "05d4e5f60718293a4b5c6d7e8f9001a2b3c4d5e6f7081920a1b2c3d4e5f6070809",
    display_name: "law-node-berlin",
    content_preview: "Legal counsel for Bitcoin businesses. Confidential encrypted sessions.",
    price_msat: 200_000,
    capabilities: ["X3dh", "FileTransfer", "VoIP"],
    tier: "T2",
  },
  {
    node_id: "06e5f60718293a4b5c6d7e8f9001a2b3c4d5e6f7081920a1b2c3d4e5f607080910",
    display_name: "builder-node-01",
    content_preview: "Rust and SolidJS consulting. Open to encrypted project discussions.",
    price_msat: 80_000,
    capabilities: ["X3dh", "FileTransfer"],
    tier: "T1",
  },
  {
    node_id: "07f60718293a4b5c6d7e8f9001a2b3c4d5e6f7081920a1b2c3d4e5f60708091011",
    display_name: "writer-sovereign",
    content_preview: "Long-form encrypted journalism. Accepts micro-payments per article.",
    price_msat: 10_000,
    capabilities: ["X3dh"],
    tier: "T1",
  },
];

const PLACEHOLDER_ENDORSEMENTS: EndorsedNode[] = [
  {
    node_id: "07f60718293a4b5c6d7e8f9001a2b3c4d5e6f7081920a1b2c3d4e5f60708091011",
    display_name: "charlie-node",
    endorsed_by: [
      { node_id: "02a1b2c3d4e5f60718293a4b5c6d7e8f9001a2b3c4d5e6f7081920a1b2c3d4e5f6", alias: "alice-node" },
      { node_id: "03b2c3d4e5f60718293a4b5c6d7e8f9001a2b3c4d5e6f7081920a1b2c3d4e5f607", alias: "dev-mesh-alpha" },
    ],
    notes: "Reliable sovereign node, on the mesh for 6+ months.",
  },
  {
    node_id: "080718293a4b5c6d7e8f9001a2b3c4d5e6f7081920a1b2c3d4e5f6070809101112",
    display_name: "delta-sovereign",
    endorsed_by: [
      { node_id: "03b2c3d4e5f60718293a4b5c6d7e8f9001a2b3c4d5e6f7081920a1b2c3d4e5f607", alias: "dev-mesh-alpha" },
    ],
    notes: undefined,
  },
];

const PLACEHOLDER_SUBS: Subscription[] = [
  {
    id: "sub1",
    peer_node_id: "02a1b2c3d4e5f60718293a4b5c6d7e8f9001a2b3c4d5e6f7081920a1b2c3d4e5f6",
    peer_label: "alice-node",
    budget_msat: 1_000_000,
    spent_msat: 240_000,
    delivery_mode: "immediate",
    active: true,
    created_at: Date.now() - 1_000 * 60 * 60 * 24 * 7,
  },
  {
    id: "sub2",
    peer_node_id: "03b2c3d4e5f60718293a4b5c6d7e8f9001a2b3c4d5e6f7081920a1b2c3d4e5f607",
    peer_label: "dev-mesh-alpha",
    budget_msat: 500_000,
    spent_msat: 500_000,
    delivery_mode: "batched",
    active: false,
    created_at: Date.now() - 1_000 * 60 * 60 * 24 * 14,
  },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function kindBadge(kind: Announcement["kind"]): string {
  switch (kind) {
    case "service":        return "badge badge-warning";
    case "profile_update": return "badge badge-info";
    case "event":          return "badge badge-success";
    default:               return "badge";
  }
}

function kindLabel(kind: Announcement["kind"]): string {
  switch (kind) {
    case "service":        return "Service";
    case "profile_update": return "Profile";
    case "event":          return "Event";
    default:               return "Post";
  }
}

function deliveryLabel(mode: Subscription["delivery_mode"]): string {
  switch (mode) {
    case "immediate": return "Immediate";
    case "batched":   return "Batched";
    case "on_demand": return "On-demand";
  }
}

// ── Sub-components ────────────────────────────────────────────────────────────

function AnnouncementCard(props: { item: Announcement }) {
  const a = props.item;
  const label = a.from_alias ?? truncateId(a.from_node_id);

  return (
    <div class="card" style={{ "margin-bottom": "12px", padding: "16px" }}>
      <div class="flex items-center gap-8" style={{ "margin-bottom": "8px" }}>
        <div class="flex items-center gap-8" style={{ flex: 1, "min-width": 0 }}>
          <div
            class="flex items-center justify-center"
            style={{
              width: "32px",
              height: "32px",
              background: "var(--bg-accent-subtle)",
              "border-radius": "50%",
              "flex-shrink": 0,
            }}
          >
            <IconUser size={14} class="text-accent" />
          </div>
          <div style={{ "min-width": 0 }}>
            <div class="font-medium text-sm truncate" title={a.from_node_id}>
              {label}
            </div>
            <div class="text-xs text-muted">{formatRelativeTime(a.timestamp)}</div>
          </div>
        </div>

        <div class="flex items-center gap-8 flex-shrink-0">
          <span class={kindBadge(a.kind)}>{kindLabel(a.kind)}</span>
          <Show when={a.price_msat > 0}>
            <span class="flex items-center gap-4 text-xs text-accent">
              <IconLightning size={12} />
              {formatMsat(a.price_msat)}
            </span>
          </Show>
        </div>
      </div>

      <p class="text-sm" style={{ "line-height": "1.5", "margin-bottom": "8px" }}>
        {a.content}
      </p>

      <Show when={a.tags.length > 0}>
        <div class="flex gap-6" style={{ "flex-wrap": "wrap" }}>
          <For each={a.tags}>
            {(tag) => (
              <span
                class="badge"
                style={{
                  background: "var(--bg-tertiary)",
                  color: "var(--text-secondary)",
                  "font-size": "11px",
                }}
              >
                #{tag}
              </span>
            )}
          </For>
        </div>
      </Show>
    </div>
  );
}

// ── Whitelist Dialog — collects an address before calling addPeer ─────────────

interface WhitelistDialogProps {
  node: EndorsedNode;
  onClose: () => void;
  onAdded: () => void;
}

function WhitelistDialog(props: WhitelistDialogProps) {
  const [addr, setAddr] = createSignal("");
  const [label, setLabel] = createSignal(props.node.display_name ?? "");
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  const isValidAddr = () => /^.+:\d{1,5}$/.test(addr().trim());

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);
    if (!isValidAddr()) {
      setError("Address must be in host:port format (e.g. 10.0.0.1:9735).");
      return;
    }
    setLoading(true);
    try {
      await addPeer(props.node.node_id, addr().trim(), label().trim() || undefined);
      toast.success(`${label().trim() || truncateId(props.node.node_id)} added to whitelist`);
      props.onAdded();
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to add peer";
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      class="modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-label="Add to whitelist"
      onClick={(e) => { if (e.target === e.currentTarget) props.onClose(); }}
    >
      <div class="modal glass" style={{ "max-width": "420px" }}>
        <div class="modal-header">
          <h3 class="modal-title">Add to Whitelist</h3>
          <button class="btn btn-ghost btn-sm" onClick={props.onClose} aria-label="Close">
            <IconX size={16} />
          </button>
        </div>

        <div style={{ padding: "0 20px 8px" }}>
          <p class="text-sm text-muted" style={{ "margin-bottom": "16px" }}>
            Adding{" "}
            <strong>{props.node.display_name ?? truncateId(props.node.node_id)}</strong>{" "}
            to your whitelist. Provide their network address to establish the connection.
          </p>

          {/* Provenance trail */}
          <div
            class="card"
            style={{
              padding: "10px 12px",
              "margin-bottom": "16px",
              background: "var(--bg-tertiary)",
            }}
          >
            <div class="flex items-center gap-6 text-xs text-muted" style={{ "margin-bottom": "6px" }}>
              <IconShield size={12} />
              <span>Endorsed by your peers</span>
            </div>
            <For each={props.node.endorsed_by}>
              {(endorser) => (
                <div class="flex items-center gap-6 text-xs" style={{ "margin-left": "18px" }}>
                  <IconChevronRight size={10} class="text-muted" />
                  <span class="text-accent">{endorser.alias}</span>
                  <span class="text-muted mono" style={{ "font-size": "10px" }}>
                    {truncateId(endorser.node_id, 6, 6)}
                  </span>
                </div>
              )}
            </For>
            <Show when={props.node.notes}>
              <p class="text-xs text-muted" style={{ "margin-top": "6px", "font-style": "italic" }}>
                "{props.node.notes}"
              </p>
            </Show>
          </div>

          <form onSubmit={handleSubmit}>
            <div class="form-group">
              <label class="form-label" for="wl-node-id">
                Node ID
              </label>
              <input
                id="wl-node-id"
                class="input"
                type="text"
                value={props.node.node_id}
                readonly
                style={{ "font-family": "var(--font-mono)", "font-size": "11px" }}
              />
            </div>

            <div class="form-group">
              <label class="form-label" for="wl-label">
                Label
              </label>
              <input
                id="wl-label"
                class="input"
                type="text"
                placeholder="Optional nickname"
                value={label()}
                onInput={(e) => setLabel(e.currentTarget.value)}
              />
            </div>

            <div class="form-group">
              <label class="form-label" for="wl-addr">
                Address <span class="text-error">*</span>
              </label>
              <input
                id="wl-addr"
                class="input"
                type="text"
                placeholder="host:port (e.g. 10.0.0.1:9735)"
                value={addr()}
                onInput={(e) => setAddr(e.currentTarget.value)}
                required
              />
            </div>

            <Show when={error()}>
              <p class="text-sm text-error" style={{ "margin-bottom": "12px" }}>{error()}</p>
            </Show>

            <div class="flex gap-8" style={{ "justify-content": "flex-end" }}>
              <button type="button" class="btn btn-secondary" onClick={props.onClose} disabled={loading()}>
                Cancel
              </button>
              <button type="submit" class="btn btn-primary" disabled={loading() || !addr().trim()}>
                <Show when={loading()} fallback={<><IconPlus size={14} /> Add to Whitelist</>}>
                  Adding…
                </Show>
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}

// ── Tab: Feed ─────────────────────────────────────────────────────────────────

function FeedTab() {
  // TODO: replace with api.get("/api/v1/discovery/feed") when endpoint lands
  const [feed] = createSignal<Announcement[]>(PLACEHOLDER_FEED);
  const [loading, setLoading] = createSignal(false);

  const refresh = async () => {
    setLoading(true);
    // TODO: fetch real data here
    await new Promise((r) => setTimeout(r, 400)); // simulate network
    setLoading(false);
    toast.info("Feed refreshed");
  };

  onMount(() => {
    // TODO: poll or subscribe via WebSocket for live announces
  });

  return (
    <div>
      <div class="flex items-center gap-8" style={{ "margin-bottom": "16px" }}>
        <p class="text-sm text-muted" style={{ flex: 1 }}>
          Announcements from nodes you subscribe to, in chronological order.
        </p>
        <button class="btn btn-ghost btn-sm" onClick={refresh} disabled={loading()} aria-label="Refresh feed">
          <IconRefresh size={14} />
          <Show when={!loading()} fallback="Refreshing…">Refresh</Show>
        </button>
      </div>

      <Show
        when={!loading()}
        fallback={
          <div class="empty-state">
            <div class="connection-spinner" />
          </div>
        }
      >
        <Show
          when={feed().length > 0}
          fallback={
            <div class="empty-state">
              <p class="text-muted">No announcements yet.</p>
              <p class="text-sm text-muted">
                Subscribe to nodes in the <strong>Subscriptions</strong> tab to see their posts here.
              </p>
            </div>
          }
        >
          <For each={feed()}>{(item) => <AnnouncementCard item={item} />}</For>
        </Show>
      </Show>
    </div>
  );
}

// ── Tab: Search ───────────────────────────────────────────────────────────────

function SearchTab() {
  const [query, setQuery] = createSignal("");
  const [maxPriceSats, setMaxPriceSats] = createSignal<number | null>(null);
  const [capFilter, setCapFilter] = createSignal<string>("");
  const [results, setResults] = createSignal<SearchResult[]>([]);
  const [searched, setSearched] = createSignal(false);
  const [loading, setLoading] = createSignal(false);

  const CAPABILITIES = ["X3dh", "FileTransfer", "VoIP", "Calendar"];

  const filtered = createMemo(() =>
    results().filter((r) => {
      const maxMsat = maxPriceSats() !== null ? (maxPriceSats()! * 1_000) : Infinity;
      if (r.price_msat > maxMsat) return false;
      if (capFilter() && !r.capabilities.includes(capFilter())) return false;
      return true;
    }),
  );

  const handleSearch = async (e: Event) => {
    e.preventDefault();
    if (!query().trim()) return;
    setLoading(true);
    setSearched(false);
    // TODO: replace with api.get(`/api/v1/discovery/search?q=${encodeURIComponent(query())}`)
    await new Promise((r) => setTimeout(r, 600)); // simulate network
    setResults(
      PLACEHOLDER_SEARCH.filter((r) =>
        r.content_preview.toLowerCase().includes(query().toLowerCase()) ||
        (r.display_name ?? "").toLowerCase().includes(query().toLowerCase()),
      ),
    );
    setSearched(true);
    setLoading(false);
  };

  const alreadyPeer = (nodeId: string) => peers.some((p) => p.node_id === nodeId);

  return (
    <div>
      <form onSubmit={handleSearch} style={{ "margin-bottom": "16px" }}>
        <div class="flex gap-8" style={{ "margin-bottom": "10px" }}>
          <div style={{ flex: 1, position: "relative" }}>
            <span
              style={{
                position: "absolute",
                left: "10px",
                top: "50%",
                transform: "translateY(-50%)",
                color: "var(--text-muted)",
                "pointer-events": "none",
              }}
            >
              <IconSearch size={14} />
            </span>
            <input
              class="input"
              type="search"
              placeholder="Search nodes by name, service, or content…"
              value={query()}
              onInput={(e) => setQuery(e.currentTarget.value)}
              style={{ "padding-left": "34px" }}
            />
          </div>
          <button type="submit" class="btn btn-primary" disabled={loading() || !query().trim()}>
            <Show when={!loading()} fallback="Searching…">Search</Show>
          </button>
        </div>

        {/* Filters row */}
        <div class="flex gap-12 items-center flex-wrap">
          <div class="flex items-center gap-8">
            <label class="text-xs text-muted" for="max-price">Max price (sats)</label>
            <input
              id="max-price"
              class="input"
              type="number"
              min="0"
              placeholder="Any"
              style={{ width: "90px" }}
              value={maxPriceSats() ?? ""}
              onInput={(e) => {
                const v = e.currentTarget.value;
                setMaxPriceSats(v === "" ? null : Math.max(0, parseInt(v, 10)));
              }}
            />
          </div>
          <div class="flex items-center gap-8">
            <label class="text-xs text-muted" for="cap-filter">Capability</label>
            <select
              id="cap-filter"
              class="input"
              style={{ width: "130px" }}
              value={capFilter()}
              onChange={(e) => setCapFilter(e.currentTarget.value)}
            >
              <option value="">Any</option>
              <For each={CAPABILITIES}>{(c) => <option value={c}>{c}</option>}</For>
            </select>
          </div>
        </div>
      </form>

      <Show when={loading()}>
        <div class="empty-state"><div class="connection-spinner" /></div>
      </Show>

      <Show when={searched() && !loading()}>
        <Show
          when={filtered().length > 0}
          fallback={
            <div class="empty-state">
              <p class="text-muted">No results match your query and filters.</p>
            </div>
          }
        >
          <p class="text-xs text-muted" style={{ "margin-bottom": "12px" }}>
            {filtered().length} result{filtered().length !== 1 ? "s" : ""}
          </p>
          <For each={filtered()}>
            {(r) => {
              const isPeer = () => alreadyPeer(r.node_id);
              return (
                <div class="card" style={{ "margin-bottom": "10px", padding: "16px" }}>
                  <div class="flex items-start gap-12">
                    <div
                      class="flex items-center justify-center flex-shrink-0"
                      style={{
                        width: "36px",
                        height: "36px",
                        background: "var(--bg-accent-subtle)",
                        "border-radius": "50%",
                      }}
                    >
                      <IconUser size={16} class="text-accent" />
                    </div>

                    <div style={{ flex: 1, "min-width": 0 }}>
                      <div class="flex items-center gap-8 flex-wrap" style={{ "margin-bottom": "4px" }}>
                        <span class="font-medium text-sm">
                          {r.display_name ?? truncateId(r.node_id)}
                        </span>
                        <Show when={r.tier}>
                          <span class="badge badge-info" style={{ "font-size": "10px" }}>
                            {r.tier}
                          </span>
                        </Show>
                        <Show when={isPeer()}>
                          <span class="badge badge-success" style={{ "font-size": "10px" }}>
                            <IconCheck size={10} /> In whitelist
                          </span>
                        </Show>
                      </div>

                      <p class="text-sm text-secondary" style={{ "margin-bottom": "8px" }}>
                        {r.content_preview}
                      </p>

                      <div class="flex items-center gap-12 flex-wrap">
                        <span class="flex items-center gap-4 text-xs text-accent">
                          <IconLightning size={12} />
                          {r.price_msat === 0 ? "Free" : formatMsat(r.price_msat)}
                        </span>
                        <div class="flex gap-6 flex-wrap">
                          <For each={r.capabilities}>
                            {(cap) => (
                              <span
                                class="badge"
                                style={{
                                  background: "var(--bg-tertiary)",
                                  color: "var(--text-secondary)",
                                  "font-size": "10px",
                                }}
                              >
                                {cap}
                              </span>
                            )}
                          </For>
                        </div>
                      </div>
                    </div>

                    <Show when={!isPeer()}>
                      <a
                        href="/peers"
                        class="btn btn-sm btn-secondary flex-shrink-0"
                        title="Go to Peers to add this node"
                      >
                        <IconPlus size={14} /> Add
                      </a>
                    </Show>
                  </div>
                </div>
              );
            }}
          </For>
        </Show>
      </Show>

      <Show when={!searched() && !loading()}>
        <div class="empty-state">
          <IconSearch size={32} class="text-muted" />
          <p class="text-muted" style={{ "margin-top": "12px" }}>
            Search the sovereign mesh for nodes, services, and content.
          </p>
          <p class="text-xs text-muted">Results come from your peers' peer-exchange graphs.</p>
        </div>
      </Show>
    </div>
  );
}

// ── Tab: Endorsements ─────────────────────────────────────────────────────────

function EndorsementsTab() {
  // TODO: replace with api.get("/api/v1/discovery/endorsements") when endpoint lands
  const [endorsed] = createSignal<EndorsedNode[]>(PLACEHOLDER_ENDORSEMENTS);
  const [whitelistTarget, setWhitelistTarget] = createSignal<EndorsedNode | null>(null);
  const [addedIds, setAddedIds] = createSignal<Set<string>>(new Set());

  const alreadyPeer = (nodeId: string) =>
    peers.some((p) => p.node_id === nodeId) || addedIds().has(nodeId);

  const handleAdded = (nodeId: string) => {
    setAddedIds((prev) => new Set([...prev, nodeId]));
    setWhitelistTarget(null);
  };

  return (
    <div>
      <p class="text-sm text-muted" style={{ "margin-bottom": "16px" }}>
        Nodes that your existing peers vouch for. Adding one to your whitelist extends your trust
        network. Each card shows the provenance trail so you can assess the endorsement chain.
      </p>

      <Show
        when={endorsed().length > 0}
        fallback={
          <div class="empty-state">
            <IconShield size={32} class="text-muted" />
            <p class="text-muted" style={{ "margin-top": "12px" }}>No endorsements yet.</p>
            <p class="text-xs text-muted">
              Endorsements appear once your peers have shared their trusted contacts.
            </p>
          </div>
        }
      >
        <For each={endorsed()}>
          {(node) => {
            const isPeer = () => alreadyPeer(node.node_id);
            return (
              <div class="card" style={{ "margin-bottom": "12px", padding: "16px" }}>
                <div class="flex items-start gap-12">
                  <div
                    class="flex items-center justify-center flex-shrink-0"
                    style={{
                      width: "38px",
                      height: "38px",
                      background: "var(--bg-accent-subtle)",
                      "border-radius": "50%",
                    }}
                  >
                    <IconUser size={16} class="text-accent" />
                  </div>

                  <div style={{ flex: 1, "min-width": 0 }}>
                    <div class="flex items-center gap-8 flex-wrap" style={{ "margin-bottom": "6px" }}>
                      <span class="font-medium text-sm">
                        {node.display_name ?? truncateId(node.node_id)}
                      </span>
                      <Show when={isPeer()}>
                        <span class="badge badge-success" style={{ "font-size": "10px" }}>
                          <IconCheck size={10} /> In whitelist
                        </span>
                      </Show>
                    </div>

                    <div class="text-xs mono text-muted" style={{ "margin-bottom": "10px" }}>
                      {truncateId(node.node_id, 12, 12)}
                    </div>

                    {/* Provenance trail */}
                    <div
                      class="card"
                      style={{
                        padding: "8px 10px",
                        background: "var(--bg-tertiary)",
                        "margin-bottom": "10px",
                      }}
                    >
                      <div
                        class="flex items-center gap-6 text-xs text-muted"
                        style={{ "margin-bottom": "4px" }}
                      >
                        <IconShield size={11} />
                        <span>Endorsed by</span>
                      </div>
                      <For each={node.endorsed_by}>
                        {(endorser, i) => (
                          <div
                            class="flex items-center gap-6 text-xs"
                            style={{ "margin-left": `${(i() + 1) * 12}px` }}
                          >
                            <IconChevronRight size={10} class="text-muted" />
                            <span class="text-accent">{endorser.alias}</span>
                            <span
                              class="text-muted mono"
                              style={{ "font-size": "10px" }}
                              title={endorser.node_id}
                            >
                              {truncateId(endorser.node_id, 6, 6)}
                            </span>
                          </div>
                        )}
                      </For>
                    </div>

                    <Show when={node.notes}>
                      <p
                        class="text-xs text-secondary"
                        style={{ "font-style": "italic", "margin-bottom": "10px" }}
                      >
                        "{node.notes}"
                      </p>
                    </Show>
                  </div>

                  <Show when={!isPeer()}>
                    <button
                      class="btn btn-sm btn-primary flex-shrink-0"
                      onClick={() => setWhitelistTarget(node)}
                    >
                      <IconPlus size={14} /> Add
                    </button>
                  </Show>
                </div>
              </div>
            );
          }}
        </For>
      </Show>

      {/* Whitelist dialog */}
      <Show when={whitelistTarget() !== null}>
        <WhitelistDialog
          node={whitelistTarget()!}
          onClose={() => setWhitelistTarget(null)}
          onAdded={() => handleAdded(whitelistTarget()!.node_id)}
        />
      </Show>
    </div>
  );
}

// ── Tab: Subscriptions ────────────────────────────────────────────────────────

function SubscriptionsTab() {
  // TODO: replace with api.get("/api/v1/discovery/subscriptions") when endpoint lands
  const [subs, setSubs] = createSignal<Subscription[]>(PLACEHOLDER_SUBS);

  const cancelSub = async (id: string) => {
    // TODO: api.delete(`/api/v1/discovery/subscriptions/${id}`)
    setSubs((prev) => prev.filter((s) => s.id !== id));
    toast.success("Subscription cancelled");
  };

  const budgetPct = (sub: Subscription) =>
    sub.budget_msat > 0 ? Math.min(100, (sub.spent_msat / sub.budget_msat) * 100) : 0;

  const budgetBarColor = (pct: number) => {
    if (pct >= 100) return "var(--error)";
    if (pct >= 80) return "var(--warning)";
    return "var(--accent)";
  };

  return (
    <div>
      <div class="flex items-center gap-8" style={{ "margin-bottom": "16px" }}>
        <p class="text-sm text-muted" style={{ flex: 1 }}>
          Manage your discovery subscriptions. Each subscription streams announcements from a
          specific node within your set budget.
        </p>
        {/* TODO: "New Subscription" button when POST /api/v1/discovery/subscriptions lands */}
      </div>

      <Show
        when={subs().length > 0}
        fallback={
          <div class="empty-state">
            <p class="text-muted">No active subscriptions.</p>
            <p class="text-xs text-muted">
              Subscribe to a peer's announcement feed to see their posts in your Feed tab.
            </p>
          </div>
        }
      >
        <For each={subs()}>
          {(sub) => {
            const pct = () => budgetPct(sub);
            const exhausted = () => sub.spent_msat >= sub.budget_msat;
            const peerLabel = sub.peer_label ?? truncateId(sub.peer_node_id);

            return (
              <div class="card" style={{ "margin-bottom": "12px", padding: "16px" }}>
                <div class="flex items-start gap-12">
                  <div
                    class="flex items-center justify-center flex-shrink-0"
                    style={{
                      width: "36px",
                      height: "36px",
                      background: sub.active ? "var(--bg-accent-subtle)" : "var(--bg-tertiary)",
                      "border-radius": "50%",
                    }}
                  >
                    <IconUser size={16} class={sub.active ? "text-accent" : "text-muted"} />
                  </div>

                  <div style={{ flex: 1, "min-width": 0 }}>
                    {/* Header row */}
                    <div class="flex items-center gap-8 flex-wrap" style={{ "margin-bottom": "6px" }}>
                      <span class="font-medium text-sm">{peerLabel}</span>
                      <span
                        class={`badge ${sub.active && !exhausted() ? "badge-success" : "badge-error"}`}
                        style={{ "font-size": "10px" }}
                      >
                        {exhausted() ? "Budget exhausted" : sub.active ? "Active" : "Cancelled"}
                      </span>
                      <span
                        class="badge"
                        style={{
                          "font-size": "10px",
                          background: "var(--bg-tertiary)",
                          color: "var(--text-secondary)",
                        }}
                      >
                        {deliveryLabel(sub.delivery_mode)}
                      </span>
                    </div>

                    <div
                      class="text-xs mono text-muted"
                      style={{ "margin-bottom": "10px" }}
                      title={sub.peer_node_id}
                    >
                      {truncateId(sub.peer_node_id, 12, 12)}
                    </div>

                    {/* Budget bar */}
                    <div style={{ "margin-bottom": "6px" }}>
                      <div class="flex items-center gap-8" style={{ "margin-bottom": "4px" }}>
                        <span class="text-xs text-muted" style={{ flex: 1 }}>
                          Budget: {formatMsat(sub.spent_msat)} / {formatMsat(sub.budget_msat)}
                        </span>
                        <span
                          class="text-xs"
                          style={{ color: budgetBarColor(pct()) }}
                        >
                          {Math.round(pct())}%
                        </span>
                      </div>
                      <div
                        style={{
                          height: "4px",
                          background: "var(--bg-tertiary)",
                          "border-radius": "2px",
                          overflow: "hidden",
                        }}
                      >
                        <div
                          style={{
                            height: "100%",
                            width: `${pct()}%`,
                            background: budgetBarColor(pct()),
                            "border-radius": "2px",
                            transition: "width 0.3s ease",
                          }}
                        />
                      </div>
                    </div>

                    <div class="text-xs text-muted">
                      Started {formatRelativeTime(sub.created_at)}
                    </div>
                  </div>

                  <button
                    class="btn btn-sm btn-danger flex-shrink-0"
                    onClick={() => cancelSub(sub.id)}
                    aria-label={`Cancel subscription to ${peerLabel}`}
                    title="Cancel subscription"
                  >
                    <IconTrash size={14} />
                  </button>
                </div>
              </div>
            );
          }}
        </For>
      </Show>
    </div>
  );
}

// ── Main view ─────────────────────────────────────────────────────────────────

export default function DiscoveryView() {
  const [tab, setTab] = createSignal<Tab>("feed");

  const tabs: Array<{ id: Tab; label: string }> = [
    { id: "feed",          label: "Feed" },
    { id: "search",        label: "Search" },
    { id: "endorsements",  label: "Endorsements" },
    { id: "subscriptions", label: "Subscriptions" },
  ];

  return (
    <div class="page content-max">
      <div class="page-header">
        <h2 class="page-title">Discovery</h2>
      </div>

      {/* Tab bar */}
      <div
        class="flex gap-4"
        role="tablist"
        aria-label="Discovery sections"
        style={{ "margin-bottom": "20px", "border-bottom": "1px solid var(--border-primary)", "padding-bottom": "0" }}
      >
        <For each={tabs}>
          {(t) => (
            <button
              role="tab"
              aria-selected={tab() === t.id}
              class="btn btn-ghost btn-sm"
              style={{
                "border-bottom": tab() === t.id ? "2px solid var(--accent)" : "2px solid transparent",
                "border-radius": "0",
                "padding-bottom": "8px",
                color: tab() === t.id ? "var(--accent)" : "var(--text-secondary)",
                "font-weight": tab() === t.id ? "600" : "400",
              }}
              onClick={() => setTab(t.id)}
            >
              {t.label}
            </button>
          )}
        </For>
      </div>

      {/* Tab content */}
      <Show when={tab() === "feed"}>          <FeedTab /></Show>
      <Show when={tab() === "search"}>        <SearchTab /></Show>
      <Show when={tab() === "endorsements"}>  <EndorsementsTab /></Show>
      <Show when={tab() === "subscriptions"}><SubscriptionsTab /></Show>
    </div>
  );
}
