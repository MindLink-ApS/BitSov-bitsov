/** Sovereign Browser — Phase 2: Rich content, internal links, back/forward, manifest. */

import { createSignal, onMount, onCleanup, Show, For, createMemo } from "solid-js";
import { api, nodeId } from "../stores/auth";
import { peers, refreshPeers } from "../stores/peers";
import { balance, formatMsat, refreshBalance } from "../stores/payments";
import { toast } from "../stores/toast";
import { renderMarkdown } from "../utils/markdown";
import { truncateId } from "../utils/formatting";
import { loadJSON, saveJSON, removeItem } from "../utils/storage";
import { MessageKind } from "../api/types";
import type { PeerResponse, MessageResponse, ManifestPage, WebManifest } from "../api/types";
import {
  IconBrowser,
  IconBookmark,
  IconVerified,
  IconRefresh,
  IconArrowLeft,
  IconArrowRight,
  IconArrowUpRight,
  IconDocument,
  IconLightning,
  IconLock,
  IconLoader,
  IconClock,
  IconPlus,
  IconTrash,
  IconGlobe,
  IconSitemap,
} from "./Icons";

// ── Types ───────────────────────────────────────────────────────────────

interface Bookmark {
  peerId: string;
  peerLabel: string;
  path: string;
  title: string;
  addedAt: number;
}

interface BrowseHistoryEntry {
  peerId: string;
  peerLabel: string;
  path: string;
  timestamp: number;
  costMsat: number;
}

interface NavEntry {
  peerId: string;
  path: string;
}

// ── Markdown Renderer — shared from ../utils/markdown ──────────────────

// ── Page Cache (in-memory, avoids re-paying for back/forward) ───────────

interface CachedPage {
  content: string;
  title: string;
  costMsat: number;
  timestamp: number;
}

/** Cache key: peerId + path */
function cacheKey(peerId: string, pagePath: string): string {
  return `${peerId}::${pagePath}`;
}

const pageCache = new Map<string, CachedPage>();

// ── Persistence ─────────────────────────────────────────────────────────

function loadBookmarks(): Bookmark[] {
  return loadJSON<Bookmark[]>("konsensus_bookmarks", []);
}

function saveBookmarks(bookmarks: Bookmark[]) {
  saveJSON("konsensus_bookmarks", bookmarks);
}

function loadHistory(): BrowseHistoryEntry[] {
  return loadJSON<BrowseHistoryEntry[]>("konsensus_browse_history", []);
}

function saveHistory(history: BrowseHistoryEntry[]) {
  saveJSON("konsensus_browse_history", history.slice(0, 100));
}

// ── Parse page response from received message ──────────────────────────

function parsePageResponse(plaintext: string): {
  status: string;
  content_type: string;
  body: string;
  request_id: string;
} | null {
  try { return JSON.parse(plaintext); }
  catch { return null; }
}

function parseManifest(plaintext: string): WebManifest | null {
  try {
    const obj = JSON.parse(plaintext);
    if (obj.site_name && Array.isArray(obj.pages)) return obj as WebManifest;
    return null;
  } catch { return null; }
}

// ── Component ───────────────────────────────────────────────────────────

export default function BrowserView() {
  const [selectedPeer, setSelectedPeer] = createSignal("");
  const [path, setPath] = createSignal("/index.md");
  const [loading, setLoading] = createSignal(false);
  const [pageContent, setPageContent] = createSignal("");
  const [pageTitle, setPageTitle] = createSignal("");
  const [pageStatus, setPageStatus] = createSignal<string | null>(null);
  const [pageCost, setPageCost] = createSignal(0);
  const [sessionCost, setSessionCost] = createSignal(0);
  const [pagesLoaded, setPagesLoaded] = createSignal(0);
  const [errorMsg, setErrorMsg] = createSignal("");
  const [bookmarks, setBookmarks] = createSignal<Bookmark[]>(loadBookmarks());
  const [history, setHistory] = createSignal<BrowseHistoryEntry[]>(loadHistory());
  const [activeTab, setActiveTab] = createSignal<"browser" | "bookmarks" | "history" | "manifest">("browser");

  // Back/forward navigation stack
  const [navStack, setNavStack] = createSignal<NavEntry[]>([]);
  const [navIndex, setNavIndex] = createSignal(-1);
  const [isNavAction, setIsNavAction] = createSignal(false);

  // Manifest
  const [manifest, setManifest] = createSignal<WebManifest | null>(null);
  const [manifestLoading, setManifestLoading] = createSignal(false);
  const [manifestPeer, setManifestPeer] = createSignal("");

  onMount(() => {
    refreshPeers();
    refreshBalance();

    // Check for navigation target from Bookmarks view
    const browseTarget = loadJSON<{ peerId?: string; path?: string } | null>("konsensus_browse_target", null);
    if (browseTarget) {
      removeItem("konsensus_browse_target");
      if (browseTarget.peerId) setSelectedPeer(browseTarget.peerId);
      if (browseTarget.path) setPath(browseTarget.path);
    }
  });

  const connectedPeers = createMemo(() => peers.filter((p) => p.connected));

  const selectedPeerLabel = createMemo(() => {
    const p = peers.find((p) => p.node_id === selectedPeer());
    return p?.label || truncateId(selectedPeer());
  });

  const canGoBack = createMemo(() => navIndex() > 0);
  const canGoForward = createMemo(() => navIndex() < navStack().length - 1);

  /** Extract title from the first H1 in markdown content. */
  function extractTitle(md: string): string {
    for (const line of md.split("\n")) {
      const m = line.match(/^#\s+(.+)/);
      if (m) return m[1].trim();
    }
    return "";
  }

  /** Push a new entry to the navigation stack (for back/forward). */
  function pushNavEntry(peerId: string, pagePath: string) {
    if (isNavAction()) {
      setIsNavAction(false);
      return;
    }
    const stack = navStack().slice(0, navIndex() + 1);
    stack.push({ peerId, path: pagePath });
    setNavStack(stack);
    setNavIndex(stack.length - 1);
  }

  function goBack() {
    if (!canGoBack()) return;
    const idx = navIndex() - 1;
    setNavIndex(idx);
    const entry = navStack()[idx];
    setIsNavAction(true);
    setSelectedPeer(entry.peerId);
    setPath(entry.path);
    browsePage();
  }

  function goForward() {
    if (!canGoForward()) return;
    const idx = navIndex() + 1;
    setNavIndex(idx);
    const entry = navStack()[idx];
    setIsNavAction(true);
    setSelectedPeer(entry.peerId);
    setPath(entry.path);
    browsePage();
  }

  /** Handle clicks on internal links in rendered content. */
  function handleContentClick(e: MouseEvent) {
    const target = e.target as HTMLElement;
    const anchor = target.closest("a[data-internal]") as HTMLAnchorElement | null;
    if (!anchor) return;
    e.preventDefault();

    const href = anchor.getAttribute("href") || "";

    if (href.startsWith("konsensus://")) {
      // Parse konsensus://peerId/path
      const withoutScheme = href.slice("konsensus://".length);
      const slashIdx = withoutScheme.indexOf("/");
      if (slashIdx > 0) {
        const peerRef = withoutScheme.slice(0, slashIdx);
        const linkPath = withoutScheme.slice(slashIdx);

        // Resolve peer reference — try label match first, then ID prefix
        const resolved = peers.find(
          (p) =>
            p.node_id === peerRef ||
            p.node_id.startsWith(peerRef) ||
            (p.label && p.label.toLowerCase() === peerRef.toLowerCase())
        );
        if (resolved) {
          setSelectedPeer(resolved.node_id);
        }
        setPath(linkPath);
      } else {
        // No path, just peer reference
        setPath("/index.md");
      }
    } else if (href.startsWith("/")) {
      // Relative path on same peer
      setPath(href);
    }

    browsePage();
  }

  async function browsePage(forceRefresh = false) {
    const peer = selectedPeer();
    const pagePath = path();

    if (!peer) {
      toast.warning("Select a peer to browse");
      return;
    }
    if (!pagePath) {
      toast.warning("Enter a page path");
      return;
    }

    // Check cache first (unless force refresh)
    const key = cacheKey(peer, pagePath);
    if (!forceRefresh) {
      const cached = pageCache.get(key);
      if (cached) {
        setPageContent(cached.content);
        setPageTitle(cached.title);
        setPageCost(0);
        setPageStatus("ok");
        setActiveTab("browser");
        pushNavEntry(peer, pagePath);
        return;
      }
    }

    setLoading(true);
    setErrorMsg("");
    setPageContent("");
    setPageTitle("");
    setPageStatus(null);
    setActiveTab("browser");

    // Local content preview — free, no payment needed
    const myId = nodeId();
    if (myId && peer === myId) {
      try {
        const cleanPath = pagePath.replace(/^\//, "");
        const page = await api.readPage(cleanPath);
        const content = page.content;
        const title = extractTitle(content);
        setPageContent(content);
        setPageTitle(title);
        setPageCost(0);
        setPageStatus("ok");
        pushNavEntry(peer, pagePath);
        pageCache.set(key, { content, title, costMsat: 0, timestamp: Date.now() });
      } catch (e: unknown) {
        setErrorMsg(e instanceof Error ? e.message : "Page not found on local node");
        setPageStatus("error");
      } finally {
        setLoading(false);
      }
      return;
    }

    try {
      const result = await api.browsePage(peer, pagePath);
      setPageCost(result.amount_msat);
      setSessionCost((prev) => prev + result.amount_msat);
      setPagesLoaded((prev) => prev + 1);

      if (result.delivered) {
        await pollForResponse(peer, result.message_id);

        // Cache the page if it loaded successfully
        if (pageStatus() === "ok" && pageContent()) {
          pageCache.set(key, {
            content: pageContent(),
            title: pageTitle(),
            costMsat: result.amount_msat,
            timestamp: Date.now(),
          });
        }

        // Push to nav stack
        pushNavEntry(peer, pagePath);

        // Add to history
        const entry: BrowseHistoryEntry = {
          peerId: peer,
          peerLabel: selectedPeerLabel(),
          path: pagePath,
          timestamp: Date.now(),
          costMsat: result.amount_msat,
        };
        const h = [entry, ...history()];
        setHistory(h);
        saveHistory(h);
      } else {
        setErrorMsg("Request not delivered. Peer may be offline.");
        setPageStatus("error");
      }

      refreshBalance();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to send page request";
      setErrorMsg(msg);
      setPageStatus("error");
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  }

  async function pollForResponse(peerId: string, _requestMsgId: string) {
    const maxAttempts = 20;
    const delayMs = 500;

    for (let i = 0; i < maxAttempts; i++) {
      await new Promise((r) => setTimeout(r, delayMs));
      try {
        const messages = await api.listMessages({ limit: 10 });
        const response = messages.find(
          (m: MessageResponse) =>
            m.sender === peerId &&
            m.kind === MessageKind.PAGE_RESPONSE &&
            m.plaintext
        );

        if (response && response.plaintext) {
          const parsed = parsePageResponse(response.plaintext);
          if (parsed) {
            if (parsed.status === "Ok") {
              setPageContent(parsed.body);
              setPageTitle(extractTitle(parsed.body));
              setPageStatus("ok");
            } else {
              setErrorMsg(`Server returned: ${parsed.status} — ${parsed.body}`);
              setPageStatus("error");
            }
            return;
          }
        }
      } catch { /* continue polling */ }
    }

    setErrorMsg("Request timed out after 10 seconds. The peer may be slow or offline. Your payment was sent.");
    setPageStatus("error");
  }

  /** Fetch the web manifest from a peer to see available pages. */
  async function fetchManifest() {
    const peer = selectedPeer();
    if (!peer) {
      toast.warning("Select a peer first");
      return;
    }

    setManifestLoading(true);
    setManifest(null);
    setManifestPeer(peer);

    try {
      const result = await api.fetchManifest(peer);
      if (result.delivered) {
        // Poll for manifest response
        const maxAttempts = 20;
        for (let i = 0; i < maxAttempts; i++) {
          await new Promise((r) => setTimeout(r, 500));
          try {
            const messages = await api.listMessages({ limit: 10 });
            const resp = messages.find(
              (m: MessageResponse) =>
                m.sender === peer &&
                m.kind === MessageKind.WEB_MANIFEST &&
                m.plaintext
            );
            if (resp && resp.plaintext) {
              const parsed = parseManifest(resp.plaintext);
              if (parsed) {
                setManifest(parsed);
                setActiveTab("manifest");
                toast.success(`Loaded manifest: ${parsed.site_name} (${parsed.pages.length} pages)`);
                break;
              }
            }
          } catch { /* continue */ }
        }
        if (!manifest()) {
          toast.info("Manifest request sent but no response received yet");
        }
      } else {
        toast.error("Could not reach peer");
      }
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to fetch manifest");
    } finally {
      setManifestLoading(false);
    }
  }

  function navigateFromManifest(page: ManifestPage) {
    setPath(page.path);
    setActiveTab("browser");
    browsePage();
  }

  function addBookmark() {
    const peer = selectedPeer();
    const p = path();
    if (!peer || !p) return;

    const existing = bookmarks().find((b) => b.peerId === peer && b.path === p);
    if (existing) {
      toast.info("Already bookmarked");
      return;
    }

    const bm: Bookmark = {
      peerId: peer,
      peerLabel: selectedPeerLabel(),
      path: p,
      title: pageTitle() || p.replace(/^\//, "").replace(/\.md$/, ""),
      addedAt: Date.now(),
    };
    const updated = [bm, ...bookmarks()];
    setBookmarks(updated);
    saveBookmarks(updated);
    toast.success("Bookmark added");
  }

  function removeBookmark(index: number) {
    const updated = bookmarks().filter((_, i) => i !== index);
    setBookmarks(updated);
    saveBookmarks(updated);
  }

  function navigateToBookmark(bm: Bookmark) {
    setSelectedPeer(bm.peerId);
    setPath(bm.path);
    setActiveTab("browser");
    browsePage();
  }

  function navigateToHistory(entry: BrowseHistoryEntry) {
    setSelectedPeer(entry.peerId);
    setPath(entry.path);
    setActiveTab("browser");
    browsePage();
  }

  function formatTime(ts: number): string {
    const diff = Date.now() - ts;
    if (diff < 60_000) return "just now";
    if (diff < 3600_000) return `${Math.floor(diff / 60_000)}m ago`;
    if (diff < 86400_000) return `${Math.floor(diff / 3600_000)}h ago`;
    return new Date(ts).toLocaleDateString();
  }

  return (
    <div class="page" style={{ "max-width": "var(--content-max)" }}>
      {/* Header */}
      <div class="page-header">
        <h2 class="page-title">
          <IconBrowser size={20} /> Browse
        </h2>
        <div class="flex-row gap-sm align-center">
          <span class="browser-session-cost" title="Session cost">
            <IconLightning size={12} />
            {formatMsat(sessionCost())} | {pagesLoaded()} pages
          </span>
        </div>
      </div>

      {/* Tab bar */}
      <div class="browser-tabs">
        <button
          class={`browser-tab ${activeTab() === "browser" ? "active" : ""}`}
          onClick={() => setActiveTab("browser")}
        >
          <IconGlobe size={14} /> Browse
        </button>
        <button
          class={`browser-tab ${activeTab() === "manifest" ? "active" : ""}`}
          onClick={() => setActiveTab("manifest")}
        >
          <IconSitemap size={14} /> Site Map
        </button>
        <button
          class={`browser-tab ${activeTab() === "bookmarks" ? "active" : ""}`}
          onClick={() => setActiveTab("bookmarks")}
        >
          <IconBookmark size={14} /> Bookmarks
        </button>
        <button
          class={`browser-tab ${activeTab() === "history" ? "active" : ""}`}
          onClick={() => setActiveTab("history")}
        >
          <IconClock size={14} /> History
        </button>
      </div>

      {/* Address bar — visible on all tabs */}
      <p class="browser-address-hint text-xs text-muted">
        Format: konsensus://&lt;peer&gt;/&lt;path&gt;
      </p>
      <div class="browser-address-bar card">
        <div class="browser-address-row">
          {/* Back/Forward buttons */}
          <button
            class="btn btn-ghost btn-sm"
            onClick={goBack}
            disabled={!canGoBack()}
            title="Go back"
            aria-label="Go back"
          >
            <IconArrowLeft size={14} />
          </button>
          <button
            class="btn btn-ghost btn-sm"
            onClick={goForward}
            disabled={!canGoForward()}
            title="Go forward"
            aria-label="Go forward"
          >
            <IconArrowRight size={14} />
          </button>

          <select
            class="browser-peer-select"
            value={selectedPeer()}
            onChange={(e) => setSelectedPeer(e.currentTarget.value)}
          >
            <option value="">Select peer...</option>
            <Show when={nodeId()}>
              <option value={nodeId()!}>
                My Node (local preview)
              </option>
            </Show>
            <For each={connectedPeers()}>
              {(peer) => (
                <option value={peer.node_id}>
                  {peer.label || truncateId(peer.node_id)}
                </option>
              )}
            </For>
          </select>

          <div class="browser-path-container">
            <span class="browser-path-prefix">konsensus://</span>
            <input
              type="text"
              class="browser-path-input"
              value={path()}
              onInput={(e) => setPath(e.currentTarget.value)}
              placeholder="/index.md"
              onKeyDown={(e) => {
                if (e.key === "Enter") browsePage();
              }}
            />
          </div>

          <button
            class="btn btn-primary"
            onClick={() => browsePage()}
            disabled={loading() || !selectedPeer()}
          >
            <Show when={loading()} fallback={<IconArrowUpRight size={14} />}>
              <IconLoader size={14} />
            </Show>
            Load
          </button>

          <button
            class="btn btn-ghost btn-sm"
            onClick={() => browsePage(true)}
            disabled={loading() || !selectedPeer()}
            title="Refresh (re-fetch and pay)"
            aria-label="Refresh page"
          >
            <IconRefresh size={14} />
          </button>

          <button
            class="btn btn-ghost btn-sm"
            onClick={fetchManifest}
            disabled={manifestLoading() || !selectedPeer()}
            title="Fetch site map from peer"
            aria-label="Fetch site map"
          >
            <Show when={manifestLoading()} fallback={<IconSitemap size={14} />}>
              <IconLoader size={14} />
            </Show>
          </button>

          <button
            class="btn btn-ghost btn-sm"
            onClick={addBookmark}
            disabled={!selectedPeer() || !path()}
            title="Bookmark this page"
            aria-label="Bookmark this page"
          >
            <IconBookmark size={14} />
          </button>
        </div>

        <Show when={selectedPeer()}>
          <div class="browser-identity-bar">
            <span class="browser-identity-badge">
              <IconVerified size={12} />
              <span>Ed25519 verified</span>
            </span>
            <span class="browser-identity-id">
              {truncateId(selectedPeer())}
            </span>
            <span class="browser-lock-badge">
              <IconLock size={12} /> E2EE
            </span>
            <Show when={pageTitle()}>
              <span class="browser-page-title-badge">
                <IconDocument size={12} /> {pageTitle()}
              </span>
            </Show>
          </div>
        </Show>
      </div>

      {/* Browse tab — content viewer */}
      <Show when={activeTab() === "browser"}>
        <div class="browser-content card" onClick={handleContentClick}>
          <Show when={loading()}>
            <div class="browser-loading">
              <div class="browser-loading-skeleton">
                <div class="skeleton-line skeleton-title" />
                <div class="skeleton-line skeleton-text" />
                <div class="skeleton-line skeleton-text" />
                <div class="skeleton-line skeleton-short" />
                <div class="skeleton-line skeleton-text" />
              </div>
              <p class="browser-loading-text">
                Fetching page... Payment in progress
              </p>
            </div>
          </Show>

          <Show when={!loading() && pageStatus() === "error"}>
            <div class="browser-error">
              <IconBrowser size={32} />
              <h3>Unable to load page</h3>
              <p>{errorMsg()}</p>
              <button class="btn btn-ghost" onClick={() => browsePage()} aria-label="Retry loading page">
                <IconRefresh size={14} /> Retry
              </button>
            </div>
          </Show>

          <Show when={!loading() && pageStatus() === "ok" && pageContent()}>
            <div class="browser-page-meta">
              <Show when={pageCost() > 0} fallback={
                <span class="browser-cache-badge" title="Served from cache (no payment)">
                  Cached
                </span>
              }>
                <span class="browser-cost-badge">
                  <IconLightning size={12} /> {formatMsat(pageCost())}
                </span>
              </Show>
            </div>
            <div
              class="browser-rendered-content"
              innerHTML={renderMarkdown(pageContent())}
            />
          </Show>

          <Show when={!loading() && !pageStatus()}>
            <div class="browser-empty">
              <IconGlobe size={48} />
              <h3>Peer Sites</h3>
              <p>
                Browse sovereign pages your peers publish on the BitSov mesh.
                Select a peer above, enter a path, and load a page.
              </p>
              <p class="browser-empty-detail">
                Every page is end-to-end encrypted, paid for with a small
                Bitcoin amount, and served directly by the peer's node.
                No DNS, no cloud, no gatekeepers.
              </p>
              <div class="browser-features">
                <div class="browser-feature">
                  <IconLock size={16} />
                  <span>E2E Encrypted</span>
                </div>
                <div class="browser-feature">
                  <IconLightning size={16} />
                  <span>Payment-gated</span>
                </div>
                <div class="browser-feature">
                  <IconVerified size={16} />
                  <span>Ed25519 verified</span>
                </div>
              </div>
            </div>
          </Show>
        </div>
      </Show>

      {/* Manifest / Site Map tab */}
      <Show when={activeTab() === "manifest"}>
        <div class="browser-manifest card">
          <Show
            when={manifest()}
            fallback={
              <div class="browser-empty-list">
                <IconSitemap size={32} />
                <p>
                  No site map loaded. Select a peer and click the site map button
                  to discover available pages and their prices.
                </p>
              </div>
            }
          >
            {(m) => (
              <>
                <div class="browser-manifest-header">
                  <h3>{m().site_name}</h3>
                  <span class="browser-manifest-meta">
                    {m().pages.length} pages | Default: {formatMsat(m().default_price_msat)}/page
                    | Block #{m().block_height.toLocaleString()}
                  </span>
                </div>
                <Show when={m().free_paths.length > 0}>
                  <div class="browser-manifest-free">
                    Free paths: {m().free_paths.join(", ")}
                  </div>
                </Show>
                <div class="browser-manifest-pages">
                  <For each={m().pages}>
                    {(page) => (
                      <button
                        class="browser-manifest-page"
                        onClick={() => navigateFromManifest(page)}
                        aria-label={`Open page: ${page.title}`}
                      >
                        <IconDocument size={14} />
                        <div class="browser-manifest-page-info">
                          <span class="browser-manifest-page-title">{page.title}</span>
                          <span class="browser-manifest-page-path">{page.path}</span>
                        </div>
                        <span class="browser-manifest-page-price">
                          <IconLightning size={10} />
                          {page.price_msat != null
                            ? formatMsat(page.price_msat)
                            : formatMsat(m().default_price_msat)}
                        </span>
                      </button>
                    )}
                  </For>
                </div>
              </>
            )}
          </Show>
        </div>
      </Show>

      {/* Bookmarks tab */}
      <Show when={activeTab() === "bookmarks"}>
        <div class="browser-bookmarks card">
          <Show
            when={bookmarks().length > 0}
            fallback={
              <div class="browser-empty-list">
                <IconBookmark size={32} />
                <p>No bookmarks yet. Browse a page and bookmark it.</p>
              </div>
            }
          >
            <For each={bookmarks()}>
              {(bm, i) => (
                <div class="browser-bookmark-item">
                  <button
                    class="browser-bookmark-link"
                    onClick={() => navigateToBookmark(bm)}
                    aria-label={`Open bookmark: ${bm.title}`}
                  >
                    <IconDocument size={14} />
                    <div class="browser-bookmark-info">
                      <span class="browser-bookmark-title">{bm.title}</span>
                      <span class="browser-bookmark-path">
                        {bm.peerLabel} {bm.path}
                      </span>
                    </div>
                  </button>
                  <button
                    class="btn btn-ghost btn-sm"
                    onClick={() => removeBookmark(i())}
                    title="Remove bookmark"
                    aria-label="Remove bookmark"
                  >
                    <IconTrash size={12} />
                  </button>
                </div>
              )}
            </For>
          </Show>
        </div>
      </Show>

      {/* History tab */}
      <Show when={activeTab() === "history"}>
        <div class="browser-history card">
          <Show
            when={history().length > 0}
            fallback={
              <div class="browser-empty-list">
                <IconClock size={32} />
                <p>No browse history yet.</p>
              </div>
            }
          >
            <For each={history()}>
              {(entry) => (
                <button
                  class="browser-history-item"
                  onClick={() => navigateToHistory(entry)}
                  aria-label={`Open history: ${entry.peerLabel} ${entry.path}`}
                >
                  <IconDocument size={14} />
                  <div class="browser-history-info">
                    <span class="browser-history-path">
                      {entry.peerLabel} {entry.path}
                    </span>
                    <span class="browser-history-meta">
                      {formatTime(entry.timestamp)} |{" "}
                      <IconLightning size={10} /> {formatMsat(entry.costMsat)}
                    </span>
                  </div>
                </button>
              )}
            </For>
          </Show>
        </div>
      </Show>
    </div>
  );
}
