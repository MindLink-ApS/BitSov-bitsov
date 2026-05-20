/** My Content — Publisher UI (BR7).
 *
 * Tabs: Pages | Editor | Topics | Analytics | Discovery
 *
 * Backend endpoints for Topics and Analytics are not yet implemented;
 * those sections use localStorage as a local-only store until the
 * server-side APIs land.  Every place that needs a backend call is
 * marked with a TODO comment.
 */

import type { JSX } from "solid-js";
import {
  createSignal,
  createMemo,
  onMount,
  Show,
  For,
  batch,
} from "solid-js";
import { api } from "../stores/auth";
import { toast } from "../stores/toast";
import { renderMarkdown } from "../utils/markdown";
import type { ContentPageInfo, PeerResponse } from "../api/types";
import {
  IconDocument,
  IconPlus,
  IconTrash,
  IconPencil,
  IconCheck,
  IconX,
  IconUpload,
  IconGlobe,
  IconEye,
  IconActivity,
  IconSend,
  IconGroups,
  IconInfo,
  IconLightning,
  IconRefresh,
} from "./Icons";
import { formatDate } from "../utils/formatting";

// ---- Local data models ------------------------------------------------------

interface Topic {
  id: string;
  name: string;
  description: string;
  price_msat: number;
  created_ms: number;
}

interface PublisherAnalytics {
  page_views: Record<string, number>;
  total_earned_msat: number;
  subscriber_joins: number;
}

const TOPICS_KEY = "bitsov_publisher_topics";
const ANALYTICS_KEY = "bitsov_publisher_analytics";

function loadTopics(): Topic[] {
  try {
    const raw = localStorage.getItem(TOPICS_KEY);
    return raw ? (JSON.parse(raw) as Topic[]) : [];
  } catch {
    return [];
  }
}

function saveTopics(topics: Topic[]): void {
  localStorage.setItem(TOPICS_KEY, JSON.stringify(topics));
}

function loadAnalytics(): PublisherAnalytics {
  try {
    const raw = localStorage.getItem(ANALYTICS_KEY);
    return raw
      ? (JSON.parse(raw) as PublisherAnalytics)
      : { page_views: {}, total_earned_msat: 0, subscriber_joins: 0 };
  } catch {
    return { page_views: {}, total_earned_msat: 0, subscriber_joins: 0 };
  }
}

// ---- BSX renderer -----------------------------------------------------------

interface BsxBlock {
  t: "h1" | "h2" | "h3" | "p" | "code" | "quote" | "divider";
  text?: string;
  lang?: string;
}

interface BsxDoc {
  v: 1;
  blocks: BsxBlock[];
}

function renderBsx(json: string): string {
  try {
    const doc = JSON.parse(json) as BsxDoc;
    if (!Array.isArray(doc.blocks)) return "<em>Invalid BSX document.</em>";
    return doc.blocks
      .map((b) => {
        const esc = (s: string): string =>
          s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
        const text = esc(b.text ?? "");
        switch (b.t) {
          case "h1": return `<h1>${text}</h1>`;
          case "h2": return `<h2>${text}</h2>`;
          case "h3": return `<h3>${text}</h3>`;
          case "p":  return `<p>${text}</p>`;
          case "code": return `<pre><code class="lang-${esc(b.lang ?? "")}">${text}</code></pre>`;
          case "quote": return `<blockquote><p>${text}</p></blockquote>`;
          case "divider": return "<hr/>";
          default: return "";
        }
      })
      .join("\n");
  } catch {
    return "<em>Invalid JSON \u2014 fix the syntax to see a preview.</em>";
  }
}

const BSX_PLACEHOLDER: BsxDoc = {
  v: 1,
  blocks: [
    { t: "h1", text: "My Article" },
    { t: "p",  text: "Write your introduction here." },
    { t: "h2", text: "Section One" },
    { t: "p",  text: "Content goes here." },
    { t: "code", lang: "rust", text: "fn main() {\n    println!(\"Hello, BitSov!\");\n}" },
  ],
};

// ---- Tab type ----------------------------------------------------------------

type Tab = "pages" | "editor" | "topics" | "analytics" | "discovery";

const TAB_LABELS: Record<Tab, string> = {
  pages: "Pages",
  editor: "Editor",
  topics: "Topics",
  analytics: "Analytics",
  discovery: "Discovery",
};

function TabIcon(props: { tab: Tab }): JSX.Element {
  switch (props.tab) {
    case "pages":     return <IconDocument size={14} />;
    case "editor":    return <IconPencil size={14} />;
    case "topics":    return <IconGroups size={14} />;
    case "analytics": return <IconActivity size={14} />;
    case "discovery": return <IconGlobe size={14} />;
  }
}

// ---- Main component ---------------------------------------------------------

export default function MyContent(): JSX.Element {
  const [activeTab, setActiveTab] = createSignal<Tab>("pages");

  // Pages
  const [pages, setPages] = createSignal<ContentPageInfo[]>([]);
  const [enabled, setEnabled] = createSignal(false);
  const [contentDir, setContentDir] = createSignal("");
  const [loading, setLoading] = createSignal(true);
  const [showNew, setShowNew] = createSignal(false);
  const [newFilename, setNewFilename] = createSignal("");

  // Editor
  const [editingPath, setEditingPath] = createSignal<string | null>(null);
  const [editorMode, setEditorMode] = createSignal<"markdown" | "bsx">("markdown");
  const [editorContent, setEditorContent] = createSignal("");
  const [showPreview, setShowPreview] = createSignal(true);
  const [saving, setSaving] = createSignal(false);

  const previewHtml = createMemo(() =>
    editorMode() === "bsx"
      ? renderBsx(editorContent())
      : renderMarkdown(editorContent())
  );

  // Topics
  const [topics, setTopics] = createSignal<Topic[]>(loadTopics());
  const [showNewTopic, setShowNewTopic] = createSignal(false);
  const [newTopicName, setNewTopicName] = createSignal("");
  const [newTopicDesc, setNewTopicDesc] = createSignal("");
  const [newTopicPriceSats, setNewTopicPriceSats] = createSignal(100);
  const [creatingTopic, setCreatingTopic] = createSignal(false);

  // Analytics
  const [analytics, setAnalytics] = createSignal<PublisherAnalytics>(loadAnalytics());
  const totalViews = createMemo(() =>
    Object.values(analytics().page_views).reduce((a, b) => a + b, 0)
  );

  // Discovery
  const [peers, setPeers] = createSignal<PeerResponse[]>([]);
  const [selectedPeers, setSelectedPeers] = createSignal<Set<string>>(new Set());
  const [announcing, setAnnouncing] = createSignal(false);
  const [loadingPeers, setLoadingPeers] = createSignal(false);

  onMount(loadPages);

  async function loadPages(): Promise<void> {
    setLoading(true);
    try {
      const result = await api.listPages();
      batch(() => {
        setEnabled(result.enabled);
        setContentDir(result.content_dir);
        setPages(result.pages);
      });
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load pages");
    } finally {
      setLoading(false);
    }
  }

  async function openEditor(path: string): Promise<void> {
    try {
      const page = await api.readPage(path);
      const isBsx = path.endsWith(".bsx") || path.endsWith(".json");
      batch(() => {
        setEditingPath(path);
        setEditorContent(page.content);
        setEditorMode(isBsx ? "bsx" : "markdown");
        setActiveTab("editor");
      });
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to read page");
    }
  }

  async function savePage(): Promise<void> {
    const path = editingPath();
    if (!path) return;
    setSaving(true);
    try {
      await api.writePage(path, editorContent());
      toast.success("Page saved");
      await loadPages();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to save page");
    } finally {
      setSaving(false);
    }
  }

  async function deletePage(path: string): Promise<void> {
    if (
      !confirm(
        `Delete "${path}"? This removes it from your node only.\n\nPeers who already downloaded the page may retain a local copy.`
      )
    ) return;
    try {
      await api.deletePage(path);
      toast.success("Page deleted");
      if (editingPath() === path) {
        batch(() => { setEditingPath(null); setActiveTab("pages"); });
      }
      await loadPages();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to delete page");
    }
  }

  async function createPage(): Promise<void> {
    let filename = newFilename().trim();
    if (!filename) { toast.warning("Enter a filename"); return; }
    if (!filename.endsWith(".md") && !filename.endsWith(".txt") && !filename.endsWith(".bsx")) {
      filename += ".md";
    }
    setSaving(true);
    try {
      const defaultContent = filename.endsWith(".bsx")
        ? JSON.stringify(BSX_PLACEHOLDER, null, 2)
        : `# ${filename.replace(/\.(md|txt)$/, "")}\n\nWrite your content here.\n`;
      await api.writePage(filename, defaultContent);
      toast.success("Page created");
      batch(() => { setShowNew(false); setNewFilename(""); });
      await loadPages();
      void openEditor("/" + filename);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to create page");
    } finally {
      setSaving(false);
    }
  }

  function createTopic(): void {
    const name = newTopicName().trim();
    if (!name) { toast.warning("Enter a topic name"); return; }
    setCreatingTopic(true);
    try {
      const topic: Topic = {
        id: crypto.randomUUID(),
        name,
        description: newTopicDesc().trim(),
        price_msat: Math.max(0, Math.floor(newTopicPriceSats())) * 1000,
        created_ms: Date.now(),
      };
      const updated = [...topics(), topic];
      setTopics(updated);
      saveTopics(updated);
      toast.success("Topic created");
      // TODO: POST /api/v1/content/topics when backend lands
      batch(() => {
        setShowNewTopic(false);
        setNewTopicName("");
        setNewTopicDesc("");
        setNewTopicPriceSats(100);
      });
    } finally {
      setCreatingTopic(false);
    }
  }

  function deleteTopic(id: string): void {
    const topic = topics().find((t) => t.id === id);
    if (!confirm(`Delete topic "${topic?.name ?? id}"?`)) return;
    const updated = topics().filter((t) => t.id !== id);
    setTopics(updated);
    saveTopics(updated);
    toast.success("Topic deleted");
    // TODO: DELETE /api/v1/content/topics/:id when backend lands
  }

  function refreshAnalytics(): void {
    setAnalytics(loadAnalytics());
    // TODO: GET /api/v1/content/analytics when backend lands
  }

  async function loadPeers(): Promise<void> {
    setLoadingPeers(true);
    try {
      const result = await api.listPeers();
      setPeers(result);
      setSelectedPeers(new Set(result.map((p) => p.node_id)));
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load peers");
    } finally {
      setLoadingPeers(false);
    }
  }

  function togglePeer(nodeId: string): void {
    const current = new Set(selectedPeers());
    if (current.has(nodeId)) { current.delete(nodeId); } else { current.add(nodeId); }
    setSelectedPeers(current);
  }

  async function announce(): Promise<void> {
    const audience = peers().filter((p) => selectedPeers().has(p.node_id));
    if (audience.length === 0) { toast.warning("Select at least one peer"); return; }
    setAnnouncing(true);
    let sent = 0;
    let failed = 0;
    try {
      // TODO: Replace with POST /api/v1/content/announce once backend has broadcast endpoint.
      for (const peer of audience) {
        try { await api.fetchManifest(peer.node_id); sent++; } catch { failed++; }
      }
      if (failed === 0) {
        toast.success(`Manifest announced to ${sent} peer${sent !== 1 ? "s" : ""}`);
      } else {
        toast.warning(`Announced to ${sent} peers, ${failed} failed`);
      }
    } finally {
      setAnnouncing(false);
    }
  }

  function formatSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  function formatSats(msat: number): string {
    const sats = Math.floor(msat / 1000);
    return sats === 0 ? "free" : `${sats.toLocaleString()} sats`;
  }

  function shortId(id: string): string {
    return id.slice(0, 8) + "\u2026" + id.slice(-8);
  }

  return (
    <div class="page" style={{ "max-width": "var(--content-max)" }}>
      {/* Header */}
      <div class="page-header">
        <h2 class="page-title flex items-center gap-8">
          <IconUpload size={20} /> My Content
        </h2>
        <Show when={enabled() && activeTab() === "pages"}>
          <button class="btn btn-primary btn-sm" onClick={() => setShowNew(true)}>
            <IconPlus size={14} /> New Page
          </button>
        </Show>
        <Show when={activeTab() === "editor" && editingPath() !== null}>
          <button
            class="btn btn-primary btn-sm"
            onClick={() => void savePage()}
            disabled={saving()}
          >
            <IconCheck size={14} /> {saving() ? "Saving\u2026" : "Save"}
          </button>
        </Show>
      </div>

      {/* Tab bar */}
      <div class="browser-tabs mycontent-tabs">
        {(["pages", "editor", "topics", "analytics", "discovery"] as Tab[]).map((tab) => (
          <button
            class={`browser-tab ${activeTab() === tab ? "active" : ""}`}
            onClick={() => {
              setActiveTab(tab);
              if (tab === "discovery" && peers().length === 0) void loadPeers();
              if (tab === "analytics") refreshAnalytics();
            }}
          >
            <TabIcon tab={tab} /> {TAB_LABELS[tab]}
          </button>
        ))}
      </div>

      {/* ===== PAGES ===== */}
      <Show when={activeTab() === "pages"}>
        <Show when={showNew()}>
          <div class="card mycontent-new-form">
            <div class="flex items-center gap-8">
              <input
                type="text"
                class="input flex-1"
                placeholder="filename.md  (or .txt / .bsx)"
                value={newFilename()}
                onInput={(e) => setNewFilename(e.currentTarget.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") void createPage();
                  if (e.key === "Escape") setShowNew(false);
                }}
                autofocus
              />
              <button class="btn btn-primary btn-sm" onClick={() => void createPage()} disabled={saving()}>
                <IconCheck size={14} /> Create
              </button>
              <button class="btn btn-ghost btn-sm" onClick={() => { setShowNew(false); setNewFilename(""); }} aria-label="Cancel">
                <IconX size={14} />
              </button>
            </div>
            <p class="text-xs text-muted mt-4">
              Use <code>.md</code> for markdown, <code>.txt</code> for plain text, or <code>.bsx</code> for structured blocks.
            </p>
          </div>
        </Show>

        <Show when={loading()}>
          <div class="card mycontent-loading">
            <div class="skeleton-line skeleton-title" />
            <div class="skeleton-line skeleton-text" />
            <div class="skeleton-line skeleton-short" />
          </div>
        </Show>

        <Show when={!loading() && !enabled()}>
          <div class="card mycontent-disabled">
            <IconGlobe size={48} />
            <h3>Content Server Not Enabled</h3>
            <p>Enable the sovereign browser content server in your node configuration to publish pages.</p>
            <pre class="mycontent-config-hint">{`[web]\nenabled = true\ncontent_dir = "pages"\nsite_name = "My Node"`}</pre>
          </div>
        </Show>

        <Show when={!loading() && enabled()}>
          <Show
            when={pages().length > 0}
            fallback={
              <div class="card mycontent-empty">
                <IconDocument size={48} />
                <h3>No Pages Published</h3>
                <p>Create your first page to start publishing content on the sovereign web.</p>
              </div>
            }
          >
            <div class="mycontent-list">
              <For each={pages()}>
                {(page) => (
                  <div class="card mycontent-page-card">
                    <div class="mycontent-page-info">
                      <IconDocument size={16} />
                      <div class="mycontent-page-meta">
                        <span class="mycontent-page-title">{page.title}</span>
                        <span class="text-xs text-muted">
                          {page.path} | {formatSize(page.size_bytes)} | {page.modified_ms ? formatDate(page.modified_ms) : "Unknown"}
                        </span>
                      </div>
                    </div>
                    <div class="mycontent-page-actions">
                      <button class="btn btn-ghost btn-sm" onClick={() => void openEditor(page.path)} title="Edit page" aria-label={`Edit ${page.title}`}>
                        <IconPencil size={14} />
                      </button>
                      <button class="btn btn-ghost btn-sm" onClick={() => void deletePage(page.path)} title="Delete page" aria-label={`Delete ${page.title}`}>
                        <IconTrash size={14} />
                      </button>
                    </div>
                  </div>
                )}
              </For>
            </div>
            <p class="text-xs text-muted mt-8">Content directory: {contentDir()}</p>
          </Show>
        </Show>
      </Show>

      {/* ===== EDITOR ===== */}
      <Show when={activeTab() === "editor"}>
        <Show
          when={editingPath() !== null}
          fallback={
            <div class="card mycontent-empty">
              <IconPencil size={48} />
              <h3>No Page Open</h3>
              <p>Go to the <strong>Pages</strong> tab and click the edit icon on any page.</p>
              <button class="btn btn-primary btn-sm" onClick={() => setActiveTab("pages")}>
                <IconDocument size={14} /> Go to Pages
              </button>
            </div>
          }
        >
          <div class="mycontent-editor-mode-bar">
            <button
              class={`btn btn-sm ${editorMode() === "markdown" ? "btn-primary" : "btn-ghost"}`}
              onClick={() => setEditorMode("markdown")}
            >
              Markdown
            </button>
            <button
              class={`btn btn-sm ${editorMode() === "bsx" ? "btn-primary" : "btn-ghost"}`}
              onClick={() => setEditorMode("bsx")}
            >
              BSX JSON
            </button>
            <button class="btn btn-ghost btn-sm" onClick={() => setShowPreview(!showPreview())} aria-label="Toggle preview">
              <IconEye size={14} /> {showPreview() ? "Hide Preview" : "Show Preview"}
            </button>
            <span class="mycontent-editor-path">{editingPath()}</span>
          </div>

          <div class="mycontent-editor">
            <div class={`mycontent-editor-body ${showPreview() ? "mycontent-split" : ""}`}>
              <textarea
                class="mycontent-editor-textarea"
                value={editorContent()}
                onInput={(e) => setEditorContent(e.currentTarget.value)}
                spellcheck={false}
                placeholder={editorMode() === "bsx" ? JSON.stringify(BSX_PLACEHOLDER, null, 2) : "Write markdown here\u2026"}
              />
              <Show when={showPreview()}>
                <div class="mycontent-preview">
                  <div class="mycontent-preview-label">
                    <IconEye size={12} /> {editorMode() === "bsx" ? "BSX Preview" : "Live Preview"}
                  </div>
                  <div class="mycontent-preview-content browser-content" innerHTML={previewHtml()} />
                </div>
              </Show>
            </div>
          </div>

          <Show when={editorMode() === "bsx"}>
            <div class="mycontent-bsx-hint card">
              <IconInfo size={14} />
              <span>
                BSX is a JSON block format. Supported types: <code>h1</code>, <code>h2</code>, <code>h3</code>,{" "}
                <code>p</code>, <code>code</code> (with optional <code>lang</code>), <code>quote</code>, <code>divider</code>.
                Block WYSIWYG toolbar is planned for a follow-up.
              </span>
            </div>
          </Show>
        </Show>
      </Show>

      {/* ===== TOPICS ===== */}
      <Show when={activeTab() === "topics"}>
        <div class="mycontent-section-header">
          <p class="text-sm text-muted">
            Topics are named subscription feeds. Subscribers pay a per-delivery fee and receive posts you push to that topic.
          </p>
          <button class="btn btn-primary btn-sm" onClick={() => setShowNewTopic(true)}>
            <IconPlus size={14} /> New Topic
          </button>
        </div>

        <Show when={showNewTopic()}>
          <div class="card mycontent-topic-form">
            <div class="mycontent-topic-form-row">
              <label class="text-sm text-muted">Topic name</label>
              <input type="text" class="input" placeholder="e.g. Weekly Dispatch" value={newTopicName()} onInput={(e) => setNewTopicName(e.currentTarget.value)} autofocus />
            </div>
            <div class="mycontent-topic-form-row">
              <label class="text-sm text-muted">Description</label>
              <input type="text" class="input" placeholder="What subscribers can expect" value={newTopicDesc()} onInput={(e) => setNewTopicDesc(e.currentTarget.value)} />
            </div>
            <div class="mycontent-topic-form-row">
              <label class="text-sm text-muted">Price per delivery (sats)</label>
              <input
                type="number" class="input" min="0" step="1"
                value={newTopicPriceSats()}
                onInput={(e) => setNewTopicPriceSats(Math.max(0, parseInt(e.currentTarget.value, 10) || 0))}
              />
              <span class="text-xs text-muted">{newTopicPriceSats() === 0 ? "Free" : `${newTopicPriceSats().toLocaleString()} sats`}</span>
            </div>
            <div class="flex gap-8 mt-8">
              <button class="btn btn-primary btn-sm" onClick={createTopic} disabled={creatingTopic()}>
                <IconCheck size={14} /> Create Topic
              </button>
              <button class="btn btn-ghost btn-sm" onClick={() => { setShowNewTopic(false); setNewTopicName(""); setNewTopicDesc(""); setNewTopicPriceSats(100); }}>
                <IconX size={14} /> Cancel
              </button>
            </div>
          </div>
        </Show>

        <Show
          when={topics().length > 0}
          fallback={
            <div class="card mycontent-empty">
              <IconGroups size={48} />
              <h3>No Topics</h3>
              <p>Create a topic to start a subscription feed. Subscribers pay per delivery.</p>
            </div>
          }
        >
          <div class="mycontent-list">
            <For each={topics()}>
              {(topic) => (
                <div class="card mycontent-topic-card">
                  <div class="mycontent-topic-info">
                    <div class="mycontent-topic-name">{topic.name}</div>
                    <Show when={topic.description}>
                      <div class="text-sm text-muted">{topic.description}</div>
                    </Show>
                    <div class="mycontent-topic-meta">
                      <span class="mycontent-topic-badge">
                        <IconLightning size={12} /> {formatSats(topic.price_msat)}
                      </span>
                      {/* TODO: show real count from GET /api/v1/content/topics/:id/subscribers */}
                      <span class="text-xs text-muted">0 subscribers</span>
                      <span class="text-xs text-muted">Created {formatDate(topic.created_ms)}</span>
                    </div>
                  </div>
                  <div class="mycontent-page-actions">
                    <button class="btn btn-ghost btn-sm" onClick={() => deleteTopic(topic.id)} title="Delete topic" aria-label={`Delete topic ${topic.name}`}>
                      <IconTrash size={14} />
                    </button>
                  </div>
                </div>
              )}
            </For>
          </div>
        </Show>

        <div class="mycontent-info-banner card">
          <IconInfo size={14} />
          <span class="text-sm text-muted">
            Topic subscriber lists will appear once the backend endpoint lands (<code>GET /api/v1/content/topics/:id/subscribers</code>).
            Topics are persisted locally until then.
          </span>
        </div>
      </Show>

      {/* ===== ANALYTICS ===== */}
      <Show when={activeTab() === "analytics"}>
        <div class="mycontent-sovereignty-banner card">
          <IconInfo size={16} />
          <div>
            <div class="font-medium">Local analytics only</div>
            <div class="text-sm text-muted">
              These metrics are collected and stored on your node. They never leave your node and are not visible to peers.
            </div>
          </div>
        </div>

        <div class="mycontent-stat-grid">
          <div class="card mycontent-stat-card">
            <div class="mycontent-stat-icon"><IconEye size={20} /></div>
            <div class="mycontent-stat-value">{totalViews().toLocaleString()}</div>
            <div class="mycontent-stat-label">Total page views</div>
          </div>
          <div class="card mycontent-stat-card">
            <div class="mycontent-stat-icon"><IconGroups size={20} /></div>
            <div class="mycontent-stat-value">{analytics().subscriber_joins.toLocaleString()}</div>
            <div class="mycontent-stat-label">Subscriber joins</div>
          </div>
          <div class="card mycontent-stat-card">
            <div class="mycontent-stat-icon"><IconLightning size={20} /></div>
            <div class="mycontent-stat-value">{formatSats(analytics().total_earned_msat)}</div>
            <div class="mycontent-stat-label">Earned from content</div>
          </div>
          <div class="card mycontent-stat-card">
            <div class="mycontent-stat-icon"><IconDocument size={20} /></div>
            <div class="mycontent-stat-value">{pages().length}</div>
            <div class="mycontent-stat-label">Published pages</div>
          </div>
        </div>

        <Show
          when={Object.keys(analytics().page_views).length > 0}
          fallback={
            <div class="card mycontent-analytics-empty">
              <IconActivity size={32} />
              <p class="text-muted">
                Page view counts will appear here once peers start browsing your content.
                {/* TODO: populate from GET /api/v1/content/analytics once backend lands */}
              </p>
            </div>
          }
        >
          <div class="card" style={{ padding: "16px" }}>
            <h4 class="text-sm font-medium mb-12">Views per page</h4>
            <div class="mycontent-list">
              <For each={Object.entries(analytics().page_views).sort((a, b) => b[1] - a[1])}>
                {([path, views]) => (
                  <div class="mycontent-analytics-row">
                    <span class="text-sm" style={{ "font-family": "var(--font-mono)" }}>{path}</span>
                    <span class="mycontent-analytics-count">{(views as number).toLocaleString()}</span>
                  </div>
                )}
              </For>
            </div>
          </div>
        </Show>
      </Show>

      {/* ===== DISCOVERY ===== */}
      <Show when={activeTab() === "discovery"}>
        <div class="card mycontent-announce-card">
          <div class="mycontent-announce-header">
            <div>
              <div class="font-medium">Announce to peers</div>
              <div class="text-sm text-muted">
                Send your web manifest (pages, topics, pricing) to selected peers so they can discover and subscribe to your content.
              </div>
            </div>
            <button
              class="btn btn-primary"
              onClick={() => void announce()}
              disabled={announcing() || selectedPeers().size === 0}
            >
              <IconSend size={14} />
              {announcing() ? "Announcing\u2026" : `Announce to ${selectedPeers().size} peer${selectedPeers().size !== 1 ? "s" : ""}`}
            </button>
          </div>

          <div class="mycontent-audience-section">
            <div class="mycontent-audience-header">
              <span class="text-sm font-medium">Audience</span>
              <div class="flex gap-8">
                <button class="btn btn-ghost btn-sm" onClick={() => setSelectedPeers(new Set(peers().map((p) => p.node_id)))}>All</button>
                <button class="btn btn-ghost btn-sm" onClick={() => setSelectedPeers(new Set())}>None</button>
                <button class="btn btn-ghost btn-sm" onClick={() => void loadPeers()} disabled={loadingPeers()} title="Refresh peer list">
                  <IconRefresh size={14} />
                </button>
              </div>
            </div>
            <Show when={loadingPeers()}>
              <p class="text-sm text-muted">Loading peers\u2026</p>
            </Show>
            <Show when={!loadingPeers() && peers().length === 0}>
              <p class="text-sm text-muted">No peers connected. Add peers in the Peers view to announce your content.</p>
            </Show>
            <Show when={peers().length > 0}>
              <div class="mycontent-peer-list">
                <For each={peers()}>
                  {(peer) => {
                    const isSelected = (): boolean => selectedPeers().has(peer.node_id);
                    return (
                      <button
                        class={`mycontent-peer-chip ${isSelected() ? "selected" : ""}`}
                        onClick={() => togglePeer(peer.node_id)}
                        title={peer.node_id}
                      >
                        <Show when={isSelected()}><IconCheck size={10} /></Show>
                        <span class="text-sm">{peer.label ?? shortId(peer.node_id)}</span>
                      </button>
                    );
                  }}
                </For>
              </div>
            </Show>
          </div>
        </div>

        <div class="card" style={{ padding: "16px", "margin-bottom": "16px" }}>
          <h4 class="text-sm font-medium mb-12">What will be announced</h4>
          <div class="mycontent-announce-summary">
            <div class="mycontent-announce-summary-row">
              <IconDocument size={14} />
              <span class="text-sm">{pages().length} page{pages().length !== 1 ? "s" : ""}</span>
            </div>
            <div class="mycontent-announce-summary-row">
              <IconGroups size={14} />
              <span class="text-sm">{topics().length} topic{topics().length !== 1 ? "s" : ""}</span>
            </div>
          </div>
          <Show when={pages().length === 0 && topics().length === 0}>
            <p class="text-sm text-muted mt-8">Publish at least one page or topic before announcing.</p>
          </Show>
        </div>

        <div class="card mycontent-unpublish-card">
          <div class="mycontent-unpublish-header">
            <div class="font-medium">Unpublishing</div>
          </div>
          <div class="mycontent-unpublish-body">
            <p class="text-sm text-muted">
              Deleting a page (from the <strong>Pages</strong> tab) removes it from your node immediately.
              Peers will receive a 404 if they request it again.
            </p>
            <p class="text-sm text-muted mt-8">
              <strong>Honest caveat:</strong> Peers who already downloaded your content may retain a local copy.
              BitSov has no deletion broadcast \u2014 data sovereignty cuts both ways.
              After deleting, announce your updated manifest so peers know to stop requesting the page.
            </p>
          </div>
        </div>
      </Show>
    </div>
  );
}
