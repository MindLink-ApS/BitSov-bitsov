/**
 * Inbox — Email-shaped message view.
 * Same data as Messages but presented in email format with From, Subject,
 * Preview, Inbox/Sent/Drafts folders, Forward, and CC.
 * Uses KIND_LONGFORM (1) for email-shaped messages, KIND_CHAT (0) for quick.
 */

import { createSignal, Show, For, onMount, createMemo } from "solid-js";
import { nodeId, api } from "../stores/auth";
import { peers, refreshPeers } from "../stores/peers";
import { messages, loadMessages, composeMessage, getConversationMessages, getConversations } from "../stores/messages";
import { refreshBalance, formatMsat, getPrice } from "../stores/payments";
import { toast } from "../stores/toast";
import { MessageKind, type MessageResponse } from "../api/types";
import {
  IconInbox,
  IconSend,
  IconDraft,
  IconMail,
  IconForward,
  IconReply,
  IconArrowLeft,
  IconPlus,
  IconTrash,
  IconClock,
  IconUser,
} from "./Icons";
import { truncateId, formatDate } from "../utils/formatting";
import { loadJSON, saveJSON, loadString, saveString } from "../utils/storage";

// ── Types ─────────────────────────────────────────────────────────

interface ParsedMail {
  subject: string;
  body: string;
  cc: string[];
  signature: string;
}

interface Draft {
  id: string;
  to: string;
  cc: string[];
  subject: string;
  body: string;
  signature: string;
  savedAt: number;
}

type Folder = "inbox" | "sent" | "drafts";

// ── Helpers ───────────────────────────────────────────────────────

/** Parse longform message plaintext into structured mail fields. */
function parseMail(plaintext: string | undefined): ParsedMail {
  if (!plaintext) return { subject: "(Encrypted)", body: "", cc: [], signature: "" };

  // Format: "Subject: ...\nCC: ...\n---\nBody\n--\nSignature"
  const lines = plaintext.split("\n");
  let subject = "";
  let cc: string[] = [];
  let bodyStart = 0;

  for (let i = 0; i < lines.length; i++) {
    if (lines[i].startsWith("Subject: ")) {
      subject = lines[i].slice(9);
    } else if (lines[i].startsWith("CC: ")) {
      cc = lines[i].slice(4).split(",").map(s => s.trim()).filter(Boolean);
    } else if (lines[i] === "---") {
      bodyStart = i + 1;
      break;
    } else {
      // No structured headers — treat entire text as body
      bodyStart = 0;
      break;
    }
  }

  const rest = lines.slice(bodyStart).join("\n");
  const sigIndex = rest.lastIndexOf("\n--\n");
  const body = sigIndex >= 0 ? rest.slice(0, sigIndex) : rest;
  const signature = sigIndex >= 0 ? rest.slice(sigIndex + 4) : "";

  if (!subject) {
    subject = body.split("\n")[0]?.slice(0, 80) || "(No subject)";
  }

  return { subject, body, cc, signature };
}

/** Format longform message for sending. */
function formatMail(to: string, cc: string[], subject: string, body: string, signature: string): string {
  const parts: string[] = [];
  parts.push(`Subject: ${subject}`);
  if (cc.length > 0) parts.push(`CC: ${cc.join(", ")}`);
  parts.push("---");
  parts.push(body);
  if (signature.trim()) {
    parts.push("--");
    parts.push(signature);
  }
  return parts.join("\n");
}

function peerLabel(id: string): string {
  const peer = peers.find(p => p.node_id === id);
  return peer?.label ?? `${id.slice(0, 8)}...${id.slice(-6)}`;
}

function formatFullDate(ts: number): string {
  return new Date(ts).toLocaleString([], {
    weekday: "long", year: "numeric", month: "long", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

// ── Draft persistence ─────────────────────────────────────────────

function loadDrafts(): Draft[] {
  return loadJSON<Draft[]>("konsensus_inbox_drafts", []);
}

function saveDrafts(drafts: Draft[]): void {
  saveJSON("konsensus_inbox_drafts", drafts);
}

// ── Component ─────────────────────────────────────────────────────

export default function Inbox() {
  const [folder, setFolder] = createSignal<Folder>("inbox");
  const [selectedId, setSelectedId] = createSignal<string | null>(null);
  const [composing, setComposing] = createSignal(false);
  const [drafts, setDrafts] = createSignal<Draft[]>(loadDrafts());

  // Compose state
  const [composeTo, setComposeTo] = createSignal("");
  const [composeCc, setComposeCc] = createSignal("");
  const [composeSubject, setComposeSubject] = createSignal("");
  const [composeBody, setComposeBody] = createSignal("");
  const [composeSignature, setComposeSignature] = createSignal(
    loadString("konsensus_mail_signature") ?? ""
  );
  const [sending, setSending] = createSignal(false);
  const [longformPrice, setLongformPrice] = createSignal<number | null>(null);

  const myId = () => nodeId() ?? "";

  onMount(async () => {
    refreshPeers();
    loadMessages(200);
    try {
      const p = await getPrice(MessageKind.LONGFORM);
      setLongformPrice(p);
    } catch { /* no-op */ }
  });

  // ── Mail items by folder ────────────────────────────────────────

  const allMessages = createMemo(() => {
    const ids = messages.ordered;
    return ids.map(id => messages.byId[id]).filter((m): m is MessageResponse => !!m);
  });

  const inboxMessages = createMemo(() =>
    allMessages()
      .filter(m => m.sender !== myId() && (m.kind === MessageKind.LONGFORM || m.kind === MessageKind.REPLY))
      .sort((a, b) => b.timestamp - a.timestamp)
  );

  const sentMessages = createMemo(() =>
    allMessages()
      .filter(m => m.sender === myId() && (m.kind === MessageKind.LONGFORM || m.kind === MessageKind.REPLY))
      .sort((a, b) => b.timestamp - a.timestamp)
  );

  const currentItems = () => {
    if (folder() === "drafts") return [];
    return folder() === "inbox" ? inboxMessages() : sentMessages();
  };

  const selectedMessage = () => {
    const id = selectedId();
    if (!id) return null;
    return messages.byId[id] ?? null;
  };

  // ── Actions ─────────────────────────────────────────────────────

  const openCompose = (prefill?: { to?: string; subject?: string; body?: string }) => {
    setComposeTo(prefill?.to ?? "");
    setComposeCc("");
    setComposeSubject(prefill?.subject ?? "");
    setComposeBody(prefill?.body ?? "");
    setComposing(true);
    setSelectedId(null);
  };

  const handleSend = async () => {
    const to = composeTo().trim();
    if (!to || !composeBody().trim()) return;

    setSending(true);
    try {
      const plaintext = formatMail(
        to,
        composeCc().split(",").map(s => s.trim()).filter(Boolean),
        composeSubject().trim() || "(No subject)",
        composeBody(),
        composeSignature(),
      );

      await composeMessage(to, MessageKind.LONGFORM, plaintext);
      // Save signature for next time
      saveString("konsensus_mail_signature", composeSignature());
      toast.success("Mail sent");
      setComposing(false);
      refreshBalance();
      loadMessages(200);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to send");
    } finally {
      setSending(false);
    }
  };

  const handleSaveDraft = () => {
    const draft: Draft = {
      id: crypto.randomUUID(),
      to: composeTo(),
      cc: composeCc().split(",").map(s => s.trim()).filter(Boolean),
      subject: composeSubject(),
      body: composeBody(),
      signature: composeSignature(),
      savedAt: Date.now(),
    };
    const updated = [draft, ...drafts()];
    setDrafts(updated);
    saveDrafts(updated);
    setComposing(false);
    toast.success("Draft saved");
  };

  const openDraft = (draft: Draft) => {
    setComposeTo(draft.to);
    setComposeCc(draft.cc.join(", "));
    setComposeSubject(draft.subject);
    setComposeBody(draft.body);
    setComposeSignature(draft.signature);
    // Remove from drafts
    const updated = drafts().filter(d => d.id !== draft.id);
    setDrafts(updated);
    saveDrafts(updated);
    setComposing(true);
    setSelectedId(null);
  };

  const deleteDraft = (id: string) => {
    const updated = drafts().filter(d => d.id !== id);
    setDrafts(updated);
    saveDrafts(updated);
  };

  const handleForward = (msg: MessageResponse) => {
    const parsed = parseMail(msg.plaintext);
    openCompose({
      subject: `Fwd: ${parsed.subject}`,
      body: `\n\n---------- Forwarded message ----------\nFrom: ${peerLabel(msg.sender)}\nDate: ${formatFullDate(msg.timestamp)}\nSubject: ${parsed.subject}\n\n${parsed.body}`,
    });
  };

  const handleReply = (msg: MessageResponse) => {
    const parsed = parseMail(msg.plaintext);
    openCompose({
      to: msg.sender,
      subject: `Re: ${parsed.subject}`,
      body: `\n\n> ${parsed.body.split("\n").join("\n> ")}`,
    });
  };

  // ── Render ──────────────────────────────────────────────────────

  return (
    <div class="page content-max">
      <div class="page-header flex items-center justify-between">
        <h2 class="page-title">Inbox</h2>
        <button class="btn btn-primary btn-sm icon-text" onClick={() => openCompose()}>
          <IconPlus size={14} /> Compose
        </button>
      </div>

      {/* Folder tabs */}
      <div class="inbox-tabs flex gap-2 mb-16">
        <button
          class={`inbox-tab ${folder() === "inbox" ? "active" : ""}`}
          onClick={() => { setFolder("inbox"); setSelectedId(null); setComposing(false); }}
        >
          <IconInbox size={14} /> Inbox
          <Show when={inboxMessages().length > 0}>
            <span class="inbox-tab-count">{inboxMessages().length}</span>
          </Show>
        </button>
        <button
          class={`inbox-tab ${folder() === "sent" ? "active" : ""}`}
          onClick={() => { setFolder("sent"); setSelectedId(null); setComposing(false); }}
        >
          <IconSend size={14} /> Sent
        </button>
        <button
          class={`inbox-tab ${folder() === "drafts" ? "active" : ""}`}
          onClick={() => { setFolder("drafts"); setSelectedId(null); setComposing(false); }}
        >
          <IconDraft size={14} /> Drafts
          <Show when={drafts().length > 0}>
            <span class="inbox-tab-count">{drafts().length}</span>
          </Show>
        </button>
      </div>

      {/* Compose view */}
      <Show when={composing()}>
        <div class="card animate-fade-in mb-16">
          <div class="card-header flex items-center justify-between">
            <span class="icon-text">
              <IconMail size={16} /> New Mail
            </span>
            <button class="btn btn-ghost btn-sm" onClick={() => {
              // Auto-save draft if there's content
              if (composeTo().trim() || composeSubject().trim() || composeBody().trim()) {
                handleSaveDraft();
              } else {
                setComposing(false);
              }
            }}>Cancel</button>
          </div>
          <div class="flex-col gap-8">
            {/* To field */}
            <div class="inbox-field">
              <label class="inbox-field-label">To</label>
              <select
                value={composeTo()}
                onInput={(e) => setComposeTo(e.currentTarget.value)}
                class="flex-1"
              >
                <option value="">Select peer...</option>
                <For each={peers}>
                  {(peer) => (
                    <option value={peer.node_id}>
                      {peer.label ?? truncateId(peer.node_id)}
                    </option>
                  )}
                </For>
              </select>
            </div>

            {/* CC field */}
            <div class="inbox-field">
              <label class="inbox-field-label">CC</label>
              <input
                type="text"
                value={composeCc()}
                onInput={(e) => setComposeCc(e.currentTarget.value)}
                placeholder="Node IDs, comma-separated (optional)"
                class="flex-1"
              />
            </div>

            {/* Subject */}
            <div class="inbox-field">
              <label class="inbox-field-label">Subject</label>
              <input
                type="text"
                value={composeSubject()}
                onInput={(e) => setComposeSubject(e.currentTarget.value)}
                placeholder="Subject"
                class="flex-1"
              />
            </div>

            {/* Body */}
            <textarea
              value={composeBody()}
              onInput={(e) => setComposeBody(e.currentTarget.value)}
              placeholder="Write your message..."
              rows={10}
              class="resize-vertical"
              style={{ "min-height": "150px" }}
            />

            {/* Signature */}
            <div class="inbox-field">
              <label class="inbox-field-label">Signature</label>
              <input
                type="text"
                value={composeSignature()}
                onInput={(e) => setComposeSignature(e.currentTarget.value)}
                placeholder="Your signature (optional)"
                class="flex-1"
              />
            </div>

            {/* Actions */}
            <div class="flex items-center gap-8 mt-4">
              <button
                class="btn btn-primary btn-sm icon-text"
                onClick={handleSend}
                disabled={sending() || !composeTo() || !composeBody().trim()}
              >
                <IconSend size={14} /> {sending() ? "Sending..." : "Send"}
              </button>
              <button
                class="btn btn-secondary btn-sm icon-text"
                onClick={handleSaveDraft}
              >
                <IconDraft size={14} /> Save Draft
              </button>
              <Show when={longformPrice() !== null}>
                <span class="text-xs text-muted ml-auto">
                  Cost: {formatMsat(longformPrice()!)} per message
                </span>
              </Show>
            </div>
          </div>
        </div>
      </Show>

      {/* Detail view */}
      <Show when={!composing() && selectedMessage()}>
        {(msg) => {
          const parsed = () => parseMail(msg().plaintext);
          return (
            <div class="card animate-fade-in mb-16">
              {/* Header */}
              <div class="flex items-center gap-8 mb-12">
                <button class="btn btn-ghost btn-sm" onClick={() => setSelectedId(null)}>
                  <IconArrowLeft size={16} />
                </button>
                <h3 class="text-lg font-semibold flex-1">{parsed().subject}</h3>
              </div>

              {/* Meta */}
              <div class="inbox-meta mb-16">
                <div class="inbox-meta-row">
                  <span class="text-xs text-muted">From:</span>
                  <span class="text-sm">{peerLabel(msg().sender)}</span>
                </div>
                <div class="inbox-meta-row">
                  <span class="text-xs text-muted">To:</span>
                  <span class="text-sm">{peerLabel(msg().recipient)}</span>
                </div>
                <Show when={parsed().cc.length > 0}>
                  <div class="inbox-meta-row">
                    <span class="text-xs text-muted">CC:</span>
                    <span class="text-sm">{parsed().cc.map(peerLabel).join(", ")}</span>
                  </div>
                </Show>
                <div class="inbox-meta-row">
                  <span class="text-xs text-muted">Date:</span>
                  <span class="text-sm">{formatFullDate(msg().timestamp)}</span>
                </div>
                <div class="inbox-meta-row">
                  <span class="text-xs text-muted">Payment:</span>
                  <span class="text-sm text-accent">{formatMsat(msg().payment_amount_msat)}</span>
                </div>
              </div>

              {/* Body */}
              <div class="inbox-body inbox-body-content">
                {parsed().body}
              </div>

              {/* Signature */}
              <Show when={parsed().signature}>
                <div class="inbox-signature">
                  {parsed().signature}
                </div>
              </Show>

              {/* Actions */}
              <div class="inbox-actions-bar">
                <button
                  class="btn btn-secondary btn-sm icon-text"
                  onClick={() => handleReply(msg())}
                  aria-label="Reply to this message"
                >
                  <IconReply size={14} /> Reply
                </button>
                <button
                  class="btn btn-secondary btn-sm icon-text"
                  onClick={() => handleForward(msg())}
                  aria-label="Forward this message"
                >
                  <IconForward size={14} /> Forward
                </button>
              </div>
            </div>
          );
        }}
      </Show>

      {/* Message list */}
      <Show when={!composing() && !selectedMessage()}>
        <Show when={folder() === "drafts"}>
          {/* Drafts list */}
          <Show when={drafts().length > 0} fallback={
            <div class="card">
              <div class="empty-state">
                <IconDraft size={32} />
                <div class="empty-title">No drafts</div>
                <div class="empty-description">Saved drafts will appear here</div>
              </div>
            </div>
          }>
            <div class="card">
              <For each={drafts()}>
                {(draft) => (
                  <div class="inbox-item" onClick={() => openDraft(draft)}>
                    <div class="inbox-item-header">
                      <span class="inbox-item-from">
                        <IconUser size={12} />
                        {draft.to ? peerLabel(draft.to) : "No recipient"}
                      </span>
                      <span class="inbox-item-date">
                        <IconClock size={12} /> {formatDate(draft.savedAt)}
                      </span>
                    </div>
                    <div class="inbox-item-subject">{draft.subject || "(No subject)"}</div>
                    <div class="inbox-item-preview">{draft.body.slice(0, 100)}</div>
                    <button
                      class="btn btn-ghost btn-sm inbox-item-delete"
                      onClick={(e) => { e.stopPropagation(); deleteDraft(draft.id); }}
                      title="Delete draft"
                      aria-label="Delete draft"
                    >
                      <IconTrash size={14} />
                    </button>
                  </div>
                )}
              </For>
            </div>
          </Show>
        </Show>

        <Show when={folder() !== "drafts"}>
          <Show when={currentItems().length > 0} fallback={
            <div class="card">
              <div class="empty-state">
                <IconMail size={32} />
                <div class="empty-title">
                  {folder() === "inbox" ? "No mail yet" : "No sent mail"}
                </div>
                <div class="empty-description">
                  {folder() === "inbox"
                    ? "Long-form messages from peers will appear here"
                    : "Mail you send will appear here"}
                </div>
              </div>
            </div>
          }>
            <div class="card">
              <For each={currentItems()}>
                {(msg) => {
                  const parsed = parseMail(msg.plaintext);
                  const from = folder() === "inbox" ? msg.sender : msg.recipient;
                  return (
                    <div
                      class="inbox-item"
                      onClick={() => setSelectedId(msg.id)}
                    >
                      <div class="inbox-item-header">
                        <span class="inbox-item-from">
                          <IconUser size={12} />
                          {peerLabel(from)}
                        </span>
                        <span class="inbox-item-date">
                          {formatDate(msg.timestamp)}
                        </span>
                      </div>
                      <div class="inbox-item-subject">{parsed.subject}</div>
                      <div class="inbox-item-preview">
                        {parsed.body.slice(0, 120)}
                      </div>
                    </div>
                  );
                }}
              </For>
            </div>
          </Show>
        </Show>
      </Show>
    </div>
  );
}
