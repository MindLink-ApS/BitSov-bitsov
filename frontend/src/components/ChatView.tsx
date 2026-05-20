/**
 * ChatView — layout coordinator for the chat feature.
 *
 * Owns shared state (active conversation, scroll position, search overlay)
 * and composes ConversationList, MessageBubble, and ComposeArea. Message feed
 * scroll logic and load-more handling live here because they depend on DOM refs
 * that span the feed and the compose area.
 */

import { createSignal, createEffect, createMemo, For, Show, onMount, onCleanup } from "solid-js";
import { useNavigate } from "@solidjs/router";
import {
  messages,
  getConversations,
  getConversationMessages,
  initMessages,
  markConversationRead,
  loadOlderMessages,
  loadConversationMessages,
  hasMoreMessages,
  loadingOlder,
} from "../stores/messages";
import { nodeId } from "../stores/auth";
import { peers, refreshPeers } from "../stores/peers";
import { refreshBalance } from "../stores/payments";
import { api } from "../stores/auth";
import { isRoomKey, refreshRooms, pendingConversation, setPendingConversation, roomsById } from "../stores/rooms";
import { PENDING_CONVERSATION_KEY } from "../state/onboarding";
import {
  IconSearch,
  IconMessages,
  IconGroups,
  IconArrowDown,
  IconEncrypted,
  IconRefresh,
} from "./Icons";
import { truncateId, formatRelativeTime } from "../utils/formatting";
import ConversationList, { peerLabel } from "./ConversationList";
import MessageBubble from "./MessageBubble";
import ComposeArea from "./ComposeArea";

interface PendingConversation {
  key: string;
  isRoom: boolean;
}

function takePendingConversationFromStorage(): PendingConversation | null {
  let raw: string | null = null;
  try {
    raw = sessionStorage.getItem(PENDING_CONVERSATION_KEY);
    if (raw) {
      sessionStorage.removeItem(PENDING_CONVERSATION_KEY);
    }
  } catch {
    return null;
  }
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Partial<PendingConversation>;
    if (typeof parsed.key === "string" && typeof parsed.isRoom === "boolean") {
      return { key: parsed.key, isRoom: parsed.isRoom };
    }
  } catch {
    // Ignore malformed handoff state; the chat view still loads normally.
  }
  return null;
}

// ---------------------------------------------------------------------------
// SearchOverlay — message full-text search, scoped to ChatView
// ---------------------------------------------------------------------------

function SearchOverlay(props: {
  open: boolean;
  onClose: () => void;
  onSelect: (convKey: string) => void;
}) {
  const [query, setQuery] = createSignal("");
  let inputRef: HTMLInputElement | undefined;

  createEffect(() => {
    if (props.open && inputRef) {
      inputRef.focus();
      setQuery("");
    }
  });

  const results = createMemo(() => {
    const q = query().toLowerCase().trim();
    if (!q) return [];
    const hits: { msg: typeof messages.byId[string]; convKey: string }[] = [];
    for (const id of messages.ordered) {
      if (hits.length >= 20) break;
      const msg = messages.byId[id];
      if (!msg) continue;
      const text = msg.plaintext?.toLowerCase() ?? "";
      if (text.includes(q)) {
        const myId = nodeId() ?? "";
        const convKey = msg.sender === myId ? msg.recipient : msg.sender;
        hits.push({ msg, convKey });
      }
    }
    return hits;
  });

  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Escape") props.onClose();
  };

  return (
    <Show when={props.open}>
      <div class="search-overlay" onClick={props.onClose} onKeyDown={handleKeyDown}>
        <div class="search-panel glass" onClick={(e) => e.stopPropagation()}>
          <div class="search-input-row">
            <span class="search-icon">
              <IconSearch size={16} />
            </span>
            <input
              ref={inputRef}
              class="search-input"
              type="text"
              placeholder="Search messages..."
              value={query()}
              onInput={(e) => setQuery(e.currentTarget.value)}
              onKeyDown={handleKeyDown}
              aria-label="Search messages"
            />
            <span class="text-xs text-muted">ESC</span>
          </div>
          <Show when={query().trim().length > 0}>
            <div class="search-results">
              <Show when={results().length === 0}>
                <div
                  class="empty-state py-16"
                  style={{ "padding-left": "16px", "padding-right": "16px" }}
                >
                  <div class="empty-state-title text-sm">No results</div>
                  <div class="empty-state-desc text-xs">
                    No messages match "{query()}"
                  </div>
                </div>
              </Show>
              <For each={results()}>
                {(hit) => (
                  <button
                    class="search-result-item"
                    onClick={() => {
                      props.onSelect(hit.convKey);
                      props.onClose();
                    }}
                  >
                    <div class="flex justify-between items-center">
                      <span class="text-sm font-medium">{peerLabel(hit.convKey)}</span>
                      <span class="text-xs text-muted">
                        {formatRelativeTime(hit.msg.timestamp)}
                      </span>
                    </div>
                    <div class="truncate text-xs text-muted mt-2">
                      {hit.msg.plaintext?.slice(0, 100)}
                    </div>
                  </button>
                )}
              </For>
            </div>
          </Show>
        </div>
      </div>
    </Show>
  );
}

// ---------------------------------------------------------------------------
// ChatView
// ---------------------------------------------------------------------------

export default function ChatView() {
  const navigate = useNavigate();
  const [activeConv, setActiveConv] = createSignal<string | null>(null);
  const [searchOpen, setSearchOpen] = createSignal(false);
  const [pendingQuote, setPendingQuote] = createSignal<string | null>(null);
  const [pendingReply, setPendingReply] = createSignal<import("../api/types").MessageResponse | null>(null);
  const [showScrollBtn, setShowScrollBtn] = createSignal(false);
  const [newMsgBelow, setNewMsgBelow] = createSignal(false);
  const [activeRoomMemberCount, setActiveRoomMemberCount] = createSignal<number | null>(null);
  let messagesEndRef: HTMLDivElement | undefined;
  let msgFeedRef: HTMLDivElement | undefined;
  let prevMsgCount = 0;

  const isNearBottom = () => {
    if (!msgFeedRef) return true;
    return msgFeedRef.scrollHeight - msgFeedRef.scrollTop - msgFeedRef.clientHeight < 80;
  };

  const isNearTop = () => {
    if (!msgFeedRef) return false;
    return msgFeedRef.scrollTop < 60;
  };

  const scrollToBottom = () => {
    messagesEndRef?.scrollIntoView({ behavior: "smooth" });
    setNewMsgBelow(false);
  };

  /** Scroll a specific message element into view (for jump-to-parent). */
  const scrollToMessage = (messageId: string) => {
    const el = msgFeedRef?.querySelector(`[data-msg-id="${messageId}"]`);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "center" });
      el.classList.add("msg-highlight");
      setTimeout(() => el.classList.remove("msg-highlight"), 1500);
    }
  };

  const handleLoadOlder = async () => {
    const conv = activeConv();
    if (!conv || loadingOlder() || !hasMoreMessages(conv)) return;
    const feed = msgFeedRef;
    const prevHeight = feed?.scrollHeight ?? 0;
    await loadOlderMessages(conv);
    if (feed) {
      feed.scrollTop += feed.scrollHeight - prevHeight;
    }
  };

  onMount(() => {
    const myId = nodeId();
    if (myId) {
      const unsub = initMessages(myId);
      onCleanup(unsub);
    }
    refreshPeers();
    refreshBalance();
    refreshRooms();

    const pending = takePendingConversationFromStorage() ?? pendingConversation();
    if (pending) {
      setActiveConv(pending.key);
      setPendingConversation(null);
      if (window.location.pathname !== "/chat") {
        navigate("/chat", { replace: true });
      }
    }
  });

  onMount(() => {
    const handleGlobalKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        setSearchOpen(true);
      }
    };
    document.addEventListener("keydown", handleGlobalKeyDown);
    onCleanup(() => document.removeEventListener("keydown", handleGlobalKeyDown));
  });

  createEffect(() => {
    const conv = activeConv();
    if (conv) {
      loadConversationMessages(conv)
        .then(() => messagesEndRef?.scrollIntoView({ behavior: "smooth" }))
        .catch((e: unknown) => {
          console.warn("Failed to load conversation messages:", e instanceof Error ? e.message : e);
        });
      markConversationRead(conv);
    }
  });

  // Track room member count so we can show a proper empty state for 0-member groups.
  createEffect(() => {
    const conv = activeConv();
    if (!conv || !isRoomKey(conv)) {
      setActiveRoomMemberCount(null);
      return;
    }
    setActiveRoomMemberCount(null); // reset while loading
    api.listRoomMembers(conv)
      .then((members) => setActiveRoomMemberCount(members.length))
      .catch(() => setActiveRoomMemberCount(null));
  });

  createEffect(() => {
    const msgs = activeMessages();
    if (msgs.length > prevMsgCount && prevMsgCount > 0) {
      if (isNearBottom()) {
        setTimeout(() => messagesEndRef?.scrollIntoView({ behavior: "smooth" }), 50);
      } else {
        setNewMsgBelow(true);
      }
    }
    prevMsgCount = msgs.length;
  });

  const conversations = () => {
    const msgConvs = getConversations();
    const roomIds = Object.keys(roomsById);
    const merged = [...msgConvs];
    for (const rid of roomIds) {
      if (!merged.includes(rid)) merged.push(rid);
    }
    return merged;
  };

  const activeMessages = () => {
    const conv = activeConv();
    return conv ? getConversationMessages(conv) : [];
  };

  const chronologicalMessages = () => [...activeMessages()].reverse();

  return (
    <div class="chat-layout">
      <SearchOverlay
        open={searchOpen()}
        onClose={() => setSearchOpen(false)}
        onSelect={(key) => setActiveConv(key)}
      />

      <ConversationList
        conversations={conversations}
        activeConv={activeConv}
        onSelectConv={setActiveConv}
        onOpenSearch={() => setSearchOpen(true)}
      />

      {/* Message area */}
      <div class="msg-area">
        <Show
          when={activeConv()}
          fallback={
            <div class="empty-state empty-state-centered">
              <div class="empty-state-icon">
                <IconMessages size={32} />
              </div>
              <div class="empty-state-title">Select a conversation</div>
              <div class="empty-state-desc">
                Choose a conversation from the left panel, or add a new peer to begin.
              </div>
            </div>
          }
        >
          {/* Header */}
          <div class="msg-header">
            <Show when={isRoomKey(activeConv()!)}>
              <span class="text-muted">
                <IconGroups size={16} />
              </span>
            </Show>
            <span class="font-semibold">{peerLabel(activeConv()!)}</span>
            <span class="mono text-xs text-muted">{truncateId(activeConv()!)}</span>
            <Show when={isRoomKey(activeConv()!)}>
              <span class="badge badge-accent ml-auto">Group</span>
            </Show>
          </div>

          {/* E2EE Banner */}
          <div class="e2ee-banner">
            <IconEncrypted size={12} />
            <span>
              Messages are end-to-end encrypted. No one outside this conversation can read them.
            </span>
          </div>

          {/* Message feed */}
          <div
            class="msg-feed"
            ref={msgFeedRef}
            onScroll={() => {
              const near = isNearBottom();
              setShowScrollBtn(!near);
              if (near) setNewMsgBelow(false);
              if (isNearTop()) handleLoadOlder();
            }}
          >
            <Show when={loadingOlder()}>
              <div class="text-center text-xs text-muted py-8">
                <IconRefresh size={14} /> Loading older messages...
              </div>
            </Show>
            <Show when={!loadingOlder() && !hasMoreMessages(activeConv() ?? "")}>
              <div class="text-center text-xs text-muted py-8">
                Beginning of conversation
              </div>
            </Show>
            <For each={chronologicalMessages()}>
              {(msg, idx) => {
                const msgs = chronologicalMessages();
                const prev = idx() > 0 ? msgs[idx() - 1] : null;
                const next = idx() < msgs.length - 1 ? msgs[idx() + 1] : null;
                const isMine = msg.sender === nodeId();
                const isGrouped =
                  prev !== null &&
                  prev.sender === msg.sender &&
                  msg.timestamp - prev.timestamp < 120_000;
                const isLastInGroup =
                  next === null ||
                  next.sender !== msg.sender ||
                  next.timestamp - msg.timestamp >= 120_000;
                return (
                  <div data-msg-id={msg.id}>
                    <MessageBubble
                      msg={msg}
                      isMine={isMine}
                      isGrouped={isGrouped}
                      isLastInGroup={isLastInGroup}
                      onQuote={(block) => setPendingQuote(block)}
                      onReply={(m) => setPendingReply(m)}
                      onJumpTo={(id) => scrollToMessage(id)}
                    />
                  </div>
                );
              }}
            </For>
            <div ref={messagesEndRef} />
          </div>

          {/* Scroll to bottom */}
          <Show when={showScrollBtn()}>
            <button
              class="scroll-to-bottom"
              onClick={scrollToBottom}
              aria-label="Scroll to latest messages"
            >
              <IconArrowDown size={16} />
              <Show when={newMsgBelow()}>
                <span class="scroll-to-bottom-badge">New</span>
              </Show>
            </button>
          </Show>

          <Show
            when={!(isRoomKey(activeConv()!) && activeRoomMemberCount() === 0)}
            fallback={
              <div class="group-empty-state">
                <div class="group-empty-icon">
                  <IconGroups size={40} />
                </div>
                <div class="group-empty-title">No members yet</div>
                <div class="group-empty-body">
                  Add peers to this group to start a conversation. Messages are
                  end-to-end encrypted and payment-gated.
                </div>
                <button
                  class="btn btn-primary group-empty-cta"
                  onClick={() => navigate("/rooms")}
                >
                  + Add members
                </button>
              </div>
            }
          >
            <ComposeArea
                recipient={activeConv()!}
                isRoom={isRoomKey(activeConv()!)}
                pendingQuote={pendingQuote}
                onQuoteConsumed={() => setPendingQuote(null)}
                replyTo={pendingReply}
                onReplyConsumed={() => setPendingReply(null)}
              />
          </Show>
        </Show>
      </div>
    </div>
  );
}
