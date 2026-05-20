/**
 * ReactionStrip — emoji reaction bar shown below a MessageBubble.
 *
 * Features:
 * - Aggregated emoji counts fetched from GET /api/v1/messages/:id/reactions
 * - Tap a reaction chip to toggle it on/off
 * - "+" button opens an emoji picker with 6 common emojis + search
 * - Hidden when per-peer policy has hideReactions=true for this peer
 */

import { createSignal, For, Show, onMount } from "solid-js";
import { Portal } from "solid-js/web";
import { api } from "../stores/auth";
import type { ReactionCount } from "../api/types";
import { getHideReactions } from "../stores/reactionPolicy";

// ---------------------------------------------------------------------------
// Emoji data
// ---------------------------------------------------------------------------

/** The 6 common emojis shown without a search query. */
const COMMON_EMOJIS = ["👍", "❤️", "😂", "😮", "😢", "😡"];

/** Larger set with short name keywords for search. */
const EMOJI_SEARCH_LIST: { emoji: string; keywords: string }[] = [
  { emoji: "👍", keywords: "thumbs up like good yes" },
  { emoji: "👎", keywords: "thumbs down dislike no bad" },
  { emoji: "❤️", keywords: "heart love red" },
  { emoji: "😂", keywords: "laugh cry joy funny" },
  { emoji: "😮", keywords: "surprised wow shocked" },
  { emoji: "😢", keywords: "sad cry tear" },
  { emoji: "😡", keywords: "angry mad rage" },
  { emoji: "🎉", keywords: "party celebrate congrats" },
  { emoji: "🔥", keywords: "fire hot lit" },
  { emoji: "✅", keywords: "check done ok agree" },
  { emoji: "🙏", keywords: "pray thanks please" },
  { emoji: "👏", keywords: "clap applause" },
  { emoji: "🤔", keywords: "think hmm curious" },
  { emoji: "😍", keywords: "love eyes heart adore" },
  { emoji: "🥳", keywords: "party hat celebrate" },
  { emoji: "💯", keywords: "100 perfect score" },
  { emoji: "😭", keywords: "crying sob loud" },
  { emoji: "😊", keywords: "smile happy blush" },
  { emoji: "👀", keywords: "eyes look see" },
  { emoji: "💀", keywords: "skull dead lol" },
  { emoji: "🤝", keywords: "handshake deal agree" },
  { emoji: "✨", keywords: "sparkle magic stars" },
  { emoji: "⚡", keywords: "lightning electric fast" },
  { emoji: "🚀", keywords: "rocket launch fast ship" },
  { emoji: "👋", keywords: "wave hello bye" },
  { emoji: "💪", keywords: "muscle strong flex" },
  { emoji: "🫶", keywords: "heart hands love" },
  { emoji: "🫡", keywords: "salute respect" },
  { emoji: "💡", keywords: "idea light bulb" },
  { emoji: "🎯", keywords: "target goal aim hit" },
];

// ---------------------------------------------------------------------------
// EmojiPicker — popup with common emojis + search
// ---------------------------------------------------------------------------

function EmojiPicker(props: {
  anchorRect: DOMRect;
  onSelect: (emoji: string) => void;
  onClose: () => void;
}) {
  const [query, setQuery] = createSignal("");
  let inputRef: HTMLInputElement | undefined;

  onMount(() => {
    inputRef?.focus();
  });

  const filteredEmojis = () => {
    const q = query().trim().toLowerCase();
    if (!q) return COMMON_EMOJIS;
    return EMOJI_SEARCH_LIST
      .filter((e) => e.keywords.includes(q) || e.emoji === q)
      .map((e) => e.emoji)
      .slice(0, 12);
  };

  // Position the picker above or below the anchor, keeping it on-screen
  const pickerStyle = () => {
    const r = props.anchorRect;
    const pickerH = 160;
    const pickerW = 220;
    let top = r.bottom + 4;
    let left = r.left;

    if (top + pickerH > window.innerHeight - 8) {
      top = r.top - pickerH - 4;
    }
    if (left + pickerW > window.innerWidth - 8) {
      left = window.innerWidth - pickerW - 8;
    }
    return {
      position: "fixed" as const,
      top: `${top}px`,
      left: `${left}px`,
      width: `${pickerW}px`,
      "z-index": "1000",
    };
  };

  return (
    <Portal>
      {/* Backdrop */}
      <div
        style={{ position: "fixed", inset: "0", "z-index": "999" }}
        onClick={props.onClose}
        onContextMenu={(e) => { e.preventDefault(); props.onClose(); }}
      />
      {/* Picker panel */}
      <div class="emoji-picker-panel" style={pickerStyle()}>
        <input
          ref={inputRef}
          class="emoji-picker-search"
          type="text"
          placeholder="Search emojis…"
          value={query()}
          onInput={(e) => setQuery(e.currentTarget.value)}
          onKeyDown={(e) => { if (e.key === "Escape") props.onClose(); }}
          aria-label="Search emojis"
        />
        <div class="emoji-picker-grid">
          <For each={filteredEmojis()}>
            {(emoji) => (
              <button
                class="emoji-picker-btn"
                onClick={() => { props.onSelect(emoji); props.onClose(); }}
                title={emoji}
                aria-label={`React with ${emoji}`}
              >
                {emoji}
              </button>
            )}
          </For>
          <Show when={filteredEmojis().length === 0}>
            <span class="emoji-picker-empty">No match</span>
          </Show>
        </div>
      </div>
    </Portal>
  );
}

// ---------------------------------------------------------------------------
// ReactionStrip
// ---------------------------------------------------------------------------

interface ReactionStripProps {
  messageId: string;
  /** Sender's node ID — checked against the hide-reactions policy. */
  senderPeerId: string;
  /** Whether to align chips to the right (sent messages). */
  isMine: boolean;
}

export default function ReactionStrip(props: ReactionStripProps) {
  const [reactions, setReactions] = createSignal<ReactionCount[]>([]);
  const [sending, setSending] = createSignal(false);
  const [pickerAnchor, setPickerAnchor] = createSignal<DOMRect | null>(null);

  // Hide if per-peer policy says so (only applies to messages from others)
  const hidden = () => !props.isMine && getHideReactions(props.senderPeerId);

  onMount(async () => {
    if (hidden()) return;
    try {
      const res = await api.getMessageReactions(props.messageId);
      setReactions(res.reactions);
    } catch {
      // Backend may not support reactions yet — silently show empty strip
    }
  });

  const toggleReaction = async (emoji: string) => {
    if (sending()) return;
    setSending(true);
    try {
      await api.reactToMessage(props.messageId, emoji);
      const updated = await api.getMessageReactions(props.messageId);
      setReactions(updated.reactions);
    } catch {
      // Ignore errors — strip will not update locally
    } finally {
      setSending(false);
    }
  };

  const openPicker = (e: MouseEvent) => {
    e.stopPropagation();
    const btn = e.currentTarget as HTMLElement;
    setPickerAnchor(btn.getBoundingClientRect());
  };

  const closePicker = () => setPickerAnchor(null);

  return (
    <Show when={!hidden()}>
      <div
        class="reaction-strip"
        style={{ "justify-content": props.isMine ? "flex-end" : "flex-start" }}
      >
        <For each={reactions()}>
          {(r) => (
            <button
              class={`reaction-chip${r.reacted_by_me ? " reaction-chip-mine" : ""}`}
              onClick={() => { void toggleReaction(r.emoji); }}
              disabled={sending()}
              title={`${r.count} reaction${r.count !== 1 ? "s" : ""}${r.reacted_by_me ? " (you reacted)" : ""}`}
              aria-label={`${r.emoji} ${r.count}`}
            >
              <span class="reaction-chip-emoji">{r.emoji}</span>
              <span class="reaction-chip-count">{r.count}</span>
            </button>
          )}
        </For>

        <button
          class="reaction-add-btn"
          onClick={openPicker}
          title="Add reaction"
          aria-label="Add reaction"
        >
          +
        </button>

        <Show when={pickerAnchor()}>
          {(rect) => (
            <EmojiPicker
              anchorRect={rect()}
              onSelect={(emoji) => { void toggleReaction(emoji); }}
              onClose={closePicker}
            />
          )}
        </Show>
      </div>
    </Show>
  );
}
