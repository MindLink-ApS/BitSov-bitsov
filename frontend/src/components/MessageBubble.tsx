/**
 * MessageBubble — renders a single chat message in the message feed.
 *
 * Handles plain text, ciphertext fallback, and FILE_REF inline attachments.
 * Delegates delivery status rendering to MessageDeliveryIndicator.
 *
 * Quote replies: right-click (or long-press) a message to open a context menu
 * with a "Quote" option. Leading `> ` lines in plaintext are rendered as a
 * muted blockquote so quoted replies display correctly.
 *
 * Thread replies (KIND_REPLY): right-click → "Reply" sets a structured reply-to
 * in the compose area using KIND_REPLY=2 + envelope.references. Replies are
 * rendered with an indented parent-preview chip and a jump-to-parent button.
 * Visual depth is capped at 3 levels; full reference chain is always preserved.
 */

import { createSignal, Show } from "solid-js";
import { Portal } from "solid-js/web";
import ReactionStrip from "./ReactionStrip";
import { getDeliveryStatus, messages } from "../stores/messages";
import { formatMsat } from "../stores/payments";
import { formatFileSize } from "../stores/files";
import { kindName, MessageKind } from "../api/types";
import type { MessageResponse } from "../api/types";
import { mimeTypeIcon } from "./Icons";
import TrustIndicator from "./TrustIndicator";
import type { TrustLevel } from "./TrustIndicator";
import type { DeliveryStage } from "./MessageDeliveryState";
import MessageDeliveryIndicator from "./MessageDeliveryIndicator";
import { formatRelativeTime, displayName } from "../utils/formatting";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatFullTime(timestamp: number): string {
  const d = new Date(timestamp);
  return d.toLocaleString([], {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatHHMM(timestamp: number): string {
  const d = new Date(timestamp);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function parseFilePayload(plaintext: string | undefined): {
  filename: string;
  mime_type: string;
  size_bytes: number;
} | null {
  if (!plaintext) return null;
  try {
    const parsed = JSON.parse(plaintext);
    if (parsed.filename && parsed.size_bytes !== undefined) {
      return {
        filename: parsed.filename,
        mime_type: parsed.mime_type ?? "application/octet-stream",
        size_bytes: parsed.size_bytes,
      };
    }
  } catch {
    // Not a file payload
  }
  return null;
}

/** Determine the delivery stage of a sent message. */
export function getDeliveryStage(msg: MessageResponse, isMine: boolean): DeliveryStage {
  if (!isMine) return "delivered";
  const status = getDeliveryStatus(msg.id);
  if (status === "delivered") return "delivered";
  if (status === "rejected") return "sent";
  if (status === "sending") return "paying";
  if (status === "sent") return "sent";
  if (msg.payment_amount_msat > 0) return "sent";
  return "sent";
}

/** Determine trust level based on message encryption state. */
function getTrustLevel(msg: MessageResponse): TrustLevel {
  if (msg.plaintext) return "encrypted";
  return "unverified";
}

/**
 * Build a quote block string for the given message.
 * Format: `> [DisplayName, HH:MM] excerpt\n\n`
 */
function buildQuoteBlock(msg: MessageResponse): string {
  const name = displayName(msg.sender);
  const time = formatHHMM(msg.timestamp);
  const rawText = msg.plaintext ?? "";
  // Use first non-quote, non-blank line as the excerpt
  const firstLine =
    rawText
      .split("\n")
      .find((l) => !l.startsWith("> ") && l.trim() !== "") ?? "";
  const excerpt = firstLine.length > 80 ? `${firstLine.slice(0, 80)}…` : firstLine;
  return `> [${name}, ${time}] ${excerpt}\n\n`;
}

/**
 * Compute visual thread depth by following the reference chain.
 * Caps at MAX_DEPTH to limit DOM nesting. Full reference chain is preserved
 * in the envelope regardless of this display cap.
 */
const MAX_DEPTH = 3;

function computeDepth(msg: MessageResponse, visited = new Set<string>()): number {
  if (msg.kind !== MessageKind.REPLY || !msg.references?.length) return 0;
  if (visited.has(msg.id)) return 0; // cycle guard
  const parentId = msg.references[0];
  const parent = messages.byId[parentId];
  if (!parent) return 1;
  visited.add(msg.id);
  return Math.min(MAX_DEPTH, 1 + computeDepth(parent, visited));
}

/** Extract a short excerpt from a message for use in previews. */
function excerptText(msg: MessageResponse): string {
  const raw = msg.plaintext ?? "";
  const firstLine =
    raw.split("\n").find((l) => !l.startsWith("> ") && l.trim() !== "") ?? "";
  return firstLine.length > 60 ? `${firstLine.slice(0, 60)}…` : firstLine || "(encrypted)";
}

// ---------------------------------------------------------------------------
// PlaintextContent — renders plaintext, detecting leading `> ` quote blocks
// ---------------------------------------------------------------------------

function PlaintextContent(props: { text: string }) {
  const lines = props.text.split("\n");
  const quoteLines: string[] = [];
  let i = 0;
  for (; i < lines.length; i++) {
    if (lines[i].startsWith("> ")) {
      quoteLines.push(lines[i].slice(2));
    } else {
      break;
    }
  }
  // Skip blank separator between quote block and reply body
  while (i < lines.length && lines[i].trim() === "") i++;
  const bodyText = lines.slice(i).join("\n");

  if (quoteLines.length === 0) {
    return <>{props.text}</>;
  }

  return (
    <>
      <div class="msg-quote">{quoteLines.join("\n")}</div>
      <Show when={bodyText}>
        <div style={{ "margin-top": "4px" }}>{bodyText}</div>
      </Show>
    </>
  );
}

// ---------------------------------------------------------------------------
// ThreadParentPreview — parent-message chip shown at top of a KIND_REPLY bubble
// ---------------------------------------------------------------------------

function ThreadParentPreview(props: {
  parentId: string;
  onJump: (id: string) => void;
}) {
  const parent = () => messages.byId[props.parentId];

  return (
    <Show
      when={parent()}
      fallback={
        <div class="msg-thread-parent msg-thread-parent-unknown">
          ↪ reply to unknown message
        </div>
      }
    >
      {(p) => (
        <button
          class="msg-thread-parent"
          onClick={() => props.onJump(props.parentId)}
          title="Jump to original message"
        >
          <span class="msg-thread-parent-name">{displayName(p().sender)}</span>
          <span class="msg-thread-parent-excerpt">{excerptText(p())}</span>
        </button>
      )}
    </Show>
  );
}

// ---------------------------------------------------------------------------
// FileAttachment sub-component
// ---------------------------------------------------------------------------

function FileAttachment(props: {
  filename: string;
  mime_type: string;
  size_bytes: number;
}) {
  return (
    <div class="file-attachment">
      <span class="file-icon">{mimeTypeIcon(props.mime_type, { size: 20 })}</span>
      <div class="flex-1 min-w-0">
        <div class="truncate text-sm font-medium" title={props.filename}>
          {props.filename}
        </div>
        <div class="text-xs text-muted">{formatFileSize(props.size_bytes)}</div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// MessageBubble
// ---------------------------------------------------------------------------

interface MessageBubbleProps {
  msg: MessageResponse;
  isMine: boolean;
  isGrouped: boolean;
  isLastInGroup: boolean;
  /** Called when the user selects "Quote" from the context menu. */
  onQuote?: (quoteBlock: string) => void;
  /** Called when the user selects "Reply" from the context menu. */
  onReply?: (msg: MessageResponse) => void;
  /** Called when the user clicks "jump to parent" on a thread reply. */
  onJumpTo?: (messageId: string) => void;
}

export default function MessageBubble(props: MessageBubbleProps) {
  const isFile = () => props.msg.kind === MessageKind.FILE_REF;
  const filePayload = () => (isFile() ? parseFilePayload(props.msg.plaintext) : null);

  const [menuPos, setMenuPos] = createSignal<{ x: number; y: number } | null>(null);

  const openMenu = (e: MouseEvent) => {
    // Only show the context menu if the message has decrypted text
    if (!props.msg.plaintext || isFile()) return;
    e.preventDefault();
    setMenuPos({ x: e.clientX, y: e.clientY });
  };

  const closeMenu = () => setMenuPos(null);

  const handleQuote = () => {
    props.onQuote?.(buildQuoteBlock(props.msg));
    closeMenu();
  };

  const handleReply = () => {
    props.onReply?.(props.msg);
    closeMenu();
  };

  // Thread reply state
  const isReply = () =>
    props.msg.kind === MessageKind.REPLY && (props.msg.references?.length ?? 0) > 0;
  const parentId = () => (isReply() ? props.msg.references![0] : null);
  const depth = () => computeDepth(props.msg);

  return (
    <div
      class={props.isGrouped ? "" : "msg-appear"}
      style={{
        display: "flex",
        "flex-direction": "column",
        "align-items": props.isMine ? "flex-end" : "flex-start",
        "margin-bottom": props.isLastInGroup ? "10px" : "2px",
        "padding-left": props.isMine ? "0" : `${Math.min(depth(), MAX_DEPTH) * 16}px`,
        "padding-right": props.isMine ? `${Math.min(depth(), MAX_DEPTH) * 16}px` : "0",
      }}
    >
      <div
        class={`msg-bubble ${props.isMine ? "msg-bubble-mine" : "msg-bubble-theirs"} ${props.isGrouped ? "msg-bubble-grouped" : ""}`}
        onContextMenu={openMenu}
      >
        {/* Thread parent preview — shown at top for KIND_REPLY messages */}
        <Show when={parentId()}>
          {(pid) => (
            <ThreadParentPreview
              parentId={pid()}
              onJump={(id) => props.onJumpTo?.(id)}
            />
          )}
        </Show>

        {/* Sender label — only for first message in a group from someone else */}
        <Show when={!props.isMine && !props.isGrouped}>
          <div class="mono text-xs text-accent mb-4">
            {displayName(props.msg.sender)}
          </div>
        </Show>

        {/* File attachment */}
        <Show when={filePayload()}>
          {(fp) => (
            <FileAttachment
              filename={fp().filename}
              mime_type={fp().mime_type}
              size_bytes={fp().size_bytes}
            />
          )}
        </Show>

        {/* Text content */}
        <Show when={!filePayload()}>
          <div class={props.msg.plaintext ? "msg-text-plain" : "msg-text-cipher"}>
            <Show
              when={props.msg.plaintext}
              fallback={
                props.msg.ciphertext
                  ? props.msg.ciphertext.length > 64
                    ? `${props.msg.ciphertext.slice(0, 64)}...`
                    : props.msg.ciphertext
                  : "(Encrypted \u2014 unable to decrypt)"
              }
            >
              {(text) => <PlaintextContent text={text()} />}
            </Show>
          </div>
        </Show>

        {/* Meta — shown on last message in group or on hover */}
        <div class={`msg-meta ${props.isLastInGroup ? "" : "msg-meta-compact"}`}>
          <Show when={props.isLastInGroup}>
            <span class="badge badge-accent">{kindName(props.msg.kind)}</span>
            <span>{formatMsat(props.msg.payment_amount_msat)}</span>
          </Show>
          <span
            class="msg-timestamp ml-auto"
            title={formatFullTime(props.msg.timestamp)}
          >
            {formatRelativeTime(props.msg.timestamp)}
          </span>
          <TrustIndicator level={getTrustLevel(props.msg)} compact />
          <Show when={props.isMine && props.isLastInGroup}>
            <MessageDeliveryIndicator
              msg={props.msg}
              stage={getDeliveryStage(props.msg, props.isMine)}
            />
          </Show>
        </div>
      </div>

      {/* Reaction strip — shown below the bubble for all message kinds except REACTION */}
      <Show when={props.msg.kind !== MessageKind.REACTION}>
        <ReactionStrip
          messageId={props.msg.id}
          senderPeerId={props.msg.sender}
          isMine={props.isMine}
        />
      </Show>

      {/* Context menu — rendered in a Portal to escape stacking contexts */}
      <Show when={menuPos()}>
        {(pos) => (
          <Portal>
            <div
              style={{ position: "fixed", inset: "0", "z-index": "998" }}
              onClick={closeMenu}
              onContextMenu={(e) => { e.preventDefault(); closeMenu(); }}
            />
            <div
              class="msg-context-menu"
              style={{
                position: "fixed",
                left: `${pos().x}px`,
                top: `${pos().y}px`,
                "z-index": "999",
              }}
            >
              <button
                class="msg-context-item"
                onClick={handleReply}
                title="Reply to this message (creates a thread)"
              >
                Reply
              </button>
              <button
                class="msg-context-item"
                onClick={handleQuote}
                title="Prepend a quoted excerpt into the compose box"
              >
                Quote
              </button>
            </div>
          </Portal>
        )}
      </Show>
    </div>
  );
}
