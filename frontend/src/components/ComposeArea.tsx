/**
 * ComposeArea — message input + send button for a conversation.
 *
 * Displays a low-balance warning when the node wallet cannot cover at least
 * five messages at the current chat price. Supports Enter-to-send and
 * Shift+Enter for newlines. Auto-resizes up to 120 px tall.
 *
 * Quote replies: accepts a `pendingQuote` accessor. When it returns a non-null
 * string, the quote block is prepended into the textarea and focus is moved
 * there. `onQuoteConsumed` is called immediately after so the parent can clear
 * the pending quote signal.
 *
 * Thread replies (KIND_REPLY): accepts a `replyTo` accessor. When non-null,
 * a reply-to chip is shown above the textarea with the parent sender name and
 * excerpt. Sending in this state uses KIND_REPLY=2 + references=[parentId].
 * Clicking the chip's dismiss button (or pressing Escape) clears the reply-to.
 */

import { createSignal, createEffect, onMount, Show } from "solid-js";
import { composeMessage } from "../stores/messages";
import { refreshBalance, getPrice, formatMsat, balance } from "../stores/payments";
import { toast } from "../stores/toast";
import { MessageKind } from "../api/types";
import type { MessageResponse } from "../api/types";
import { IconWarning, IconEncrypted, IconLightning, IconRefresh } from "./Icons";
import { displayName } from "../utils/formatting";

interface ComposeAreaProps {
  recipient: string;
  isRoom?: boolean;
  /** Reactive accessor — when non-null, its value is prepended into the textarea. */
  pendingQuote?: () => string | null;
  /** Called after the pending quote has been inserted so the parent can reset it. */
  onQuoteConsumed?: () => void;
  /** Reactive accessor — when non-null, sends as a thread reply to this message. */
  replyTo?: () => MessageResponse | null;
  /** Called after the reply has been sent (or cancelled) so the parent can clear it. */
  onReplyConsumed?: () => void;
}

export default function ComposeArea(props: ComposeAreaProps) {
  const [text, setText] = createSignal("");
  const [sending, setSending] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [lastResult, setLastResult] = createSignal<string | null>(null);
  const [chatPrice, setChatPrice] = createSignal<number | null>(null);
  const [failedText, setFailedText] = createSignal<string | null>(null);
  let textareaRef: HTMLTextAreaElement | undefined;

  onMount(() => {
    getPrice(MessageKind.CHAT)
      .then((p) => setChatPrice(p))
      .catch(() => {
        console.warn("Failed to fetch chat price — balance warning may be unavailable");
      });
  });

  // Insert incoming quote block into the textarea
  createEffect(() => {
    const quote = props.pendingQuote?.();
    if (!quote) return;
    setText((prev) => quote + prev);
    props.onQuoteConsumed?.();
    // Defer resize + focus so the DOM has updated
    requestAnimationFrame(() => {
      autoResize();
      textareaRef?.focus();
    });
  });

  // Focus textarea when a reply-to is set
  createEffect(() => {
    const r = props.replyTo?.();
    if (!r) return;
    requestAnimationFrame(() => {
      textareaRef?.focus();
    });
  });

  const isLowBalance = () => {
    const bal = balance();
    const price = chatPrice();
    if (bal === null || price === null) return false;
    return bal < price * 5;
  };

  const autoResize = () => {
    if (!textareaRef) return;
    textareaRef.style.height = "auto";
    textareaRef.style.height = Math.min(textareaRef.scrollHeight, 120) + "px";
  };

  const replyExcerpt = () => {
    const r = props.replyTo?.();
    if (!r) return null;
    const raw = r.plaintext ?? "";
    const firstLine =
      raw.split("\n").find((l) => !l.startsWith("> ") && l.trim() !== "") ?? "";
    const excerpt = firstLine.length > 50 ? `${firstLine.slice(0, 50)}…` : firstLine || "(encrypted)";
    return { name: displayName(r.sender), excerpt };
  };

  const handleSend = async () => {
    const msg = text().trim();
    if (!msg || sending()) return;

    const reply = props.replyTo?.();
    const kind = reply ? MessageKind.REPLY : MessageKind.CHAT;
    const references = reply ? [reply.id] : undefined;

    setSending(true);
    setError(null);
    setLastResult(null);
    setFailedText(null);

    try {
      const result = await composeMessage(
        props.recipient,
        kind,
        msg,
        references,
        props.isRoom,
      );
      if (props.isRoom && !result.delivered && result.amountMsat === 0 && !result.messageId) {
        setError("No E2EE sessions with group members. Ensure members are connected peers.");
        setFailedText(msg);
        toast.error("Group message failed: no E2EE sessions with members");
        return;
      }
      setText("");
      if (textareaRef) {
        textareaRef.style.height = "auto";
      }
      // Clear reply-to after a successful send
      if (reply) {
        props.onReplyConsumed?.();
      }
      const status = result.delivered ? "Delivered" : "Queued";
      setLastResult(`${status} (${formatMsat(result.amountMsat)})`);
      toast.success(`Message ${result.delivered ? "delivered" : "queued"} (${formatMsat(result.amountMsat)})`);
      refreshBalance();
      setTimeout(() => setLastResult(null), 4000);
    } catch (e: unknown) {
      const errMsg = e instanceof Error ? e.message : "Failed to send message";
      setError(errMsg);
      setFailedText(msg);
      toast.error(errMsg);
    } finally {
      setSending(false);
    }
  };

  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Escape" && props.replyTo?.()) {
      props.onReplyConsumed?.();
      return;
    }
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div class="compose-area">
      <Show when={isLowBalance()}>
        <div class="compose-low-balance">
          <IconWarning size={14} /> Low balance — {formatMsat(balance()!)} remaining
        </div>
      </Show>

      {/* Reply-to chip */}
      <Show when={replyExcerpt()}>
        {(info) => (
          <div class="compose-reply-chip">
            <span class="compose-reply-icon">↩</span>
            <span class="compose-reply-text">
              <span class="compose-reply-name">{info().name}</span>
              <span class="compose-reply-excerpt">{info().excerpt}</span>
            </span>
            <button
              class="compose-reply-dismiss"
              onClick={() => props.onReplyConsumed?.()}
              aria-label="Cancel reply"
              title="Cancel reply (Esc)"
            >
              ✕
            </button>
          </div>
        )}
      </Show>

      <div class="compose-row">
        <textarea
          ref={textareaRef}
          class="compose-input"
          placeholder={props.isRoom ? "Message this group..." : "Type a message..."}
          rows={1}
          value={text()}
          onInput={(e) => {
            setText(e.currentTarget.value);
            autoResize();
          }}
          onKeyDown={handleKeyDown}
          disabled={sending()}
          aria-label="Message input"
        />
        <div class="icon-text-sm" style="align-items: center;">
          <button
            class="btn btn-primary btn-sm"
            onClick={handleSend}
            disabled={!text().trim() || sending()}
            aria-label="Send message"
          >
            {sending() ? "..." : "Send"}
          </button>
          <kbd class="compose-kbd">
            {typeof navigator !== "undefined" &&
            /Mac|iPod|iPhone|iPad/.test(navigator.platform)
              ? "⌘↩"
              : "Ctrl+Enter"}
          </kbd>
        </div>
      </div>
      <div class="compose-footer">
        <Show when={error()}>
          <span class="text-xs text-error icon-text">
            {error()}
            <Show when={failedText()}>
              <button
                class="btn btn-ghost btn-sm btn-retry"
                onClick={() => {
                  setText(failedText()!);
                  setError(null);
                  setFailedText(null);
                  handleSend();
                }}
                aria-label="Retry send"
              >
                <IconRefresh size={10} /> Retry
              </button>
            </Show>
          </span>
        </Show>
        <Show when={lastResult()}>
          <span class="text-xs text-accent">{lastResult()}</span>
        </Show>
        <Show when={!error() && !lastResult()}>
          <span class="text-xs text-muted icon-text-sm">
            <IconEncrypted size={12} /> E2E encrypted · Enter to send, Shift+Enter for new line
          </span>
        </Show>
        <Show when={chatPrice() !== null}>
          <span class="compose-cost icon-text-xs" title="Message cost">
            <IconLightning size={12} /> {formatMsat(chatPrice()!)}
          </span>
        </Show>
      </div>
    </div>
  );
}
