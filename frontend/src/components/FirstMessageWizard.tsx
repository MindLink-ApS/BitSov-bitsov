import { createSignal, Show } from "solid-js";
import { MessageKind } from "../api/types";
import * as state from "../state/onboarding";
import { composeMessage } from "../stores/messages";
import { IconLoader, IconMessages, IconSend } from "./Icons";
import { displayName, truncateId } from "../utils/formatting";

function defaultMessage(inviter: string): string {
  const label = displayName(inviter);
  return `Hi ${label}! Just joined the mesh.`;
}

export default function FirstMessageWizard() {
  const [message, setMessage] = createSignal(defaultMessage(state.inviterPubkey()));
  const [sending, setSending] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  async function sendFirstMessage() {
    const body = message().trim();
    const inviter = state.inviterPubkey();
    if (!body || !inviter) return;

    setSending(true);
    setError(null);
    try {
      await composeMessage(inviter, MessageKind.CHAT, body);
      state.completeToChat();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to send first message");
    } finally {
      setSending(false);
    }
  }

  return (
    <div class="onboarding-step animate-fade-in">
      <div class="onboarding-icon-large">
        <IconMessages size={48} class="text-success" />
      </div>
      <h1 class="onboarding-title">Connection Established</h1>
      <p class="onboarding-desc">
        Send your first paid encrypted message to{" "}
        <strong>{displayName(state.inviterPubkey())}</strong>.
      </p>

      <div class="confirm-card glass-subtle p-4 rounded-lg mt-4">
        <div class="flex flex-col gap-2">
          <span class="text-xs text-muted uppercase tracking-wider">
            Recipient Node
          </span>
          <span class="mono break-all text-sm">
            {truncateId(state.inviterPubkey())}
          </span>
        </div>

        <div class="invite-input-group">
          <label for="first-message" class="form-label">
            First Message
          </label>
          <textarea
            id="first-message"
            class="form-control"
            rows={5}
            value={message()}
            onInput={(e) => setMessage(e.currentTarget.value)}
            disabled={sending()}
          />
        </div>
      </div>

      <Show when={error()}>
        <div class="error-text mt-4">{error()}</div>
      </Show>

      <div class="onboarding-nav mt-6">
        <button
          class="btn btn-primary btn-lg w-full"
          onClick={() => void sendFirstMessage()}
          disabled={sending() || !message().trim() || !state.inviterPubkey()}
        >
          <Show
            when={sending()}
            fallback={
              <>
                <IconSend size={18} aria-hidden="true" />
                Send First Message
              </>
            }
          >
            <IconLoader size={18} class="animate-spin" aria-hidden="true" />
            Sending...
          </Show>
        </button>
        <button
          class="btn btn-ghost mt-2"
          onClick={state.completeToChat}
          disabled={sending()}
        >
          Open Chat
        </button>
      </div>
    </div>
  );
}
