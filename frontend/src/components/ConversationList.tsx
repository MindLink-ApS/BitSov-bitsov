/**
 * ConversationList — left-panel list of all active conversations.
 *
 * Each row shows the peer/room label, last message preview, unread badge, and
 * relative timestamp. peerLabel is exported so other components (MessageBubble,
 * ChatView header) can format the same identifier consistently.
 */

import { For, Show } from "solid-js";
import { getConversationMessages, getUnreadCount } from "../stores/messages";
import { peers } from "../stores/peers";
import { isRoomKey, getRoomName } from "../stores/rooms";
import { IconSearch, IconMessages, IconGroups } from "./Icons";
import { truncateId, formatRelativeTime } from "../utils/formatting";

// ---------------------------------------------------------------------------
// Shared peer label helper — exported for use in MessageBubble and ChatView
// ---------------------------------------------------------------------------

export function peerLabel(id: string): string {
  if (isRoomKey(id)) {
    return getRoomName(id) ?? `Group ${id.slice(0, 8)}`;
  }
  const peer = peers.find((p) => p.node_id === id);
  return peer?.label ?? truncateId(id);
}

// ---------------------------------------------------------------------------
// ConversationList
// ---------------------------------------------------------------------------

interface ConversationListProps {
  conversations: () => string[];
  activeConv: () => string | null;
  onSelectConv: (key: string) => void;
  onOpenSearch: () => void;
}

export default function ConversationList(props: ConversationListProps) {
  return (
    <div class="conv-list">
      <div class="conv-list-header">
        <span>Conversations</span>
        <button
          class="btn-icon text-muted"
          onClick={props.onOpenSearch}
          title="Search messages (Ctrl+K)"
          aria-label="Search messages"
          style={{ "font-size": "14px" }}
        >
          <IconSearch size={16} />
        </button>
      </div>
      <div class="flex-1 overflow-y-auto">
        <For
          each={props.conversations()}
          fallback={
            <div class="empty-state">
              <div class="empty-state-icon">
                <IconMessages size={32} />
              </div>
              <div class="empty-state-title">No conversations yet</div>
              <div class="empty-state-desc">
                Add a peer and send your first message to start a conversation.
              </div>
            </div>
          }
        >
          {(convKey) => {
            const msgs = () => getConversationMessages(convKey);
            const lastMsg = () => msgs()[0];
            const unread = () => getUnreadCount(convKey);
            const isRoom = () => isRoomKey(convKey);
            return (
              <button
                class={`conv-item ${props.activeConv() === convKey ? "active" : ""}`}
                onClick={() => props.onSelectConv(convKey)}
              >
                <div class="flex justify-between items-center">
                  <span
                    class={`truncate font-medium text-sm icon-text-sm ${unread() > 0 ? "font-bold" : ""}`}
                  >
                    <Show when={isRoom()}>
                      <span class="text-muted">
                        <IconGroups size={14} />
                      </span>
                    </Show>
                    {peerLabel(convKey)}
                  </span>
                  <div class="flex items-center gap-6">
                    <Show when={unread() > 0}>
                      <span class="conv-unread-badge">{unread()}</span>
                    </Show>
                    <Show when={lastMsg()}>
                      <span class="text-xs text-muted">
                        {formatRelativeTime(lastMsg()!.timestamp)}
                      </span>
                    </Show>
                  </div>
                </div>
                <Show when={lastMsg()}>
                  <div class="truncate text-xs text-muted mt-3">
                    {lastMsg()!.plaintext ??
                      (lastMsg()!.ciphertext
                        ? `${lastMsg()!.ciphertext.slice(0, 32)}...`
                        : "(Encrypted)")}
                  </div>
                </Show>
                <Show when={!lastMsg() && isRoom()}>
                  <div class="text-xs text-muted mt-3">No messages yet</div>
                </Show>
              </button>
            );
          }}
        </For>
      </div>
    </div>
  );
}
