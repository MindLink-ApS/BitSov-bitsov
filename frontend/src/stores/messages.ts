/**
 * Messages store — manages message state with real-time updates.
 *
 * Messages flow in two directions:
 * 1. REST API: fetch history, send messages
 * 2. WebSocket: receive new messages in real-time
 *
 * The node decrypts incoming messages using the Double Ratchet E2EE session.
 * WebSocket messages include a `plaintext` field when decryption succeeds.
 * Messages without an active session still show as truncated ciphertext.
 */

import { createSignal } from "solid-js";
import { loadJSON, saveJSON } from "../utils/storage";
import { createStore, produce } from "solid-js/store";
import type { MessageResponse, WsEnvelope, WsDeliveryStatus } from "../api/types";
import { api, ws } from "./auth";
import { sendNotification } from "./notifications";

/** Delivery status for a sent message. */
export type DeliveryStatusValue = "sending" | "sent" | "delivered" | "rejected";

interface MessagesState {
  /** All messages indexed by ID. */
  byId: Record<string, MessageResponse>;
  /** Message IDs ordered by timestamp (newest first). */
  ordered: string[];
  /** Message IDs grouped by conversation (peer node_id or room_id). */
  byConversation: Record<string, string[]>;
  /** Last-read timestamp per conversation key. */
  lastRead: Record<string, number>;
  /** Delivery status per message ID (only tracked for sent messages). */
  deliveryStatus: Record<string, DeliveryStatusValue>;
  /** Rejection reason per message ID (only present for rejected messages). */
  rejectionReason: Record<string, string>;
}

const [messages, setMessages] = createStore<MessagesState>({
  byId: {},
  ordered: [],
  byConversation: {},
  lastRead: loadLastRead(),
  deliveryStatus: {},
  rejectionReason: {},
});

function loadLastRead(): Record<string, number> {
  return loadJSON<Record<string, number>>("konsensus_last_read", {});
}

function persistLastRead(lastRead: Record<string, number>): void {
  saveJSON("konsensus_last_read", lastRead);
}

/** Mark a conversation as read up to the current time. */
export function markConversationRead(key: string): void {
  const now = Date.now();
  setMessages(
    produce((state) => {
      state.lastRead[key] = now;
      persistLastRead(state.lastRead);
    }),
  );
}

/** Get the number of unread messages in a conversation. */
export function getUnreadCount(key: string): number {
  const ids = messages.byConversation[key] ?? [];
  const lastRead = messages.lastRead[key] ?? 0;
  let count = 0;
  for (const id of ids) {
    const msg = messages.byId[id];
    if (msg && msg.timestamp > lastRead) {
      count++;
    }
  }
  return count;
}

/** Get total unread count across all conversations. */
export function getTotalUnreadCount(): number {
  let total = 0;
  for (const key of Object.keys(messages.byConversation)) {
    total += getUnreadCount(key);
  }
  return total;
}

const [loadingMessages, setLoadingMessages] = createSignal(false);
const [loadingOlder, setLoadingOlder] = createSignal(false);

/** Cached local node ID — set once during initMessages, avoids repeated identity API calls. */
let cachedMyNodeId: string | null = null;

/** Track whether a conversation has more messages to load. */
const noMoreMessages: Record<string, boolean> = {};

/** Determine the conversation key for a message. */
function conversationKey(msg: MessageResponse, myNodeId: string): string {
  // Room messages: the recipient is a room UUID (contains dashes).
  // Both sent and received room messages use the room ID as conversation key.
  if (msg.recipient.includes("-")) {
    return msg.recipient;
  }
  // Peer messages: If I sent it, the conversation is with the recipient.
  // If I received it, the conversation is with the sender.
  return msg.sender === myNodeId ? msg.recipient : msg.sender;
}

/** Set of message IDs where we already attempted a plaintext fetch. */
const plaintextFetchAttempted = new Set<string>();

/** Attempt to fetch plaintext for a message that lacks it, updating the store. */
async function fetchPlaintextForMessage(msgId: string): Promise<void> {
  if (plaintextFetchAttempted.has(msgId)) return;
  plaintextFetchAttempted.add(msgId);

  try {
    const result = await api.getMessagePlaintext(msgId);
    if (result.plaintext) {
      setMessages(
        produce((state) => {
          const existing = state.byId[msgId];
          if (existing && !existing.plaintext) {
            existing.plaintext = result.plaintext;
          }
        }),
      );
    }
  } catch {
    // Plaintext not available (no cache, cipher not configured, etc.)
  }
}

/** Insert a message into the store. */
function insertMessage(msg: MessageResponse, myNodeId: string): void {
  setMessages(
    produce((state) => {
      // Skip duplicates
      if (state.byId[msg.id]) return;

      state.byId[msg.id] = msg;

      // Insert into ordered list (maintain newest-first)
      const idx = state.ordered.findIndex(
        (id) => (state.byId[id]?.timestamp ?? 0) < msg.timestamp,
      );
      if (idx === -1) {
        state.ordered.push(msg.id);
      } else {
        state.ordered.splice(idx, 0, msg.id);
      }

      // Insert into conversation
      const key = conversationKey(msg, myNodeId);
      if (!state.byConversation[key]) {
        state.byConversation[key] = [];
      }
      const convList = state.byConversation[key];
      const convIdx = convList.findIndex(
        (id) => (state.byId[id]?.timestamp ?? 0) < msg.timestamp,
      );
      if (convIdx === -1) {
        convList.push(msg.id);
      } else {
        convList.splice(convIdx, 0, msg.id);
      }
    }),
  );

  // If the message has no plaintext, try to fetch it from the backend's cache
  if (!msg.plaintext && msg.ciphertext) {
    fetchPlaintextForMessage(msg.id);
  }
}

/** Convert a WS envelope to a MessageResponse. */
function envelopeToMessage(env: WsEnvelope): MessageResponse {
  const recipient =
    "Node" in env.recipient
      ? env.recipient.Node
      : env.recipient.Room;

  // The WS envelope's ciphertext may be a byte array (number[]) from the
  // Rust backend's Vec<u8> serialization, or a hex string from the REST API.
  // Normalize to a hex string for consistent display.
  let ciphertext: string;
  if (typeof env.ciphertext === "string") {
    ciphertext = env.ciphertext;
  } else if (Array.isArray(env.ciphertext)) {
    ciphertext = Array.from(env.ciphertext, (b: number) => b.toString(16).padStart(2, "0")).join("");
  } else {
    ciphertext = "";
  }

  return {
    id: env.id,
    kind: env.kind,
    sender: env.sender,
    recipient,
    timestamp: env.timestamp,
    ciphertext,
    plaintext: env.plaintext,
    payment_amount_msat: env.payment_proof.amount_msat,
    payment_hash: env.payment_proof.payment_hash ?? "",
    references: env.references,
  };
}

/** Update delivery status for a message. */
function handleDeliveryStatus(event: WsDeliveryStatus): void {
  if (event.type !== "delivery_status") return;
  if (event.status !== "delivered" && event.status !== "rejected") return;
  setMessages(
    produce((state) => {
      state.deliveryStatus[event.message_id] = event.status as DeliveryStatusValue;
      if (event.status === "rejected" && event.reason) {
        state.rejectionReason[event.message_id] = event.reason;
      }
    }),
  );
}

/** Get the delivery status for a message. */
export function getDeliveryStatus(messageId: string): DeliveryStatusValue | undefined {
  return messages.deliveryStatus[messageId];
}

/** Get the rejection reason for a message. */
export function getRejectionReason(messageId: string): string | undefined {
  return messages.rejectionReason[messageId];
}

/** Initialize the message store — load history and wire WebSocket. */
export function initMessages(myNodeId: string): () => void {
  // Cache the node ID to avoid repeated identity API calls in load functions
  cachedMyNodeId = myNodeId;

  // Load recent messages from API
  loadMessages();

  // Wire WebSocket for real-time updates
  const unsubMsg = ws.onMessage((envelope) => {
    const msg = envelopeToMessage(envelope);
    // Only notify for genuinely new incoming messages (not self-sent, not duplicates)
    const isNew = !messages.byId[msg.id];
    const isIncoming = msg.sender !== myNodeId;
    insertMessage(msg, myNodeId);

    if (isNew && isIncoming) {
      const preview = msg.plaintext
        ? msg.plaintext.length > 80
          ? msg.plaintext.slice(0, 80) + "..."
          : msg.plaintext
        : "New encrypted message";
      const senderLabel = msg.sender.slice(0, 8) + "...";
      sendNotification(
        `Message from ${senderLabel}`,
        preview,
        "messages",
        `msg-${msg.id}`,
      );
    }
  });

  // Wire WebSocket for delivery status updates (ack/reject)
  const unsubDelivery = ws.onDelivery(handleDeliveryStatus);

  return () => {
    unsubMsg();
    unsubDelivery();
  };
}

/** Load messages from the API (global, for initial load). */
export async function loadMessages(limit = 50, before?: number): Promise<void> {
  setLoadingMessages(true);
  try {
    const msgs = await api.listMessages({ limit, before });
    // Use cached node ID; fall back to API call if not yet initialized
    const myId = cachedMyNodeId ?? (await api.identity()).node_id;
    for (const msg of msgs) {
      insertMessage(msg, myId);
    }
  } catch {
    // Message loading failed — UI shows empty state, retry on next load
  } finally {
    setLoadingMessages(false);
  }
}

/** Load messages for a specific conversation (includes both sent and received). */
export async function loadConversationMessages(
  conversationKey: string,
  limit = 50,
  before?: number,
): Promise<number> {
  try {
    const msgs = await api.listMessages({ limit, before, peer: conversationKey });
    const myId = cachedMyNodeId ?? (await api.identity()).node_id;
    for (const msg of msgs) {
      insertMessage(msg, myId);
    }
    return msgs.length;
  } catch {
    // Conversation loading failed — caller receives 0 count
    return 0;
  }
}

/**
 * Load older messages for a conversation. Returns true if there may be more.
 * Uses the oldest loaded message's timestamp as the cursor.
 */
export async function loadOlderMessages(conversationKey: string): Promise<boolean> {
  if (noMoreMessages[conversationKey]) return false;
  if (loadingOlder()) return false;

  setLoadingOlder(true);
  try {
    const convMsgs = getConversationMessages(conversationKey);
    // Oldest message is the last in the array (newest-first order from getConversationMessages)
    const oldest = convMsgs[convMsgs.length - 1];
    const before = oldest?.timestamp;

    const loaded = await loadConversationMessages(conversationKey, 50, before);
    if (loaded < 50) {
      noMoreMessages[conversationKey] = true;
    }
    return loaded >= 50;
  } finally {
    setLoadingOlder(false);
  }
}

/** Check if a conversation has no more older messages to load. */
export function hasMoreMessages(conversationKey: string): boolean {
  return !noMoreMessages[conversationKey];
}

/** Send a message via the API (requires pre-encrypted ciphertext + payment proof). */
export async function sendMessage(
  recipient: string,
  kind: number,
  ciphertext: string,
  paymentHash: string,
  preimage: string,
  amountMsat: number,
  isRoom = false,
): Promise<string> {
  const res = await api.sendMessage({
    recipient,
    is_room: isRoom,
    kind,
    ciphertext,
    payment_hash: paymentHash,
    preimage,
    amount_msat: amountMsat,
  });
  return res.message_id;
}

/** Compose and send a message — node handles E2EE encryption + Lightning payment. */
export async function composeMessage(
  recipient: string,
  kind: number,
  plaintext: string,
  references?: string[],
  isRoom = false,
): Promise<{ messageId: string; delivered: boolean; amountMsat: number }> {
  const res = await api.composeMessage({
    recipient,
    kind,
    plaintext,
    references,
    is_room: isRoom,
  });
  // Set initial delivery status based on compose response
  setMessages(
    produce((state) => {
      state.deliveryStatus[res.message_id] = res.delivered ? "sent" : "sending";
    }),
  );
  return {
    messageId: res.message_id,
    delivered: res.delivered,
    amountMsat: res.amount_msat,
  };
}

/** Get messages for a specific conversation. */
export function getConversationMessages(key: string): MessageResponse[] {
  const ids = messages.byConversation[key] ?? [];
  return ids
    .map((id) => messages.byId[id])
    .filter((m): m is MessageResponse => m !== undefined);
}

/** Get all conversation keys. */
export function getConversations(): string[] {
  return Object.keys(messages.byConversation);
}

export { messages, loadingMessages, loadingOlder };
