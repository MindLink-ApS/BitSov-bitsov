/**
 * Home Dashboard — first view after login.
 * Activity summary, recent conversations, peer status, Lightning balance,
 * quick actions, and network health.
 */

import { createSignal, Show, For, onMount, createResource } from "solid-js";
import { A, useNavigate } from "@solidjs/router";
import { nodeId, api } from "../stores/auth";
import { peers, refreshPeers } from "../stores/peers";
import { balance, refreshBalance, formatMsat } from "../stores/payments";
import { messages, getConversations, getConversationMessages, getTotalUnreadCount, initMessages } from "../stores/messages";
import { refreshRooms, isRoomKey, getRoomName, roomsById } from "../stores/rooms";
import { files, refreshFiles } from "../stores/files";
import type { HealthResponse } from "../api/types";
import { MessageKind } from "../api/types";
import type { MessageResponse } from "../api/types";
import {
  IconMessages,
  IconGroups,
  IconLightning,
  IconPeers,
  IconDrive,
  IconActivity,
  IconPlus,
  IconSend,
  IconWallet,
  IconEncrypted,
  IconCalendar,
  IconInbox,
} from "./Icons";
import { truncateId, formatRelativeTime } from "../utils/formatting";
import { loadJSON } from "../utils/storage";


function peerLabel(id: string): string {
  if (isRoomKey(id)) return getRoomName(id) ?? `Group ${id.slice(0, 8)}`;
  const peer = peers.find((p) => p.node_id === id);
  return peer?.label ?? truncateId(id);
}

export default function Home() {
  const navigate = useNavigate();
  const [health] = createResource<HealthResponse>(() => api.health());

  onMount(() => {
    refreshPeers();
    refreshBalance();
    refreshRooms();
    refreshFiles();
    const myId = nodeId();
    if (myId) {
      initMessages(myId);
    }
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

  const recentConversations = () => {
    const convs = conversations();
    const withLastMsg = convs
      .map((key) => {
        const msgs = getConversationMessages(key);
        return { key, lastMsg: msgs[0] ?? null };
      })
      .filter((c) => c.lastMsg !== null)
      .sort((a, b) => b.lastMsg!.timestamp - a.lastMsg!.timestamp);
    return withLastMsg.slice(0, 5);
  };

  const onlinePeers = () => peers.filter((p) => p.connected);
  const offlinePeers = () => peers.filter((p) => !p.connected);
  const unreadCount = () => getTotalUnreadCount();

  // Count inbox (longform) messages received
  const inboxCount = () => {
    const myNodeId = nodeId() ?? "";
    return messages.ordered
      .map((id) => messages.byId[id])
      .filter((m): m is MessageResponse =>
        !!m && m.sender !== myNodeId &&
        (m.kind === MessageKind.LONGFORM || m.kind === MessageKind.REPLY)
      ).length;
  };

  // Calendar events from localStorage (shared with CalendarView)
  const upcomingEvents = () => {
    const events: Array<{ id: string; title: string; date: string; time: string; color: string }> =
      loadJSON("konsensus_calendar_events", []);
    const now = new Date();
    const todayStr = now.toISOString().slice(0, 10);
    const weekLater = new Date(now.getTime() + 7 * 86_400_000);
    const weekStr = weekLater.toISOString().slice(0, 10);
    return events
      .filter((e) => e.date >= todayStr && e.date <= weekStr)
      .sort((a, b) => `${a.date}T${a.time}`.localeCompare(`${b.date}T${b.time}`))
      .slice(0, 5);
  };

  return (
    <div class="page content-max">
      <div class="page-header">
        <h2 class="page-title">Home</h2>
        <span class="text-xs text-muted">Sovereign Dashboard</span>
      </div>

      {/* Activity Summary */}
      <div class="dashboard-grid mb-16">
        <A href="/chat" class="dashboard-stat-card card">
          <div class="dashboard-stat-icon text-accent"><IconMessages size={20} /></div>
          <div class="dashboard-stat-value">{unreadCount()}</div>
          <div class="dashboard-stat-label">Unread Messages</div>
        </A>
        <A href="/peers" class="dashboard-stat-card card">
          <div class="dashboard-stat-icon text-success"><IconPeers size={20} /></div>
          <div class="dashboard-stat-value">{onlinePeers().length}/{peers.length}</div>
          <div class="dashboard-stat-label">Peers Online</div>
        </A>
        <A href="/inbox" class="dashboard-stat-card card">
          <div class="dashboard-stat-icon text-secondary"><IconInbox size={20} /></div>
          <div class="dashboard-stat-value">{inboxCount()}</div>
          <div class="dashboard-stat-label">Inbox</div>
        </A>
        <A href="/wallet" class="dashboard-stat-card card">
          <div class="dashboard-stat-icon" style={{ color: "var(--bitcoin-orange)" }}><IconLightning size={20} /></div>
          <div class="dashboard-stat-value">{balance() !== null ? formatMsat(balance()!) : "--"}</div>
          <div class="dashboard-stat-label">Lightning Balance</div>
        </A>
      </div>

      {/* Quick Actions */}
      <div class="card mb-16">
        <div class="card-header">Quick Actions</div>
        <div class="dashboard-actions">
          <button class="btn btn-secondary btn-sm icon-text" onClick={() => navigate("/chat")}>
            <IconSend size={14} /> New Message
          </button>
          <button class="btn btn-secondary btn-sm icon-text" onClick={() => navigate("/groups")}>
            <IconPlus size={14} /> New Group
          </button>
          <button class="btn btn-secondary btn-sm icon-text" onClick={() => navigate("/wallet")}>
            <IconWallet size={14} /> Send Payment
          </button>
        </div>
      </div>

      <div class="grid grid-cols-2 gap-16">
        {/* Recent Conversations */}
        <div class="card">
          <div class="card-header flex justify-between items-center">
            Recent Conversations
            <A href="/chat" class="text-xs text-accent no-underline">View all</A>
          </div>
          <Show when={recentConversations().length > 0} fallback={
            <div class="text-sm text-muted py-12">No conversations yet</div>
          }>
            <For each={recentConversations()}>
              {(conv) => (
                <A
                  href="/chat"
                  class="dashboard-conv-item no-underline"
                >
                  <div class="flex items-center gap-8">
                    <Show when={isRoomKey(conv.key)}>
                      <span class="text-muted"><IconGroups size={14} /></span>
                    </Show>
                    <span class="text-sm font-medium truncate">{peerLabel(conv.key)}</span>
                  </div>
                  <div class="flex justify-between mt-2">
                    <span class="text-xs text-muted truncate flex-1">
                      {conv.lastMsg?.plaintext?.slice(0, 50) ?? "Encrypted"}
                    </span>
                    <span class="text-xs text-muted flex-shrink-0 ml-8">
                      {formatRelativeTime(conv.lastMsg!.timestamp)}
                    </span>
                  </div>
                </A>
              )}
            </For>
          </Show>
        </div>

        {/* Peer Status */}
        <div class="card">
          <div class="card-header flex justify-between items-center">
            Peer Status
            <A href="/peers" class="text-xs text-accent no-underline">View all</A>
          </div>
          <Show when={peers.length > 0} fallback={
            <div class="text-sm text-muted py-12">No peers whitelisted</div>
          }>
            <For each={[...onlinePeers(), ...offlinePeers()].slice(0, 6)}>
              {(peer) => (
                <div class="dashboard-peer-item">
                  <span class={`status-dot ${peer.connected ? "status-dot-online" : "status-dot-offline"}`} />
                  <span class="text-sm truncate flex-1">{peer.label ?? truncateId(peer.node_id)}</span>
                  <span class={`text-xs ${peer.connected ? "text-success" : "text-muted"}`}>
                    {peer.connected ? "Online" : "Offline"}
                  </span>
                </div>
              )}
            </For>
          </Show>
        </div>
      </div>

      {/* Upcoming Events */}
      <Show when={upcomingEvents().length > 0}>
        <div class="card mt-16">
          <div class="card-header flex justify-between items-center">
            <span class="flex items-center gap-8"><IconCalendar size={16} /> Upcoming Events</span>
            <A href="/calendar" class="text-xs text-accent no-underline">View calendar</A>
          </div>
          <For each={upcomingEvents()}>
            {(event) => (
              <div class="dashboard-event-item">
                <span class="dashboard-event-dot" style={{ background: event.color }} />
                <div class="flex-1 min-w-0">
                  <span class="text-sm font-medium truncate">{event.title}</span>
                </div>
                <span class="text-xs text-muted flex-shrink-0">
                  {event.date === new Date().toISOString().slice(0, 10) ? "Today" : event.date.slice(5)} {event.time}
                </span>
              </div>
            )}
          </For>
        </div>
      </Show>

      {/* Network Health */}
      <div class="card mt-16">
        <div class="card-header flex items-center gap-8">
          <IconActivity size={16} /> Network Health
        </div>
        <Show when={health()} fallback={
          <div class="skeleton" style={{ height: "40px" }} />
        }>
          {(h) => (
            <div class="stat-grid">
              <div class="stat-item">
                <div class="stat-label">Status</div>
                <div><span class="badge badge-success">{h().status}</span></div>
              </div>
              <div class="stat-item">
                <div class="stat-label">Connected Peers</div>
                <div class="stat-value">{h().connected_peers}</div>
              </div>
              <div class="stat-item">
                <div class="stat-label">E2EE Sessions</div>
                <div class="stat-value flex items-center gap-4">
                  <IconEncrypted size={14} /> {h().e2ee_sessions}
                </div>
              </div>
              <div class="stat-item">
                <div class="stat-label">Pending Deliveries</div>
                <div class="stat-value">{h().pending_deliveries}</div>
              </div>
              <div class="stat-item">
                <div class="stat-label">Lightning</div>
                <div>
                  <span class={`badge ${h().lightning_payment_capable ? "badge-success" : h().lightning_available ? "badge-warning" : "badge-error"}`}>
                    {h().lightning_payment_capable ? "Active" : h().lightning_available ? "No Outbound" : "Unavailable"}
                  </span>
                </div>
              </div>
              <div class="stat-item">
                <div class="stat-label">Uptime</div>
                <div class="stat-value">{Math.floor(h().uptime_secs / 3600)}h {Math.floor((h().uptime_secs % 3600) / 60)}m</div>
              </div>
            </div>
          )}
        </Show>
      </div>
    </div>
  );
}
