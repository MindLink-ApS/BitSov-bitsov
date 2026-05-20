import { createSignal, Show, For } from "solid-js";
import { A, useLocation } from "@solidjs/router";
import { authenticated, nodeId, wsStatus, logout } from "../stores/auth";
import { connectedCount, peers } from "../stores/peers";
import { displayName } from "../utils/formatting";
import { balance, formatMsat } from "../stores/payments";
import { theme, toggleTheme } from "../stores/theme";
import { getTotalUnreadCount } from "../stores/messages";
import {
  IconHome,
  IconMessages,
  IconInbox,
  IconGroups,
  IconDrive,
  IconCalendar,
  IconBrowser,
  IconDocument,
  IconBookmark,
  IconPeers,
  IconNetwork,
  IconWallet,
  IconAI,
  IconPhone,
  IconSettings,
  IconProfile,
  IconMoon,
  IconSun,
  IconChevronRight,
  IconCompass,
  IconMail,
} from "./Icons";

/**
 * Sidebar component — glass navigation with status, unread counts, and peer shortcuts.
 * Reference for ONB10: This sidebar links to InviteManagementView.
 */

interface NavSection {
  title: string;
  items: NavItem[];
  collapsible?: boolean;
}

interface NavItem {
  path: string;
  label: string;
  icon: (props?: Record<string, unknown>) => any;
  badge?: () => number;
  preview?: boolean;
}

const NAV_SECTIONS: NavSection[] = [
  {
    title: "Communication",
    items: [
      { path: "/home", label: "Home", icon: IconHome },
      { path: "/chat", label: "Messages", icon: IconMessages, badge: () => getTotalUnreadCount() },
      { path: "/inbox", label: "Inbox", icon: IconInbox },
      { path: "/groups", label: "Groups", icon: IconGroups },
    ],
  },
  {
    title: "Workspace",
    items: [
      { path: "/drive", label: "Drive", icon: IconDrive },
      { path: "/calendar", label: "Calendar", icon: IconCalendar, preview: true },
    ],
  },
  {
    title: "Peer Sites",
    items: [
      { path: "/browser", label: "Peer Sites", icon: IconBrowser },
      { path: "/my-content", label: "My Content", icon: IconDocument },
      { path: "/bookmarks", label: "Bookmarks", icon: IconBookmark },
    ],
  },
  {
    title: "Network",
    items: [
      { path: "/peers", label: "Peers", icon: IconPeers },
      { path: "/discovery", label: "Discovery", icon: IconCompass },
      { path: "/network", label: "Network", icon: IconNetwork },
      { path: "/wallet", label: "Wallet", icon: IconWallet },
    ],
  },
  {
    title: "Intelligence",
    items: [
      { path: "/ai", label: "AI", icon: IconAI, preview: true },
    ],
  },
  {
    title: "System",
    items: [
      { path: "/voip", label: "VoIP", icon: IconPhone, preview: true },
      { path: "/invites", label: "Invites", icon: IconMail },
      { path: "/settings", label: "Settings", icon: IconSettings },
      { path: "/profile", label: "Profile", icon: IconProfile },
    ],
  },
];

function WsIndicator() {
  const status = () => wsStatus();
  const dotClass = () => {
    switch (status()) {
      case "connected": return "status-dot status-dot-online";
      case "connecting": return "status-dot status-dot-connecting";
      default: return "status-dot status-dot-offline";
    }
  };
  return <span class={dotClass()} title={`WebSocket: ${status()}`} />;
}

function SidebarPeerList() {
  const [expanded, setExpanded] = createSignal(true);

  return (
    <div class="nav-section">
      <button
        class="nav-section-title nav-section-toggle"
        onClick={() => setExpanded(!expanded())}
        aria-expanded={expanded()}
        aria-label={expanded() ? "Collapse People section" : "Expand People section"}
      >
        <span>People</span>
        <span class={`nav-section-arrow ${expanded() ? "open" : ""}`}>
          <IconChevronRight size={12} />
        </span>
      </button>
      <Show when={expanded()}>
        <div class="nav-peer-list">
          <For each={peers.slice(0, 8)}>
            {(peer) => (
              <A
                href="/chat"
                class="nav-peer-item"
                title={peer.node_id}
              >
                <span class={`status-dot ${peer.connected ? "status-dot-online" : "status-dot-offline"}`} />
                <span class="truncate text-sm">
                  {displayName(peer.node_id)}
                </span>
              </A>
            )}
          </For>
          <Show when={peers.length > 8}>
            <A href="/peers" class="nav-peer-more text-xs text-muted">
              +{peers.length - 8} more
            </A>
          </Show>
        </div>
      </Show>
    </div>
  );
}

interface SidebarProps {
  open: boolean;
  onClose: () => void;
}

export default function Sidebar(props: SidebarProps) {
  const location = useLocation();

  return (
    <aside class={`sidebar glass ${props.open ? "open" : ""}`}>
      <div class="sidebar-header">
        {/* Brand */}
        <div class="flex items-center gap-8">
          <img src="/logo.jpeg" alt="BitSov" style={{ width: "28px", height: "28px", "border-radius": "6px" }} />
          <span class="text-lg font-bold text-accent">BitSov</span>
        </div>

        {/* Node info */}
        <Show when={authenticated()}>
          <div
            class="mono truncate text-xs text-muted mt-8"
            title={nodeId() ?? ""}
          >
            {nodeId()?.slice(0, 16)}...
          </div>
          <div class="flex items-center gap-8 mt-6">
            <WsIndicator />
            <span class="text-xs text-secondary">
              {connectedCount()} peer{connectedCount() !== 1 ? "s" : ""}
            </span>
            <Show when={balance() !== null}>
              <span class="text-xs text-accent ml-auto">
                {formatMsat(balance()!)}
              </span>
            </Show>
          </div>
        </Show>
      </div>

      {/* Navigation */}
      <nav class="sidebar-nav" aria-label="Main navigation">
        <For each={NAV_SECTIONS}>
          {(section) => (
            <div class="nav-section">
              <div class="nav-section-title">{section.title}</div>
              <For each={section.items}>
                {(item) => (
                  <A
                    href={item.path}
                    class={`nav-item ${location.pathname === item.path ? "active" : ""}`}
                    aria-current={location.pathname === item.path ? "page" : undefined}
                    onClick={() => props.onClose()}
                  >
                    <span class="nav-icon">{item.icon({ size: 16 })}</span>
                    {item.label}
                    <Show when={item.preview}>
                      <span class="nav-preview-badge">Preview</span>
                    </Show>
                    <Show when={item.badge && item.badge() > 0}>
                      <span class="nav-badge">{item.badge!()}</span>
                    </Show>
                  </A>
                )}
              </For>
            </div>
          )}
        </For>

        {/* Quick peer list */}
        <Show when={peers.length > 0}>
          <SidebarPeerList />
        </Show>
      </nav>

      {/* Footer */}
      <div class="sidebar-footer">
        <button class="theme-toggle" onClick={toggleTheme} title="Toggle theme" aria-label="Toggle theme">
          <span class="theme-toggle-icon">
            {theme() === "dark" ? <IconMoon size={14} /> : <IconSun size={14} />}
          </span>
          {theme() === "dark" ? "Light mode" : "Dark mode"}
        </button>
        <Show when={authenticated()}>
          <button
            class="btn btn-ghost btn-sm w-full mt-4"
            onClick={logout}
            aria-label="Disconnect from node"
          >
            Disconnect
          </button>
        </Show>
      </div>
    </aside>
  );
}
