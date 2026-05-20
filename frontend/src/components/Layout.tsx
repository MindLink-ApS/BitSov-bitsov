/** Main application layout — glass sidebar + content area. */

import { createSignal, Show, For, onMount, onCleanup } from "solid-js";
import type { JSX } from "solid-js";
import { type RouteSectionProps, A, useLocation, useNavigate } from "@solidjs/router";
import { authenticated, nodeId, wsStatus, logout } from "../stores/auth";
import { connectedCount, peers } from "../stores/peers";
import { initContacts } from "../stores/contacts";
import { displayName } from "../utils/formatting";
import { balance, formatMsat } from "../stores/payments";
import { theme, toggleTheme } from "../stores/theme";
import { getTotalUnreadCount } from "../stores/messages";
import { rightPanelOpen, toggleRightPanel } from "../stores/layout";
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
import ConnectionBanner from "./ConnectionBanner";
import SovereigntyBanner from "./SovereigntyBanner";
import FundWalletBanner from "./FundWalletBanner";
import RightPanel from "./RightPanel";
import Sidebar from "./Sidebar";

export default function Layout(props: RouteSectionProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = createSignal(false);

  // Keyboard shortcuts: Alt+1-9 for quick navigation, Escape to close sidebar
  const handleKeyDown = (e: KeyboardEvent) => {
    // Flat list of nav paths for keyboard shortcut navigation
    const QUICK_NAV = ["/home", "/chat", "/inbox", "/groups", "/drive", "/wallet", "/peers", "/settings", "/profile"];
    
    // Alt+number for quick nav
    if (e.altKey && !e.ctrlKey && !e.metaKey) {
      const num = parseInt(e.key, 10);
      if (num >= 1 && num <= 9 && QUICK_NAV[num - 1]) {
        e.preventDefault();
        navigate(QUICK_NAV[num - 1]);
        setSidebarOpen(false);
      }
    }
    // Escape closes mobile sidebar
    if (e.key === "Escape" && sidebarOpen()) {
      e.preventDefault();
      setSidebarOpen(false);
    }
  };

  onMount(() => {
    document.addEventListener("keydown", handleKeyDown);
  });

  // Start contact polling (returns cleanup fn).
  const stopContactPolling = initContacts();

  onCleanup(() => {
    document.removeEventListener("keydown", handleKeyDown);
    stopContactPolling();
  });

  return (
    <div class={`app-shell ${rightPanelOpen() ? "panel-open" : "panel-collapsed"}`}>
      <a href="#main-content" class="skip-link">Skip to content</a>

      {/* Mobile hamburger */}
      <button
        class="sidebar-toggle"
        onClick={() => setSidebarOpen(!sidebarOpen())}
        aria-label="Toggle navigation"
      >
        <span class="sidebar-toggle-bar" />
        <span class="sidebar-toggle-bar" />
        <span class="sidebar-toggle-bar" />
      </button>

      {/* Mobile backdrop */}
      <Show when={sidebarOpen()}>
        <div class="sidebar-backdrop" onClick={() => setSidebarOpen(false)} />
      </Show>

      {/* Sidebar */}
      <Sidebar open={sidebarOpen()} onClose={() => setSidebarOpen(false)} />

      {/* Main Content */}
      <main id="main-content" class="main-content glass">
        {/* Right panel toggle button */}
        <button
          class="right-panel-toggle"
          onClick={toggleRightPanel}
          title={rightPanelOpen() ? "Collapse AI panel" : "Expand AI panel"}
          aria-label={rightPanelOpen() ? "Collapse AI panel" : "Expand AI panel"}
          aria-expanded={rightPanelOpen()}
        >
          <IconAI size={16} />
        </button>
        <ConnectionBanner />
        <SovereigntyBanner />
        <FundWalletBanner />
        {props.children}
      </main>

      {/* Right Panel */}
      <RightPanel />
    </div>
  );
}
