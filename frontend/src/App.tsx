/** Root application component with routing. */

import { Show, onMount, createSignal, lazy, onCleanup } from "solid-js";
import { Router, Route, Navigate } from "@solidjs/router";
import Layout from "./components/Layout";
import Login from "./components/Login";
import Onboarding, { hasCompletedOnboarding } from "./components/Onboarding";
import ToastContainer from "./components/ToastContainer";
import AppErrorBoundary, { RouteErrorBoundary } from "./components/ErrorBoundary";
import NodeOffline from "./components/NodeOffline";
import CommandPalette from "./components/CommandPalette";
import { authenticated, restoreSession, nodeId } from "./stores/auth";
import { seedProfileIfEmpty } from "./stores/profileSeed";
import { peers, refreshPeers } from "./stores/peers";
import * as onboardingState from "./state/onboarding";

const Home = lazy(() => import("./components/Home"));
const ChatView = lazy(() => import("./components/ChatView"));
const InboxView = lazy(() => import("./components/Inbox"));
const PeerList = lazy(() => import("./components/PeerList"));
const Groups = lazy(() => import("./components/Rooms"));
const WalletView = lazy(() => import("./components/Wallet"));
const Settings = lazy(() => import("./components/Settings"));
const Drive = lazy(() => import("./components/Files"));
const NetworkView = lazy(() => import("./components/NetworkView"));
const AIView = lazy(() => import("./components/AIView"));
const VoIPView = lazy(() => import("./components/VoIPView"));
const CalendarView = lazy(() => import("./components/CalendarView"));
const ProfileView = lazy(() => import("./components/ProfileView"));
const BrowserView = lazy(() => import("./components/BrowserView"));
const MyContent = lazy(() => import("./components/MyContent"));
const BookmarksView = lazy(() => import("./components/Bookmarks"));
const ResyncView = lazy(() => import("./components/ResyncView"));
const DiscoveryView = lazy(() => import("./components/DiscoveryView"));
const OnboardingView = lazy(() => import("./views/OnboardingView"));
const InviteManagementView = lazy(() => import("./views/InviteManagementView"));

/** Wrap a component in a per-route error boundary so one view crash doesn't take down the app. */
function guarded(Component: () => import("solid-js").JSX.Element) {
  return () => <RouteErrorBoundary><Component /></RouteErrorBoundary>;
}

export default function App() {
  const [ready, setReady] = createSignal(false);
  const [showOnboardingWizard, setShowOnboardingWizard] = createSignal(false);
  const [paletteOpen, setPaletteOpen] = createSignal(false);

  onMount(async () => {
    // Global keybinding for Command Palette (Cmd+K / Ctrl+K)
    const handleGlobalKeyDown = (e: KeyboardEvent) => {
      const isMac = navigator.platform.toUpperCase().indexOf("MAC") >= 0;
      const isK = e.key.toLowerCase() === "k";
      const modifier = isMac ? e.metaKey : e.ctrlKey;

      if (modifier && isK) {
        e.preventDefault();
        setPaletteOpen((prev) => !prev);
      }

      if (e.key === "Escape" && paletteOpen()) {
        setPaletteOpen(false);
      }
    };

    window.addEventListener("keydown", handleGlobalKeyDown);
    onCleanup(() => window.removeEventListener("keydown", handleGlobalKeyDown));

    const restored = await restoreSession();
    if (restored) {
      await seedProfileIfEmpty(nodeId() ?? "");
      await refreshPeers();
      if (!hasCompletedOnboarding()) {
        setShowOnboardingWizard(true);
      }
    }
    setReady(true);
  });

  /** Called after successful login — seed profile + check if onboarding needed. */
  const handleLoginComplete = async () => {
    await seedProfileIfEmpty(nodeId() ?? "");
    await refreshPeers();
    if (!hasCompletedOnboarding()) {
      setShowOnboardingWizard(true);
    }
  };

  /** Should we show the invite-paste onboarding view? */
  const showInviteFlow = () =>
    onboardingState.inFlow() ||
    (!onboardingState.dismissed() && peers.length === 0 && !showOnboardingWizard());

  return (
    <Show
      when={ready()}
      fallback={
        <div class="loading-center">
          <div class="connection-spinner" style={{ "margin-bottom": "12px" }}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10" /><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" /></svg>
          </div>
          <span style={{ color: "var(--text-secondary)", "font-size": "14px" }}>Loading BitSov...</span>
        </div>
      }
    >
      <Show when={authenticated()} fallback={<Login onLoginComplete={handleLoginComplete} />}>
        <Show when={!showOnboardingWizard()} fallback={
          <Onboarding onComplete={() => setShowOnboardingWizard(false)} />
        }>
          <Show when={!showInviteFlow()} fallback={<OnboardingView />}>
            <AppErrorBoundary>
              <Router root={Layout}>
                <Route path="/home" component={guarded(Home)} />
                <Route path="/chat" component={guarded(ChatView)} />
                <Route path="/inbox" component={guarded(InboxView)} />
                <Route path="/peers" component={guarded(PeerList)} />
                <Route path="/groups" component={guarded(Groups)} />
                <Route path="/drive" component={guarded(Drive)} />
                <Route path="/wallet" component={guarded(WalletView)} />
                <Route path="/calendar" component={guarded(CalendarView)} />
                <Route path="/network" component={guarded(NetworkView)} />
                <Route path="/ai" component={guarded(AIView)} />
                <Route path="/voip" component={guarded(VoIPView)} />
                <Route path="/settings" component={guarded(Settings)} />
                <Route path="/profile" component={guarded(ProfileView)} />
                <Route path="/browser" component={guarded(BrowserView)} />
                <Route path="/my-content" component={guarded(MyContent)} />
                <Route path="/bookmarks" component={guarded(BookmarksView)} />
                <Route path="/resync" component={guarded(ResyncView)} />
                <Route path="/discovery" component={guarded(DiscoveryView)} />
                <Route path="/invites" component={guarded(InviteManagementView)} />
                <Route path="/onboarding" component={OnboardingView} />
                {/* Legacy routes redirect */}
                <Route path="/rooms" component={() => <Navigate href="/groups" />} />
                <Route path="/files" component={() => <Navigate href="/drive" />} />
                <Route path="/payments" component={() => <Navigate href="/wallet" />} />
                <Route path="*" component={() => <Navigate href="/home" />} />
              </Router>
            </AppErrorBoundary>
          </Show>
        </Show>
      </Show>
      <ToastContainer />
      <NodeOffline />
      <CommandPalette isOpen={paletteOpen()} setIsOpen={setPaletteOpen} />
    </Show>
  );
}
