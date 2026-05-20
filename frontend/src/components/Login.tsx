/** Login screen — glassmorphism panel with local node connect + advanced key auth.
 *
 * Cloud tier users see a remote URL input by default.
 * Light/Full tier users see the local connect button.
 */

import { createSignal, Show, createEffect } from "solid-js";
import { login, loginLocal, authError, loading, setNodeUrl, getNodeUrl } from "../stores/auth";
import { tier } from "../stores/tier";
import type { NodeTier } from "../stores/tier";
import { tierInfo } from "../stores/tier";
import { IconGlobe, IconShield, IconLock } from "./Icons";
import RecoveryWizard from "./RecoveryWizard";

const CLOUD_DEFAULT_URL = "https://cloud.konsensus.network";

interface LoginProps {
  onLoginComplete?: () => void;
}

export default function Login(props: LoginProps) {
  const [showAdvanced, setShowAdvanced] = createSignal(false);
  const [showRestore, setShowRestore] = createSignal(false);
  const [privateKey, setPrivateKey] = createSignal("");
  const [nodeUrl, setNodeUrlLocal] = createSignal(getNodeUrl());
  const [showKey, setShowKey] = createSignal(false);
  const [remoteUrl, setRemoteUrl] = createSignal(CLOUD_DEFAULT_URL);

  // Sync remote URL when switching to cloud tier
  createEffect(() => {
    if (tier() === "cloud") {
      const stored = getNodeUrl();
      if (stored !== "http://127.0.0.1:3141") {
        setRemoteUrl(stored);
      }
    }
  });

  const handleLocalLogin = async () => {
    try {
      await loginLocal();
      props.onLoginComplete?.();
    } catch {
      // Error is captured in authError signal
    }
  };

  const handleRemoteConnect = async () => {
    const url = remoteUrl().trim();
    if (!url) return;
    setNodeUrl(url);
    try {
      await loginLocal();
      props.onLoginComplete?.();
    } catch {
      // Error is captured in authError signal
    }
  };

  const handleKeyLogin = async (e: Event) => {
    e.preventDefault();
    const key = privateKey().trim();
    if (!key) return;
    // Apply custom node URL before authenticating
    setNodeUrl(nodeUrl());
    try {
      await login(key);
      props.onLoginComplete?.();
    } catch {
      // Error is captured in authError signal
    }
  };

  const isCloudTier = () => tier() === "cloud";
  const currentTierInfo = () => tierInfo(tier());

  const TierIcon = (p: { tier: NodeTier }) => {
    switch (p.tier) {
      case "cloud": return <IconGlobe size={14} />;
      case "light": return <IconShield size={14} />;
      case "full": return <IconLock size={14} />;
    }
  };

  return (
    <div class="login-container">
      <div class="login-bg" />

      <div class="login-card glass animate-fade-in-scale">
        {/* Logo */}
        <div class="login-logo">
          <img src="/logo.jpeg" alt="BitSov" style={{ width: "64px", height: "64px", "border-radius": "12px", "margin-bottom": "16px" }} />
          <div class="login-title">BitSov</div>
          <div class="login-subtitle">Bitcoin Sovereign Protocol</div>
        </div>

        {/* Tier indicator */}
        <div class="login-tier-badge">
          <TierIcon tier={tier()} />
          <span>{currentTierInfo().label}</span>
        </div>

        {/* Error */}
        <Show when={authError()}>
          <div class="alert alert-error animate-fade-in mb-16">
            <span>{authError()}</span>
          </div>
        </Show>

        {/* Cloud tier: remote URL input */}
        <Show when={isCloudTier()}>
          <div class="form-group">
            <label class="form-label">Node URL</label>
            <input
              type="text"
              value={remoteUrl()}
              onInput={(e) => setRemoteUrl(e.currentTarget.value)}
              placeholder="https://cloud.konsensus.network"
              class="w-full"
            />
            <p class="form-hint">
              Connect to a hosted BitSov node
            </p>
          </div>

          <button
            type="button"
            class="btn btn-primary btn-lg w-full"
            disabled={loading() || !remoteUrl().trim()}
            onClick={handleRemoteConnect}
          >
            {loading() ? "Connecting..." : "Connect to Cloud Node"}
          </button>
        </Show>

        {/* Light/Full tier: local connect */}
        <Show when={!isCloudTier()}>
          <button
            type="button"
            class="btn btn-primary btn-lg w-full"
            disabled={loading()}
            onClick={handleLocalLogin}
          >
            {loading() ? "Connecting..." : "Connect to Local Node"}
          </button>

          <p class="text-xs text-muted text-center mt-8 mb-20">
            Connects to your node at {getNodeUrl()}
          </p>
        </Show>

        {/* Advanced toggle */}
        <div class="text-center mb-16 mt-16">
          <button
            type="button"
            class="btn btn-ghost btn-sm"
            onClick={() => setShowAdvanced(!showAdvanced())}
          >
            {showAdvanced() ? "Hide advanced options" : "Advanced: connect with private key"}
          </button>
        </div>

        {/* Advanced: Key-based auth */}
        <Show when={showAdvanced()}>
          <div class="animate-fade-in">
            <div class="divider" />
            <form onSubmit={handleKeyLogin}>
              <div class="form-group">
                <label class="form-label">Node URL</label>
                <input
                  type="text"
                  value={nodeUrl()}
                  onInput={(e) => setNodeUrlLocal(e.currentTarget.value)}
                  placeholder="http://127.0.0.1:3141"
                  class="w-full"
                />
              </div>

              <div class="form-group">
                <label class="form-label">Ed25519 Private Key (hex)</label>
                <div class="relative">
                  <input
                    type={showKey() ? "text" : "password"}
                    value={privateKey()}
                    onInput={(e) => setPrivateKey(e.currentTarget.value)}
                    placeholder="64 hex characters..."
                    class="mono w-full"
                    style={{ "padding-right": "52px" }}
                  />
                  <button
                    type="button"
                    onClick={() => setShowKey(!showKey())}
                    class="btn btn-ghost btn-sm login-key-toggle"
                  >
                    {showKey() ? "Hide" : "Show"}
                  </button>
                </div>
                <p class="form-hint">
                  Your key never leaves this device. Get it from:{" "}
                  <code class="mono text-secondary">konsensus sign-challenge</code>
                </p>
              </div>

              <button
                type="submit"
                class="btn btn-secondary btn-lg w-full"
                disabled={loading() || !privateKey().trim()}
              >
                {loading() ? "Authenticating..." : "Authenticate with Key"}
              </button>
            </form>
          </div>
        </Show>

        {/* Restore from mnemonic */}
        <Show when={!showRestore()}>
          <div class="text-center mt-8">
            <button
              type="button"
              class="btn btn-ghost btn-sm"
              onClick={() => setShowRestore(true)}
            >
              Restore from recovery phrase
            </button>
          </div>
        </Show>

        <Show when={showRestore()}>
          <div class="animate-fade-in mt-16">
            <div class="divider" />
            <RecoveryWizard
              onRestored={() => {
                setShowRestore(false);
                handleLocalLogin();
              }}
              onCancel={() => setShowRestore(false)}
            />
          </div>
        </Show>

        <p class="text-xs text-muted text-center mt-24">
          v2.0 — Bitcoin-anchored identity, payment-gated communication
        </p>
      </div>
    </div>
  );
}
