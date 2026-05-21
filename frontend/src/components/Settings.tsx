/** Settings view — node identity card, status, sovereignty, mnemonic, about — glass cards. */

import { createSignal, Show, createResource, For, createMemo } from "solid-js";
import { identity, nodeId, wsStatus } from "../stores/auth";
import { api, getNodeUrl } from "../stores/auth";
import type { HealthResponse } from "../api/types";
import { tier, setTier, tierInfo, type NodeTier } from "../stores/tier";
import {
  IconLightbulb,
  IconBell,
  IconBellOff,
  IconClock,
  IconShield,
  IconGlobe,
  IconLock,
  IconKey,
  IconWarning,
  IconCheck,
  IconEye,
  IconPencil,
} from "./Icons";
import {
  notifSettings,
  notifPermission,
  toggleNotifications,
  updateNotifSettings,
} from "../stores/notifications";
import { truncateId } from "../utils/formatting";
import { loadJSON, saveJSON, loadString, saveString } from "../utils/storage";
import { peers } from "../stores/peers";
import { getHideReactions, setHideReactions } from "../stores/reactionPolicy";
import HostingBanner from "./HostingBanner";

const RETENTION_OPTIONS = [
  { value: 0, label: "Forever" },
  { value: 90, label: "90 days" },
  { value: 30, label: "30 days" },
  { value: 7, label: "7 days" },
  { value: 1, label: "24 hours" },
];

function CopyableField(props: { label: string; value: string }) {
  const [copied, setCopied] = createSignal(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(props.value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }).catch(() => {
      /* Clipboard unavailable — ignore silently */
    });
  };

  return (
    <div class="form-group">
      <label class="form-label">{props.label}</label>
      <div class="copyable">
        <span class="mono truncate text-sm flex-1">
          {props.value}
        </span>
        <button class="btn btn-ghost btn-sm" onClick={handleCopy} aria-label={`Copy ${props.label}`}>
          {copied() ? "Copied" : "Copy"}
        </button>
      </div>
    </div>
  );
}

const TIER_CARDS: Array<{ id: NodeTier; icon: typeof IconGlobe; accent: string }> = [
  { id: "cloud", icon: IconGlobe, accent: "var(--color-warning)" },
  { id: "light", icon: IconShield, accent: "var(--color-success)" },
  { id: "full", icon: IconLock, accent: "var(--color-accent)" },
];


// ── Free/Busy Policy ─────────────────────────────────────────────────────

type FreeBusyPolicy = "deny" | "partial" | "full";

const FREEBUSY_POLICY_KEY = "bitsov_freebusy_policies";

function loadFreeBusyPolicies(): Record<string, FreeBusyPolicy> {
  return loadJSON<Record<string, FreeBusyPolicy>>(FREEBUSY_POLICY_KEY, {});
}

function saveFreeBusyPolicies(policies: Record<string, FreeBusyPolicy>): void {
  saveJSON(FREEBUSY_POLICY_KEY, policies);
}

const FREEBUSY_POLICY_LABELS: Record<FreeBusyPolicy, string> = {
  deny: "Deny — share nothing",
  partial: "Partial — busy/free only",
  full: "Full — show event titles",
};

// ── Profile ──────────────────────────────────────────────────────────────

const PROFILE_KEY = "konsensus_user_profile";

function loadDisplayName(): string {
  const p = loadJSON<{ displayName?: string }>(PROFILE_KEY, {});
  return p.displayName || "";
}

function saveDisplayName(name: string) {
  const p = loadJSON(PROFILE_KEY, { displayName: "", title: "", bio: "", status: "online" });
  p.displayName = name;
  saveJSON(PROFILE_KEY, p);
}

export default function Settings() {
  const [health] = createResource<HealthResponse>(() => api.health());
  const [idCopied, setIdCopied] = createSignal(false);
  const [retentionDays, setRetentionDays] = createSignal(
    parseInt(loadString("konsensus_retention_days") ?? "0", 10)
  );
  const [displayName, setDisplayName] = createSignal(loadDisplayName());
  const [editingName, setEditingName] = createSignal(false);
  const [editNameValue, setEditNameValue] = createSignal("");
  const [mnemonicVisible, setMnemonicVisible] = createSignal(false);
  const [mnemonicWords, setMnemonicWords] = createSignal<string[]>([]);
  const [mnemonicLoading, setMnemonicLoading] = createSignal(false);

  const [mnemonicError, setMnemonicError] = createSignal("");
  const [freeBusyPolicies, setFreeBusyPolicies] = createSignal<Record<string, FreeBusyPolicy>>(
    loadFreeBusyPolicies(),
  );
  const id = identity();
  const canRevealRecoveryPhrase = createMemo(() => tier() !== "cloud");

  function getPeerPolicy(peerId: string): FreeBusyPolicy {
    return freeBusyPolicies()[peerId] ?? "partial";
  }

  function setPeerPolicy(peerId: string, policy: FreeBusyPolicy) {
    const updated = { ...freeBusyPolicies(), [peerId]: policy };
    setFreeBusyPolicies(updated);
    saveFreeBusyPolicies(updated);
  }

  const hasPeers = createMemo(() => peers.length > 0);

  const copyFullId = () => {
    const nid = nodeId();
    if (!nid) return;
    navigator.clipboard.writeText(nid).then(() => {
      setIdCopied(true);
      setTimeout(() => setIdCopied(false), 2000);
    }).catch(() => {
      /* Clipboard unavailable */
    });
  };

  function startEditName() {
    setEditNameValue(displayName());
    setEditingName(true);
  }

  function saveNameEdit() {
    const name = editNameValue().trim();
    saveDisplayName(name);
    setDisplayName(name);
    setEditingName(false);
  }

  function cancelEditName() {
    setEditingName(false);
  }

  async function loadMnemonic() {
    if (!canRevealRecoveryPhrase()) {
      setMnemonicError("Recovery phrase export is unavailable in hosted mode.");
      return;
    }
    setMnemonicLoading(true);
    setMnemonicError("");
    try {
      const res = await api.mnemonic();
      setMnemonicWords(res.mnemonic.split(" "));
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load mnemonic";
      setMnemonicError(msg);
    } finally {
      setMnemonicLoading(false);
    }
  }

  function toggleMnemonic() {
    if (mnemonicVisible()) {
      setMnemonicVisible(false);
      setMnemonicWords([]);
    } else {
      setMnemonicVisible(true);
      loadMnemonic();
    }
  }

  return (
    <div class="page content-max">
      <div class="page-header">
        <h2 class="page-title">Settings</h2>
      </div>

      <HostingBanner />

      {/* Node Identity Card — prominent display */}
      <Show when={id}>
        <div class="card mb-16">
          <div class="settings-identity-hero">
            <div class="node-id-avatar" style={{ width: "56px", height: "56px", "font-size": "18px" }}>
              {displayName().trim().length >= 2
                ? displayName().trim().slice(0, 2).toUpperCase()
                : (nodeId() || "??").slice(0, 2).toUpperCase()}
            </div>
            <div class="settings-identity-info">
              <Show when={!editingName()}>
                <div class="settings-identity-name">
                  <Show when={displayName().trim()} fallback={
                    <span class="text-muted text-sm">No display name set</span>
                  }>
                    <span style={{ "font-size": "16px", "font-weight": "600" }}>
                      {displayName()}
                    </span>
                  </Show>
                  <button class="btn btn-ghost btn-sm" onClick={startEditName} aria-label="Edit display name">
                    <IconPencil size={14} />
                  </button>
                </div>
              </Show>
              <Show when={editingName()}>
                <div class="settings-identity-name">
                  <input
                    type="text"
                    class="form-input"
                    value={editNameValue()}
                    onInput={(e) => setEditNameValue(e.currentTarget.value)}
                    onKeyDown={(e) => { if (e.key === "Enter") saveNameEdit(); if (e.key === "Escape") cancelEditName(); }}
                    placeholder="Enter display name"
                    maxLength={64}
                    autofocus
                    style={{ "max-width": "200px", "font-size": "14px" }}
                  />
                  <button class="btn btn-ghost btn-sm" onClick={saveNameEdit} aria-label="Save display name">
                    <IconCheck size={14} />
                  </button>
                </div>
              </Show>
              <div class="settings-identity-name mt-4">
                <span class="mono text-sm text-secondary">
                  {truncateId(nodeId() || "")}
                </span>
                <button class="btn btn-ghost btn-sm" onClick={copyFullId} aria-label="Copy full Node ID">
                  {idCopied() ? "Copied!" : "Copy"}
                </button>
              </div>
              <div class="flex gap-6 mt-6 flex-wrap">
                <span class={`badge ${tier() === "cloud" ? "badge-warning" : tier() === "full" ? "badge-accent" : "badge-success"}`}>
                  {tierInfo(tier()).label}
                </span>
                <Show when={health()?.lightning_available}>
                  <span class="badge badge-success">Lightning Active</span>
                </Show>
                <Show when={(health()?.connected_peers ?? 0) > 0}>
                  <span class="badge badge-info">{health()!.connected_peers} Peers</span>
                </Show>
              </div>
            </div>
          </div>

          <div class="divider" />

          <div class="settings-identity-warning">
            <span><IconLightbulb size={18} /></span>
            <span>Your identity is derived from your mnemonic phrase. Keep your backup safe — it's the only way to recover this node.</span>
          </div>
        </div>
      </Show>

      {/* Node Status */}
      <div class="card mb-16">
        <div class="card-header">Node Status</div>
        <Show
          when={health()}
          fallback={
            <div class="skeleton" style={{ height: "60px" }} />
          }
        >
          {(h) => (
            <div class="stat-grid">
              <div class="stat-item">
                <div class="stat-label">Status</div>
                <div><span class="badge badge-success">{h().status}</span></div>
              </div>
              <div class="stat-item">
                <div class="stat-label">Protocol</div>
                <div class="stat-value">v{h().version}</div>
              </div>
              <div class="stat-item">
                <div class="stat-label">Peers</div>
                <div class="stat-value">{h().connected_peers}</div>
              </div>
              <div class="stat-item">
                <div class="stat-label">Lightning</div>
                <div>
                  <span class={`badge ${h().lightning_payment_capable ? "badge-success" : h().lightning_available ? "badge-warning" : "badge-error"}`}>
                    {h().lightning_payment_capable ? "Available" : h().lightning_available ? "Receive Only" : "Unavailable"}
                  </span>
                </div>
              </div>
              <div class="stat-item">
                <div class="stat-label">WebSocket</div>
                <div>
                  <span class={`badge ${
                    wsStatus() === "connected"
                      ? "badge-success"
                      : wsStatus() === "connecting"
                        ? "badge-warning"
                        : "badge-error"
                  }`}>
                    {wsStatus()}
                  </span>
                </div>
              </div>
            </div>
          )}
        </Show>
      </div>

      {/* Sovereignty Tier */}
      <div class="card mb-16">
        <div class="card-header">
          <IconShield size={16} />
          <span style={{ "margin-left": "8px" }}>Sovereignty Tier</span>
        </div>
        <p class="form-hint mb-8">
          Your sovereignty level determines where your data lives and who controls your Lightning wallet.
        </p>
        <div class="tier-selector-grid">
          <For each={TIER_CARDS}>
            {(tc) => {
              const info = () => tierInfo(tc.id);
              const TierIcon = tc.icon;
              const isActive = () => tier() === tc.id;
              return (
                <button
                  class={`tier-card ${isActive() ? "tier-card-active" : ""}`}
                  onClick={() => setTier(tc.id)}
                  aria-label={`Select ${info().label} tier`}
                  style={{ "border-color": isActive() ? tc.accent : "transparent" }}
                >
                  <div class="tier-card-icon" style={{ color: tc.accent }}>
                    <TierIcon size={20} />
                  </div>
                  <div class="tier-card-label">{info().label}</div>
                  <div class="tier-card-desc">{info().desc}</div>
                  <Show when={isActive()}>
                    <div class="tier-card-check"><IconCheck size={14} /></div>
                  </Show>
                </button>
              );
            }}
          </For>
        </div>
        <Show when={tier() === "cloud"}>
          <div class="settings-identity-warning mt-8">
            <span><IconWarning size={16} /></span>
            <span class="text-sm">Cloud mode stores data on a hosted server. For full sovereignty, upgrade to Light or Full Node.</span>
          </div>
        </Show>
      </div>

      {/* Mnemonic Backup */}
      <Show
        when={canRevealRecoveryPhrase()}
        fallback={
          <div class="card mb-16">
            <div class="card-header">
              <IconKey size={16} />
              <span style={{ "margin-left": "8px" }}>Recovery Phrase</span>
            </div>
            <p class="form-hint mb-8">
              Recovery phrase export is unavailable in hosted mode.
            </p>
            <div class="settings-identity-warning">
              <span><IconWarning size={16} /></span>
              <span class="text-sm">Hosted nodes must not expose mnemonic export through the web interface.</span>
            </div>
          </div>
        }
      >
        <div class="card mb-16">
          <div class="card-header">
            <IconKey size={16} />
            <span style={{ "margin-left": "8px" }}>Recovery Phrase</span>
          </div>
          <p class="form-hint mb-8">
            Your 24-word recovery phrase is the master key to your identity. Write it down and store it securely offline.
          </p>
          <Show when={!mnemonicVisible()}>
            <button
              class="btn btn-secondary"
              onClick={toggleMnemonic}
              aria-label="Show recovery phrase"
            >
              <IconEye size={14} />
              <span style={{ "margin-left": "6px" }}>Reveal Recovery Phrase</span>
            </button>
          </Show>
          <Show when={mnemonicVisible()}>
            <Show when={mnemonicLoading()}>
              <div class="skeleton" style={{ height: "120px" }} />
            </Show>
            <Show when={mnemonicError()}>
              <div class="settings-identity-warning">
                <span><IconWarning size={16} /></span>
                <span class="text-sm text-warning">{mnemonicError()}</span>
              </div>
            </Show>
            <Show when={mnemonicWords().length > 0}>
              <div class="mnemonic-grid-settings">
                <For each={mnemonicWords()}>
                  {(word, i) => (
                    <div class="mnemonic-word-cell">
                      <span class="mnemonic-word-num">{i() + 1}</span>
                      <span class="mnemonic-word-text">{word}</span>
                    </div>
                  )}
                </For>
              </div>
              <div class="settings-identity-warning mt-8">
                <span><IconWarning size={16} /></span>
                <span class="text-sm text-warning">Never share your recovery phrase. Anyone with these words controls your identity and funds.</span>
              </div>
            </Show>
            <button
              class="btn btn-ghost mt-8"
              onClick={toggleMnemonic}
              aria-label="Hide recovery phrase"
            >
              Hide
            </button>
          </Show>
        </div>
      </Show>

      {/* Notifications */}
      <div class="card mb-16">
        <div class="card-header">
          {notifSettings().enabled ? <IconBell size={16} /> : <IconBellOff size={16} />}
          <span style={{ "margin-left": "8px" }}>Notifications</span>
        </div>
        <div class="notif-setting-row">
          <label class="form-label" for="notif-master">Desktop Notifications</label>
          <label class="toggle-switch">
            <input
              id="notif-master"
              type="checkbox"
              checked={notifSettings().enabled}
              onChange={(e) => toggleNotifications(e.currentTarget.checked)}
            />
            <span class="toggle-slider" />
          </label>
        </div>
        <Show when={notifPermission() === "denied"}>
          <p class="form-hint text-warning">
            Notifications are blocked by your browser. Allow them in your browser settings to enable desktop alerts.
          </p>
        </Show>
        <Show when={notifSettings().enabled}>
          <div class="divider" />
          <div class="notif-setting-row">
            <label class="form-label" for="notif-messages">New messages</label>
            <label class="toggle-switch">
              <input
                id="notif-messages"
                type="checkbox"
                checked={notifSettings().messages}
                onChange={(e) => updateNotifSettings({ messages: e.currentTarget.checked })}
              />
              <span class="toggle-slider" />
            </label>
          </div>
          <div class="notif-setting-row">
            <label class="form-label" for="notif-peers">Peer events</label>
            <label class="toggle-switch">
              <input
                id="notif-peers"
                type="checkbox"
                checked={notifSettings().peerEvents}
                onChange={(e) => updateNotifSettings({ peerEvents: e.currentTarget.checked })}
              />
              <span class="toggle-slider" />
            </label>
          </div>
          <div class="notif-setting-row">
            <label class="form-label" for="notif-payments">Payment confirmations</label>
            <label class="toggle-switch">
              <input
                id="notif-payments"
                type="checkbox"
                checked={notifSettings().payments}
                onChange={(e) => updateNotifSettings({ payments: e.currentTarget.checked })}
              />
              <span class="toggle-slider" />
            </label>
          </div>
        </Show>
      </div>

      {/* Message Retention */}
      <div class="card mb-16">
        <div class="card-header">
          <IconClock size={16} />
          <span style={{ "margin-left": "8px" }}>Message Retention</span>
        </div>
        <p class="form-hint mb-8">
          Choose how long messages are stored on this node. Deleted messages cannot be recovered.
        </p>
        <div class="retention-selector">
          <For each={RETENTION_OPTIONS}>
            {(opt) => (
              <button
                class={`retention-option ${retentionDays() === opt.value ? "active" : ""}`}
                onClick={() => {
                  setRetentionDays(opt.value);
                  saveString("konsensus_retention_days", String(opt.value));
                }}
                aria-label={`Set retention to ${opt.label}`}
              >
                {opt.label}
              </button>
            )}
          </For>
        </div>
        <Show when={retentionDays() > 0}>
          <p class="form-hint mt-8 text-warning">
            Messages older than {retentionDays()} {retentionDays() === 1 ? "day" : "days"} will be automatically deleted.
          </p>
        </Show>
      </div>

      {/* Key Details */}
      <div class="card mb-16">
        <div class="card-header">Cryptographic Keys</div>
        <Show when={id}>
          <CopyableField label="Node ID (Ed25519)" value={id!.node_id} />
          <CopyableField label="X25519 Public Key" value={id!.x25519_public} />
          <CopyableField label="secp256k1 Public Key" value={id!.secp256k1_public} />
        </Show>
        <Show when={!id}>
          <span class="text-muted">Not authenticated</span>
        </Show>
      </div>

      {/* Free/Busy Sharing Policy */}
      <div class="card mb-16">
        <div class="card-header">
          <IconClock size={14} style={{ "vertical-align": "middle", "margin-right": "6px" }} />
          Calendar Availability Sharing
        </div>
        <p class="form-hint">
          Controls what peers can learn about your calendar availability when they check
          your free/busy status. Per-peer overrides take effect when the feature is active.
        </p>
        <Show
          when={hasPeers()}
          fallback={
            <p class="text-sm text-muted" style={{ "font-style": "italic" }}>
              No peers yet. Add peers to configure per-peer policies.
            </p>
          }
        >
          <div style={{ display: "flex", "flex-direction": "column", gap: "8px" }}>
            <For each={peers}>
              {(peer) => (
                <div style={{ display: "flex", "align-items": "center", gap: "12px" }}>
                  <div style={{ flex: 1, "min-width": 0 }}>
                    <div class="text-sm" style={{ "font-weight": 500 }}>
                      {peer.label ?? "Unnamed peer"}
                    </div>
                    <div class="text-xs text-muted mono">
                      {peer.node_id.slice(0, 20)}…
                    </div>
                  </div>
                  <select
                    class="input"
                    style={{ width: "200px", "flex-shrink": 0, "font-size": "13px" }}
                    value={getPeerPolicy(peer.node_id)}
                    onChange={(e) =>
                      setPeerPolicy(peer.node_id, e.currentTarget.value as FreeBusyPolicy)
                    }
                    aria-label={`Free/busy policy for ${peer.label ?? peer.node_id}`}
                  >
                    <For each={Object.entries(FREEBUSY_POLICY_LABELS) as [FreeBusyPolicy, string][]}>
                      {([value, label]) => (
                        <option value={value}>{label}</option>
                      )}
                    </For>
                  </select>
                </div>
              )}
            </For>
          </div>
        </Show>
      </div>

      {/* Reaction Preferences */}
      <div class="card mb-16">
        <div class="card-header">Reaction Preferences</div>
        <p class="form-hint">
          Hide emoji reactions on messages from specific peers. When enabled, the
          reaction strip will not be shown for that peer's messages.
        </p>
        <Show
          when={hasPeers()}
          fallback={
            <p class="text-sm text-muted" style={{ "font-style": "italic" }}>
              No peers yet. Add peers to configure reaction preferences.
            </p>
          }
        >
          <div style={{ display: "flex", "flex-direction": "column", gap: "8px" }}>
            <For each={peers}>
              {(peer) => (
                <div style={{ display: "flex", "align-items": "center", gap: "12px" }}>
                  <div style={{ flex: 1, "min-width": 0 }}>
                    <div class="text-sm" style={{ "font-weight": 500 }}>
                      {peer.label ?? "Unnamed peer"}
                    </div>
                    <div class="text-xs text-muted mono">
                      {peer.node_id.slice(0, 20)}…
                    </div>
                  </div>
                  <label
                    style={{ display: "flex", "align-items": "center", gap: "8px", cursor: "pointer" }}
                    aria-label={`Hide reactions from ${peer.label ?? peer.node_id}`}
                  >
                    <input
                      type="checkbox"
                      checked={getHideReactions(peer.node_id)}
                      onChange={(e) => setHideReactions(peer.node_id, e.currentTarget.checked)}
                    />
                    <span class="text-sm">Hide reactions</span>
                  </label>
                </div>
              )}
            </For>
          </div>
        </Show>
      </div>

      {/* Connection */}
      <div class="card mb-16">
        <div class="card-header">Connection</div>
        <CopyableField label="Node URL" value={getNodeUrl()} />
        <p class="form-hint">
          Change via Advanced options on the login screen. Connect to a remote node via SSH tunnel:
          <code class="mono text-secondary"> ssh -L 3141:127.0.0.1:3141 user@remote-node</code>
        </p>
      </div>

      {/* About */}
      <div class="card">
        <div class="card-header">About</div>
        <p class="text-sm text-secondary leading-loose">
          BitSov is a sovereign mesh network where every user is a node
          with Bitcoin-anchored identity, payment-gated communication, and true
          data sovereignty.
        </p>
        <div class="divider" />
        <div class="stat-grid">
          <div class="stat-item">
            <div class="stat-label">Protocol</div>
            <div class="text-sm">v2</div>
          </div>
          <div class="stat-item">
            <div class="stat-label">Transport</div>
            <div class="text-sm">Noise_XX + ChaCha20</div>
          </div>
          <div class="stat-item">
            <div class="stat-label">E2EE (1:1)</div>
            <div class="text-sm">X3DH + Double Ratchet</div>
          </div>
          <div class="stat-item">
            <div class="stat-label">E2EE (Group)</div>
            <div class="text-sm">Sender Keys</div>
          </div>
          <div class="stat-item">
            <div class="stat-label">Payment Gate</div>
            <div class="text-sm">Lightning preimage</div>
          </div>
          <div class="stat-item">
            <div class="stat-label">Gate Mode</div>
            <div class="text-sm">Fail-closed</div>
          </div>
        </div>
      </div>
    </div>
  );
}
