/**
 * Profile — user identity, display name, status, and peer profiles.
 * Stores profile data in localStorage until backend profile storage exists.
 */

import { createSignal, createMemo, Show, For, onMount } from "solid-js";
import qrcode from "qrcode-generator";
import { nodeId, api } from "../stores/auth";
import { peers } from "../stores/peers";
import { tier, tierInfo } from "../stores/tier";
import { toast } from "../stores/toast";
import { loadJSON, saveJSON, loadString, saveString } from "../utils/storage";
import {
  IconProfile,
  IconCopy,
  IconCheck,
  IconKey,
  IconShield,
  IconPeers,
  IconLightning,
  IconWarning,
  IconPencil,
  IconSend,
} from "./Icons";

/** Generate an SVG QR code from a string. */
function generateQrSvg(data: string): string {
  const qr = qrcode(0, "M");
  qr.addData(data);
  qr.make();
  return qr.createSvgTag({ cellSize: 3, margin: 2, scalable: true });
}

/** Generate a human-readable node alias: label + 6-char checksum. */
function nodeAlias(nodeIdHex: string, displayName?: string): string {
  const label = displayName?.trim() || "node";
  const checksum = nodeIdHex.slice(0, 6);
  return `${label}-${checksum}`;
}

// ─── Types ────────────────────────────────────────────────

interface UserProfile {
  displayName: string;
  title: string;
  bio: string;
  status: "online" | "idle" | "dnd" | "invisible";
  x_handle?: string;
  x_url?: string;
  avatarDataUrl?: string;
}

const STATUS_OPTIONS: Array<{ value: UserProfile["status"]; label: string; color: string }> = [
  { value: "online", label: "Online", color: "#34d399" },
  { value: "idle", label: "Idle", color: "#fbbf24" },
  { value: "dnd", label: "Do Not Disturb", color: "#ef4444" },
  { value: "invisible", label: "Invisible", color: "#6b7280" },
];

const PROFILE_KEY = "konsensus_user_profile";
const MNEMONIC_BACKED_UP_KEY = "konsensus_mnemonic_backed_up";

function loadProfile(): UserProfile {
  return loadJSON<UserProfile>(PROFILE_KEY, {
    displayName: "",
    title: "",
    bio: "",
    status: "online",
  });
}

function saveProfile(profile: UserProfile) {
  saveJSON(PROFILE_KEY, profile);
}

function generateAvatarColors(id: string): [string, string] {
  let hash = 0;
  for (let i = 0; i < id.length; i++) {
    hash = id.charCodeAt(i) + ((hash << 5) - hash);
  }
  const h1 = Math.abs(hash) % 360;
  const h2 = (h1 + 40) % 360;
  return [`hsl(${h1}, 70%, 50%)`, `hsl(${h2}, 70%, 40%)`];
}

// ─── Component ────────────────────────────────────────────

export default function ProfileView() {
  const [profile, setProfile] = createSignal<UserProfile>(loadProfile());
  const [editing, setEditing] = createSignal(false);
  const [editName, setEditName] = createSignal("");
  const [editTitle, setEditTitle] = createSignal("");
  const [editBio, setEditBio] = createSignal("");
  const [editStatus, setEditStatus] = createSignal<UserProfile["status"]>("online");
  const [copied, setCopied] = createSignal(false);
  const [mnemonicBackedUp, setMnemonicBackedUp] = createSignal(
    loadString(MNEMONIC_BACKED_UP_KEY) === "true"
  );
  const [selectedPeer, setSelectedPeer] = createSignal<string | null>(null);

  // Invite generation
  const [inviteAddr, setInviteAddr] = createSignal("");
  const [inviteLabel, setInviteLabel] = createSignal("");
  const [inviteExpiry, setInviteExpiry] = createSignal(0);
  const [inviteToken, setInviteToken] = createSignal("");
  const [inviteUri, setInviteUri] = createSignal("");
  const [inviteLoading, setInviteLoading] = createSignal(false);
  const [inviteCopied, setInviteCopied] = createSignal(false);

  const nid = createMemo(() => nodeId() ?? "");
  const avatarChars = createMemo(() => {
    const name = profile().displayName.trim();
    if (name.length >= 2) return name.slice(0, 2).toUpperCase();
    if (name.length === 1) return name.toUpperCase();
    const id = nid();
    return id.length >= 2 ? id.slice(0, 2).toUpperCase() : "??";
  });
  const avatarColors = createMemo(() => generateAvatarColors(nid()));

  function startEditing() {
    const p = profile();
    setEditName(p.displayName);
    setEditTitle(p.title);
    setEditBio(p.bio);
    setEditStatus(p.status);
    setEditing(true);
  }

  function saveEdits() {
    const prev = profile();
    const updated: UserProfile = {
      displayName: editName().trim(),
      title: editTitle().trim(),
      bio: editBio().trim(),
      status: editStatus(),
      x_handle: prev.x_handle,
      x_url: prev.x_url,
      avatarDataUrl: prev.avatarDataUrl,
    };
    saveProfile(updated);
    setProfile(updated);
    setEditing(false);
  }

  function updateStatus(status: UserProfile["status"]) {
    const updated = { ...profile(), status };
    saveProfile(updated);
    setProfile(updated);
  }

  async function copyNodeId() {
    try {
      await navigator.clipboard.writeText(nid());
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch { /* clipboard not available */ }
  }

  async function generateInvite() {
    const addr = inviteAddr().trim();
    if (!addr) {
      toast.error("Enter your node's network address");
      return;
    }
    setInviteLoading(true);
    try {
      const result = await api.generateInvite(
        addr,
        inviteLabel().trim() || undefined,
        inviteExpiry() || undefined,
      );
      setInviteToken(result.token);
      setInviteUri(result.uri);
      toast.success("Invite link generated");
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to generate invite";
      toast.error(msg);
    } finally {
      setInviteLoading(false);
    }
  }

  async function copyInvite() {
    try {
      await navigator.clipboard.writeText(inviteUri() || inviteToken());
      setInviteCopied(true);
      setTimeout(() => setInviteCopied(false), 2000);
      toast.success("Invite copied to clipboard");
    } catch { /* clipboard not available */ }
  }

  function markMnemonicBackedUp() {
    saveString(MNEMONIC_BACKED_UP_KEY, "true");
    setMnemonicBackedUp(true);
  }

  const statusInfo = createMemo(() =>
    STATUS_OPTIONS.find((s) => s.value === profile().status) ?? STATUS_OPTIONS[0]
  );

  return (
    <div class="page content-max">
      <div class="page-header">
        <h2 class="page-title">Profile</h2>
        <span class="text-xs text-muted">Your identity on the mesh</span>
      </div>

      {/* Profile hero card */}
      <div class="card profile-hero">
        <div class="profile-hero-inner">
          {/* Avatar */}
          <div
            class="profile-avatar"
            style={
              profile().avatarDataUrl
                ? { "background-image": `url(${profile().avatarDataUrl})`, "background-size": "cover", "background-position": "center" }
                : { background: `linear-gradient(135deg, ${avatarColors()[0]}, ${avatarColors()[1]})` }
            }
          >
            <Show when={!profile().avatarDataUrl}>
              <span class="profile-avatar-text">{avatarChars()}</span>
            </Show>
            <span
              class="profile-status-indicator"
              style={{ background: statusInfo().color }}
              title={statusInfo().label}
            />
          </div>

          {/* Info */}
          <div class="profile-info">
            <Show when={!editing()}>
              <div class="flex items-center gap-8">
                <h3 class="text-lg font-bold">
                  {profile().displayName || "Anonymous Node"}
                </h3>
                <button class="profile-edit-btn" onClick={startEditing} title="Edit profile" aria-label="Edit profile">
                  <IconPencil size={14} />
                </button>
              </div>
              <Show when={profile().title}>
                <div class="text-sm text-secondary">{profile().title}</div>
              </Show>
              <Show when={profile().bio}>
                <div class="text-sm text-muted mt-4 leading-relaxed">
                  {profile().bio}
                </div>
              </Show>
              <Show when={profile().x_handle}>
                <div class="text-xs text-muted mt-4">
                  <a
                    href={profile().x_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    class="profile-x-link"
                  >
                    @{profile().x_handle} on X
                  </a>
                </div>
              </Show>

              {/* Status selector */}
              <div class="profile-status-row">
                <For each={STATUS_OPTIONS}>
                  {(opt) => (
                    <button
                      class={`profile-status-btn ${profile().status === opt.value ? "active" : ""}`}
                      onClick={() => updateStatus(opt.value)}
                      title={opt.label}
                    >
                      <span class="profile-status-dot" style={{ background: opt.color }} />
                      <span class="text-xs">{opt.label}</span>
                    </button>
                  )}
                </For>
              </div>
            </Show>

            {/* Edit mode */}
            <Show when={editing()}>
              <div class="profile-edit-form">
                <div class="form-group">
                  <label class="form-label">Display Name</label>
                  <input
                    class="input"
                    type="text"
                    placeholder="Your name"
                    value={editName()}
                    onInput={(e) => setEditName(e.currentTarget.value)}
                    maxLength={64}
                  />
                </div>
                <div class="form-group">
                  <label class="form-label">Title / Role</label>
                  <input
                    class="input"
                    type="text"
                    placeholder="e.g., Developer, Doctor, Node Operator"
                    value={editTitle()}
                    onInput={(e) => setEditTitle(e.currentTarget.value)}
                    maxLength={128}
                  />
                </div>
                <div class="form-group">
                  <label class="form-label">Bio</label>
                  <textarea
                    class="input resize-vertical"
                    placeholder="A short bio..."
                    rows={3}
                    value={editBio()}
                    onInput={(e) => setEditBio(e.currentTarget.value)}
                    maxLength={500}
                  />
                </div>
                <div class="form-group">
                  <label class="form-label">Status</label>
                  <div class="profile-status-row">
                    <For each={STATUS_OPTIONS}>
                      {(opt) => (
                        <button
                          class={`profile-status-btn ${editStatus() === opt.value ? "active" : ""}`}
                          onClick={() => setEditStatus(opt.value)}
                        >
                          <span class="profile-status-dot" style={{ background: opt.color }} />
                          <span class="text-xs">{opt.label}</span>
                        </button>
                      )}
                    </For>
                  </div>
                </div>
                <div class="flex gap-8">
                  <button class="btn btn-primary btn-sm" onClick={saveEdits}>Save</button>
                  <button class="btn btn-ghost btn-sm" onClick={() => setEditing(false)}>Cancel</button>
                </div>
              </div>
            </Show>
          </div>
        </div>
      </div>

      <div class="profile-grid">
        {/* Node Identity */}
        <div class="card">
          <div class="card-header icon-text-sm">
            <IconKey size={14} /> Node Identity
          </div>
          <div class="profile-identity-section">
            <div class="profile-field">
              <div class="text-xs text-muted">Node Alias</div>
              <div class="text-sm font-medium">{nodeAlias(nid(), profile().displayName)}</div>
            </div>
            <div class="profile-field">
              <div class="text-xs text-muted">Node ID (Public Key)</div>
              <div
                class="profile-copyable mono text-sm"
                onClick={copyNodeId}
                title="Click to copy"
              >
                <span class="truncate flex-1">{nid()}</span>
                {copied() ? <IconCheck size={12} /> : <IconCopy size={12} />}
              </div>
            </div>
            <div class="profile-field">
              <div class="text-xs text-muted">Sovereignty Tier</div>
              <div class="text-sm">
                <span class={`badge ${tier() === "full" ? "badge-success" : tier() === "light" ? "badge-info" : "badge-warning"}`}>
                  {tierInfo(tier()).label} — {tierInfo(tier()).sovereignty}
                </span>
              </div>
            </div>

            {/* QR Code — scannable Node ID for peer sharing */}
            <Show when={nid()}>
              <div class="profile-qr-section">
                <div class="text-xs text-muted mb-8">Share via QR Code</div>
                <div class="profile-qr-code" innerHTML={generateQrSvg(nid())} />
                <div class="text-xs text-muted mt-4 text-center">
                  Scan to add this node as a peer
                </div>
              </div>
            </Show>
          </div>
        </div>

        {/* Invite Link Generator */}
        <div class="card">
          <div class="card-header icon-text-sm">
            <IconSend size={14} /> Share Invite Link
          </div>
          <div class="text-xs text-muted mb-12 leading-relaxed">
            Generate a signed invite link. Recipients can redeem it to auto-add
            your node as a peer — no manual ID copying needed.
          </div>

          <Show when={!inviteToken()} fallback={
            <div class="profile-identity-section">
              {/* Generated invite */}
              <div class="profile-field">
                <div class="text-xs text-muted">Invite URI</div>
                <div
                  class="profile-copyable mono text-xs break-all"
                  onClick={copyInvite}
                  title="Click to copy"
                >
                  <span class="flex-1 leading-relaxed">{inviteUri()}</span>
                  {inviteCopied() ? <IconCheck size={12} /> : <IconCopy size={12} />}
                </div>
              </div>

              {/* QR for invite */}
              <div class="profile-qr-section">
                <div class="text-xs text-muted mb-8">Invite QR Code</div>
                <div class="profile-qr-code" innerHTML={generateQrSvg(inviteUri())} />
                <div class="text-xs text-muted mt-4 text-center">
                  Recipient scans this to add you as a peer
                </div>
              </div>

              <button
                class="btn btn-secondary btn-sm mt-8"
                onClick={() => { setInviteToken(""); setInviteUri(""); }}
              >
                Generate New
              </button>
            </div>
          }>
            {/* Generate form */}
            <div class="profile-identity-section">
              <div class="form-group mb-8">
                <label class="form-label">Your Network Address</label>
                <input
                  class="input w-full"
                  type="text"
                  placeholder="host:port (e.g., node.example:9735)"
                  value={inviteAddr()}
                  onInput={(e) => setInviteAddr(e.currentTarget.value)}
                />
                <div class="text-xs text-muted mt-4">
                  The address other nodes use to reach you
                </div>
              </div>
              <div class="form-group mb-8">
                <label class="form-label">Label (optional)</label>
                <input
                  class="input w-full"
                  type="text"
                  placeholder="e.g., Alice's Node"
                  value={inviteLabel()}
                  onInput={(e) => setInviteLabel(e.currentTarget.value)}
                  maxLength={255}
                />
              </div>
              <div class="form-group mb-8">
                <label class="form-label">Expires</label>
                <select
                  class="input w-full"
                  value={inviteExpiry()}
                  onChange={(e) => setInviteExpiry(Number(e.currentTarget.value))}
                >
                  <option value={0}>Never</option>
                  <option value={3600}>1 hour</option>
                  <option value={86400}>24 hours</option>
                  <option value={604800}>7 days</option>
                  <option value={2592000}>30 days</option>
                </select>
              </div>
              <button
                class="btn btn-primary btn-sm"
                onClick={generateInvite}
                disabled={inviteLoading() || !inviteAddr().trim()}
              >
                {inviteLoading() ? "Generating..." : "Generate Invite"}
              </button>
            </div>
          </Show>
        </div>

        {/* Mnemonic Backup */}
        <div class="card">
          <div class="card-header icon-text-sm">
            <IconShield size={14} /> Security
          </div>
          <Show when={!mnemonicBackedUp()} fallback={
            <div class="flex items-center gap-8 py-12">
              <span class="text-success"><IconCheck size={16} /></span>
              <span class="text-sm">Mnemonic phrase backed up</span>
            </div>
          }>
            <div class="profile-backup-warning">
              <div class="flex items-center gap-8 mb-8">
                <span class="text-warning"><IconWarning size={16} /></span>
                <span class="text-sm font-medium">Mnemonic not backed up</span>
              </div>
              <p class="text-xs text-secondary leading-relaxed mb-12">
                Your mnemonic phrase is the only way to recover your identity.
                Write it down and store it in a secure location. Without it, your
                node identity, keys, and all E2EE sessions are irrecoverable.
              </p>
              <button class="btn btn-secondary btn-sm" onClick={markMnemonicBackedUp}>
                I have backed up my mnemonic
              </button>
            </div>
          </Show>
        </div>
      </div>

      {/* Peer Profiles */}
      <div class="card mt-16">
        <div class="card-header icon-text-sm">
          <IconPeers size={14} /> Peer Profiles
        </div>
        <Show when={peers.length > 0} fallback={
          <div class="text-sm text-muted text-center py-16">
            No peers whitelisted yet
          </div>
        }>
          <div class="profile-peer-list">
            <For each={peers}>
              {(peer) => {
                const peerColors = generateAvatarColors(peer.node_id);
                const peerChars = () => {
                  if (peer.label && peer.label.length >= 2) return peer.label.slice(0, 2).toUpperCase();
                  return peer.node_id.slice(0, 2).toUpperCase();
                };
                const isSelected = () => selectedPeer() === peer.node_id;
                return (
                  <div>
                    <button
                      class={`profile-peer-item ${isSelected() ? "active" : ""}`}
                      onClick={() => setSelectedPeer(isSelected() ? null : peer.node_id)}
                    >
                      <div
                        class="profile-peer-avatar"
                        style={{ background: `linear-gradient(135deg, ${peerColors[0]}, ${peerColors[1]})` }}
                      >
                        {peerChars()}
                      </div>
                      <div class="flex-1 min-w-0">
                        <div class="text-sm font-medium truncate">{peer.label ?? peer.node_id.slice(0, 16) + "..."}</div>
                        <div class="text-xs text-muted">{peer.addr ?? "No address"}</div>
                      </div>
                      <Show when={peer.fingerprint}>
                        <span class="mono text-xs text-muted" style={{ "margin-right": "8px" }}>{peer.fingerprint}</span>
                      </Show>
                      <span class={`status-dot ${peer.connected ? "status-dot-online" : "status-dot-offline"}`} />
                    </button>
                    <Show when={isSelected()}>
                      <div class="profile-peer-detail">
                        <div class="profile-field">
                          <div class="text-xs text-muted">Node ID</div>
                          <div class="mono text-xs break-all leading-relaxed">
                            {peer.node_id}
                          </div>
                        </div>
                        <Show when={peer.addr}>
                          <div class="profile-field">
                            <div class="text-xs text-muted">Address</div>
                            <div class="text-sm">{peer.addr}</div>
                          </div>
                        </Show>
                        <div class="profile-field">
                          <div class="text-xs text-muted">Connection</div>
                          <span class={`badge ${peer.connected ? "badge-success" : "badge-muted"}`}>
                            {peer.connected ? "Connected" : "Offline"}
                          </span>
                        </div>
                        <Show when={peer.fingerprint}>
                          <div class="profile-field">
                            <div class="text-xs text-muted">Fingerprint</div>
                            <div class="mono text-xs">{peer.fingerprint}</div>
                          </div>
                        </Show>
                        <Show when={peer.safety_number}>
                          <div class="profile-field">
                            <div class="text-xs text-muted">Safety Number</div>
                            <div class="mono text-xs leading-relaxed" style={{ "letter-spacing": "0.5px" }}>
                              {peer.safety_number}
                            </div>
                            <div class="text-xs text-muted mt-4">
                              Compare this with your peer to verify identity
                            </div>
                          </div>
                        </Show>
                      </div>
                    </Show>
                  </div>
                );
              }}
            </For>
          </div>
        </Show>
      </div>
    </div>
  );
}
