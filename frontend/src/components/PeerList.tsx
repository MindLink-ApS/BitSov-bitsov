/** Peer management view — glass cards with status indicators. */

import { createSignal, For, Show, onMount } from "solid-js";
import {
  peers,
  loadingPeers,
  peersError,
  refreshPeers,
  addPeer,
  updatePeer,
  removePeer,
  connectPeer,
  exportPeers,
  importPeers,
} from "../stores/peers";
import { toast } from "../stores/toast";
import { api } from "../stores/auth";
import type { PeerBackup } from "../api/types";
import { IconNetwork, IconLock, IconCheck } from "./Icons";
import PeerRow from "./PeerRow";

export default function PeerList() {
  const [showAdd, setShowAdd] = createSignal(false);
  const [newNodeId, setNewNodeId] = createSignal("");
  const [newAddr, setNewAddr] = createSignal("");
  const [newLabel, setNewLabel] = createSignal("");
  const [addError, setAddError] = createSignal<string | null>(null);
  const [actionLoading, setActionLoading] = createSignal<string | null>(null);

  // Edit state
  const [editingId, setEditingId] = createSignal<string | null>(null);
  const [editLabel, setEditLabel] = createSignal("");
  const [editAddr, setEditAddr] = createSignal("");

  // Invite redeem state
  const [showRedeem, setShowRedeem] = createSignal(false);
  const [inviteCode, setInviteCode] = createSignal("");
  const [redeemError, setRedeemError] = createSignal<string | null>(null);
  const [redeemLoading, setRedeemLoading] = createSignal(false);

  // E2EE session state — which peers have active sessions
  const [sessionPeers, setSessionPeers] = createSignal<Set<string>>(new Set());

  async function fetchSessions() {
    try {
      const sessions = await api.listSessions();
      setSessionPeers(new Set(sessions.map((s) => s.peer_id)));
    } catch {
      // sessions fetch may fail silently
    }
  }

  onMount(() => {
    refreshPeers();
    fetchSessions();
  });

  const isValidNodeId = (id: string): boolean => {
    return /^[0-9a-fA-F]{64}$/.test(id);
  };

  const isValidAddr = (addr: string): boolean => {
    return /^.+:\d{1,5}$/.test(addr);
  };

  const nodeIdError = () => {
    const id = newNodeId().trim();
    if (!id) return null;
    if (!/^[0-9a-fA-F]*$/.test(id)) return "Must be hexadecimal characters only";
    if (id.length !== 64) return `${id.length}/64 characters`;
    return null;
  };

  const handleAdd = async (e: Event) => {
    e.preventDefault();
    setAddError(null);
    const id = newNodeId().trim();
    if (!isValidNodeId(id)) {
      setAddError("Node ID must be exactly 64 hex characters");
      return;
    }
    if (!isValidAddr(newAddr().trim())) {
      setAddError("Address must be in host:port format");
      return;
    }
    try {
      await addPeer(id, newAddr().trim(), newLabel().trim() || undefined);
      setNewNodeId("");
      setNewAddr("");
      setNewLabel("");
      setShowAdd(false);
      toast.success("Peer added to whitelist");
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to add peer";
      setAddError(msg);
      toast.error(msg);
    }
  };

  const handleRedeem = async (e: Event) => {
    e.preventDefault();
    setRedeemError(null);
    const code = inviteCode().trim();
    if (!code) {
      setRedeemError("Enter an invite code or URI");
      return;
    }
    setRedeemLoading(true);
    try {
      const result = await api.redeemInvite(code);
      setInviteCode("");
      setShowRedeem(false);
      await refreshPeers();
      await fetchSessions();
      const label = result.label || result.node_id.slice(0, 12) + "...";
      toast.success(`Peer added: ${label}${result.added ? "" : " (already known)"}`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to redeem invite";
      setRedeemError(msg);
      toast.error(msg);
    } finally {
      setRedeemLoading(false);
    }
  };

  const handleDiscover = async (nodeId: string) => {
    setActionLoading(nodeId);
    try {
      await api.discoverPeers(nodeId);
      toast.success("Peer discovery requested — new peers will appear shortly");
      // Refresh after a brief delay to allow exchange response
      setTimeout(() => refreshPeers(), 2000);
    } catch {
      toast.error("Failed to request peer discovery");
    } finally {
      setActionLoading(null);
    }
  };

  const handleConnect = async (nodeId: string) => {
    setActionLoading(nodeId);
    try {
      await connectPeer(nodeId);
      toast.success("Peer connected");
    } catch {
      toast.error("Failed to connect to peer");
    } finally {
      setActionLoading(null);
    }
  };

  const handleRemove = async (nodeId: string) => {
    setActionLoading(nodeId);
    try {
      await removePeer(nodeId);
      toast.info("Peer removed");
    } catch {
      toast.error("Failed to remove peer");
    } finally {
      setActionLoading(null);
    }
  };

  const startEdit = (nodeId: string, label: string | null, addr: string) => {
    setEditingId(nodeId);
    setEditLabel(label ?? "");
    setEditAddr(addr);
  };

  const cancelEdit = () => {
    setEditingId(null);
  };

  let fileInputRef: HTMLInputElement | undefined;

  const handleExport = async () => {
    try {
      await exportPeers();
      toast.success("Contacts exported");
    } catch {
      toast.error("Failed to export contacts");
    }
  };

  const handleImportFile = async (e: Event) => {
    const target = e.target as HTMLInputElement;
    const file = target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const backup = JSON.parse(text) as PeerBackup;
      if (!backup.version || !Array.isArray(backup.peers)) {
        toast.error("Invalid backup file format");
        return;
      }
      const result = await importPeers(backup);
      const parts: string[] = [];
      if (result.imported > 0) parts.push(`${result.imported} imported`);
      if (result.skipped > 0) parts.push(`${result.skipped} skipped`);
      if (result.errors.length > 0) parts.push(`${result.errors.length} errors`);
      toast.success(`Contacts: ${parts.join(", ")}`);
    } catch {
      toast.error("Failed to read backup file");
    } finally {
      target.value = "";
    }
  };

  const handleSaveEdit = async (nodeId: string) => {
    const addr = editAddr().trim();
    if (addr && !isValidAddr(addr)) {
      toast.error("Address must be in host:port format");
      return;
    }
    setActionLoading(nodeId);
    try {
      await updatePeer(nodeId, {
        label: editLabel().trim(),
        ...(addr ? { addr } : {}),
      });
      setEditingId(null);
      toast.success("Peer updated");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to update peer");
    } finally {
      setActionLoading(null);
    }
  };

  return (
    <div class="page content-max">
      {/* Header */}
      <div class="page-header">
        <div>
          <h2 class="page-title">Peers</h2>
          <p class="page-subtitle">
            {peers.filter((p) => p.connected).length} connected / {peers.length} total
          </p>
        </div>
        <div class="flex gap-8">
          <button class="btn btn-secondary btn-sm" onClick={handleExport} aria-label="Export contacts">
            Export
          </button>
          <button class="btn btn-secondary btn-sm" onClick={() => fileInputRef?.click()} aria-label="Import contacts">
            Import
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".json"
            style={{ display: "none" }}
            onChange={handleImportFile}
          />
          <button class="btn btn-secondary btn-sm" onClick={refreshPeers} aria-label="Refresh peer list">
            Refresh
          </button>
          <button
            class="btn btn-secondary btn-sm"
            onClick={() => { setShowRedeem(!showRedeem()); setShowAdd(false); }}
          >
            {showRedeem() ? "Cancel" : "Redeem Invite"}
          </button>
          <button
            class="btn btn-primary btn-sm"
            onClick={() => { setShowAdd(!showAdd()); setShowRedeem(false); }}
          >
            {showAdd() ? "Cancel" : "Add Peer"}
          </button>
        </div>
      </div>

      {/* Redeem invite form */}
      <Show when={showRedeem()}>
        <form onSubmit={handleRedeem} class="card animate-fade-in mb-20">
          <div class="card-header">Redeem Invite</div>
          <div class="text-xs text-muted mb-12 leading-relaxed">
            Paste an invite token or URI (konsensus://invite/...) from another
            node. This will auto-whitelist the inviter and initiate a connection.
          </div>
          <div class="form-group">
            <label class="form-label">Invite Code</label>
            <textarea
              value={inviteCode()}
              onInput={(e) => setInviteCode(e.currentTarget.value)}
              placeholder="Paste invite token or konsensus://invite/... URI"
              class="w-full mono resize-vertical"
              rows={3}
              spellcheck={false}
              autocomplete="off"
            />
          </div>
          <Show when={redeemError()}>
            <div class="alert alert-error mb-12">{redeemError()}</div>
          </Show>
          <button
            type="submit"
            class="btn btn-primary btn-sm"
            disabled={!inviteCode().trim() || redeemLoading()}
          >
            {redeemLoading() ? "Redeeming..." : "Redeem Invite"}
          </button>
        </form>
      </Show>

      {/* Add peer form */}
      <Show when={showAdd()}>
        <form onSubmit={handleAdd} class="card animate-fade-in mb-20">
          <div class="card-header">New Peer</div>
          <div class="grid grid-cols-2 gap-12 mb-12">
            <div class="form-group mb-0">
              <label class="form-label">Node ID (hex)</label>
              <input
                type="text"
                value={newNodeId()}
                onInput={(e) => setNewNodeId(e.currentTarget.value)}
                placeholder="64-character Ed25519 public key..."
                class={`mono w-full ${nodeIdError() ? "input-error" : ""}`}
                maxLength={64}
                spellcheck={false}
                autocomplete="off"
              />
              <Show when={nodeIdError()}>
                <span class="text-xs text-error" style={{ "margin-top": "4px", display: "block" }}>
                  {nodeIdError()}
                </span>
              </Show>
            </div>
            <div class="form-group mb-0">
              <label class="form-label">Address</label>
              <input
                type="text"
                value={newAddr()}
                onInput={(e) => setNewAddr(e.currentTarget.value)}
                placeholder="host:port"
                class="w-full"
              />
            </div>
          </div>
          <div class="form-group">
            <label class="form-label">Label (optional)</label>
            <input
              type="text"
              value={newLabel()}
              onInput={(e) => setNewLabel(e.currentTarget.value)}
              placeholder="e.g., Alice, Office node..."
              class="w-full"
            />
          </div>
          <Show when={addError()}>
            <div class="alert alert-error mb-12">{addError()}</div>
          </Show>
          <button
            type="submit"
            class="btn btn-primary btn-sm"
            disabled={!newNodeId().trim() || !newAddr().trim()}
          >
            Add Peer
          </button>
        </form>
      </Show>

      {/* Error */}
      <Show when={peersError()}>
        <div class="alert alert-error mb-16 flex items-center gap-8">
          <span class="flex-1">{peersError()}</span>
          <button class="btn btn-secondary btn-sm" onClick={refreshPeers}>Retry</button>
        </div>
      </Show>

      {/* Peer list */}
      <Show
        when={!loadingPeers() || peers.length > 0}
        fallback={
          <div class="empty-state">
            <div class="skeleton" style={{ height: "56px", width: "100%", "margin-bottom": "8px" }} />
            <div class="skeleton" style={{ height: "56px", width: "100%" }} />
          </div>
        }
      >
        <For
          each={peers}
          fallback={
            <div class="empty-state">
              <div class="empty-state-icon"><IconNetwork size={32} /></div>
              <div class="empty-state-title">Your mesh is empty</div>
              <div class="empty-state-desc">
                Add your first peer to join the sovereign network. Redeem an
                invite link, or add a peer manually with their Node ID and address.
              </div>
            </div>
          }
        >
          {(peer) => (
            <Show when={editingId() === peer.node_id} fallback={
              <PeerRow
                peer={peer}
                sessionActive={sessionPeers().has(peer.node_id)}
                actionLoading={actionLoading() === peer.node_id}
                onEdit={() => startEdit(peer.node_id, peer.label, peer.addr)}
                onConnect={() => handleConnect(peer.node_id)}
                onDiscover={() => handleDiscover(peer.node_id)}
                onRemove={() => handleRemove(peer.node_id)}
              />
            }>
              {/* Edit mode */}
              <div class="peer-card animate-fade-in">
                <span
                  class={`status-dot mr-12 ${peer.connected ? "status-dot-online" : "status-dot-offline"}`}
                />
                <div class="flex-1 min-w-0">
                  <div class="grid grid-cols-2 gap-8 mb-8">
                    <input
                      type="text"
                      value={editLabel()}
                      onInput={(e) => setEditLabel(e.currentTarget.value)}
                      placeholder="Label (optional)"
                      class="w-full"
                    />
                    <input
                      type="text"
                      value={editAddr()}
                      onInput={(e) => setEditAddr(e.currentTarget.value)}
                      placeholder="host:port"
                      class="w-full"
                    />
                  </div>
                  <div class="mono truncate text-xs text-muted">
                    {peer.node_id}
                  </div>
                </div>
                <div class="flex gap-6 ml-12">
                  <button
                    class="btn btn-primary btn-sm"
                    disabled={actionLoading() === peer.node_id}
                    onClick={() => handleSaveEdit(peer.node_id)}
                  >
                    Save
                  </button>
                  <button
                    class="btn btn-secondary btn-sm"
                    onClick={cancelEdit}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            </Show>
          )}
        </For>
      </Show>
    </div>
  );
}
