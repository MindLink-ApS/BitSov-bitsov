/**
 * Peers store — manages peer list and connection state.
 */

import { createSignal } from "solid-js";
import { createStore, produce } from "solid-js/store";
import type { PeerResponse, PeerBackup } from "../api/types";
import { api } from "./auth";

const [peers, setPeers] = createStore<PeerResponse[]>([]);
const [loadingPeers, setLoadingPeers] = createSignal(false);
const [peersError, setPeersError] = createSignal<string | null>(null);

/** Refresh the peer list from the API. */
export async function refreshPeers(): Promise<void> {
  setLoadingPeers(true);
  setPeersError(null);
  try {
    const list = await api.listPeers();
    setPeers(list);
  } catch (e) {
    setPeersError(e instanceof Error ? e.message : "Failed to load peers");
  } finally {
    setLoadingPeers(false);
  }
}

/** Add a new peer. */
export async function addPeer(
  nodeId: string,
  addr: string,
  label?: string,
  autoConnect = true,
): Promise<void> {
  const peer = await api.addPeer({
    node_id: nodeId,
    addr,
    label,
    auto_connect: autoConnect,
  });
  setPeers(produce((list) => list.push(peer)));
}

/** Update a peer's label and/or address. */
export async function updatePeer(
  nodeId: string,
  updates: { addr?: string; label?: string },
): Promise<void> {
  const updated = await api.updatePeer(nodeId, updates);
  setPeers(
    (p) => p.node_id === nodeId,
    () => updated,
  );
}

/** Remove a peer. */
export async function removePeer(nodeId: string): Promise<void> {
  await api.removePeer(nodeId);
  setPeers((list) => list.filter((p) => p.node_id !== nodeId));
}

/** Connect to a peer. */
export async function connectPeer(nodeId: string): Promise<void> {
  await api.connectPeer(nodeId);
  // Refresh to get updated connection status
  await refreshPeers();
}

/** Get connected peer count. */
export function connectedCount(): number {
  return peers.filter((p) => p.connected).length;
}

/** Export peers as a downloadable JSON backup file. */
export async function exportPeers(): Promise<void> {
  const backup = await api.exportPeers();
  const blob = new Blob([JSON.stringify(backup, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `konsensus-contacts-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

/** Import peers from a JSON backup file. Returns the result summary. */
export async function importPeers(
  backup: PeerBackup,
  skipExisting = false,
): Promise<{ imported: number; skipped: number; errors: string[] }> {
  const result = await api.importPeers({ backup, skip_existing: skipExisting });
  // Refresh peer list after import
  await refreshPeers();
  return result;
}

export { peers, loadingPeers, peersError };
