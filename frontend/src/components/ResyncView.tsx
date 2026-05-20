/** ResyncView — "Restore message history" screen. Two-phase: discover + fulfill. */
import { createSignal, createMemo, For, Show, onMount } from "solid-js";
import { api } from "../stores/auth";
import { peers, refreshPeers } from "../stores/peers";
import { formatMsat } from "../stores/payments";
import { truncateId } from "../utils/formatting";
import type { ResyncEntry, ResyncDiscoverResponse, ResyncFulfillResponse } from "../api/types";

const MS_PER_DAY = 86_400_000;
const PRESETS = [
  { label: "7 days", days: 7 }, { label: "30 days", days: 30 },
  { label: "90 days", days: 90 }, { label: "1 year", days: 365 },
];

export default function ResyncView() {
  const [peerId, setPeerId]       = createSignal("");
  const [days, setDays]           = createSignal(30);
  const [discovering, setDisc]    = createSignal(false);
  const [discErr, setDiscErr]     = createSignal<string|null>(null);
  const [manifest, setManifest]   = createSignal<ResyncDiscoverResponse|null>(null);
  const [selected, setSelected]   = createSignal<Record<string,boolean>>({});
  const [fulfilling, setFulfill]  = createSignal(false);
  const [fulfillErr, setFulfillErr]= createSignal<string|null>(null);
  const [result, setResult]       = createSignal<ResyncFulfillResponse|null>(null);

  onMount(() => refreshPeers());

  const setAll = (m: ResyncDiscoverResponse) => {
    const s: Record<string,boolean> = {};
    m.messages.forEach(e => s[e.id] = true);
    setSelected(s); setManifest(m);
  };

  const selectedIds = createMemo(() => Object.keys(selected()).filter(id => selected()[id]));
  const cost = createMemo(() => {
    const m = manifest(); if (!m) return 0;
    const s = selected();
    return m.messages.filter(e => s[e.id]).reduce((n,e) => n + e.estimated_fee_msat, 0);
  });
  const allSel = createMemo(() => { const m = manifest(); return !!m && m.messages.length > 0 && m.messages.every(e => selected()[e.id]); });
  const toggleAll = () => { const m = manifest(); if (!m) return; const next = !allSel(); const s: Record<string,boolean> = {}; m.messages.forEach(e => s[e.id] = next); setSelected(s); };

  const doDiscover = async () => {
    if (!peerId()) return;
    setDisc(true); setDiscErr(null); setManifest(null); setResult(null); setFulfillErr(null);
    try { setAll(await api.resyncDiscover(peerId(), Date.now() - days() * MS_PER_DAY, Date.now())); }
    catch (e) { setDiscErr(e instanceof Error ? e.message : "Discovery failed"); }
    finally { setDisc(false); }
  };

  const doFulfill = async () => {
    const ids = selectedIds(); if (!peerId() || !ids.length) return;
    setFulfill(true); setFulfillErr(null); setResult(null);
    try { setResult(await api.resyncFulfill(peerId(), ids)); }
    catch (e) { setFulfillErr(e instanceof Error ? e.message : "Restore failed"); }
    finally { setFulfill(false); }
  };

  const peerLabel = (id: string) => peers.find(p => p.node_id === id)?.label ?? truncateId(id);

  return (
    <div class="view-container">
      <div class="view-header">
        <h1 class="view-title">Restore message history</h1>
        <p style={{ color: "var(--text-secondary)", "font-size": "14px" }}>
          Re-import stored messages at 50% resync discount. Cached plaintext is restored immediately.
        </p>
      </div>

      {/* Step 1 */}
      <div class="card" style={{ "margin-bottom": "16px" }}>
        <h2 class="card-title" style={{ "font-size": "15px", "margin-bottom": "14px" }}>Step 1 — Peer &amp; time window</h2>
        <div class="form-group" style={{ "margin-bottom": "14px" }}>
          <label class="form-label">Peer</label>
          <Show when={peers.length > 0} fallback={<p style={{ color: "var(--text-secondary)", "font-size": "13px" }}>No peers found.</p>}>
            <select class="input" value={peerId()} onChange={e => setPeerId(e.currentTarget.value)}>
              <option value="">— choose a peer —</option>
              <For each={peers}>{p =>
                <option value={p.node_id}>{p.label ?? truncateId(p.node_id)}{p.connected ? " ●" : ""}</option>
              }</For>
            </select>
          </Show>
        </div>
        <div class="form-group" style={{ "margin-bottom": "14px" }}>
          <label class="form-label">Window</label>
          <div style={{ display: "flex", gap: "8px" }}>
            <For each={PRESETS}>{pr =>
              <button class={`btn btn-sm ${days() === pr.days ? "btn-primary" : "btn-ghost"}`} onClick={() => setDays(pr.days)}>{pr.label}</button>
            }</For>
          </div>
        </div>
        <button class="btn btn-primary" disabled={!peerId() || discovering()} onClick={doDiscover}>
          {discovering() ? "Discovering…" : "Discover"}
        </button>
        <Show when={discErr()}><p style={{ color: "var(--color-error)", "margin-top": "8px", "font-size": "13px" }}>{discErr()}</p></Show>
      </div>

      {/* Step 2 */}
      <Show when={manifest()}>
        {m => (
          <div class="card" style={{ "margin-bottom": "16px" }}>
            <div style={{ display: "flex", "justify-content": "space-between", "margin-bottom": "10px" }}>
              <h2 class="card-title" style={{ "font-size": "15px" }}>Step 2 — Review &amp; restore</h2>
              <span style={{ "font-size": "13px", color: "var(--text-secondary)" }}>{m().total_count} message{m().total_count !== 1 ? "s" : ""} for <b>{peerLabel(m().peer_id)}</b></span>
            </div>
            <Show when={m().messages.length > 0} fallback={<p style={{ color: "var(--text-secondary)", "font-size": "13px" }}>No messages in this window.</p>}>
              <div style={{ display: "flex", "align-items": "center", gap: "8px", "padding-bottom": "8px", "border-bottom": "1px solid var(--border)" }}>
                <input type="checkbox" checked={allSel()} onChange={toggleAll} />
                <label style={{ "font-size": "13px", cursor: "pointer" }}>All ({m().messages.length})</label>
              </div>
              <div style={{ "max-height": "280px", "overflow-y": "auto", margin: "8px 0" }}>
                <For each={m().messages}>{entry => (
                  <div style={{ display: "flex", "align-items": "center", gap: "10px", padding: "5px 0", "border-bottom": "1px solid var(--border)", opacity: selected()[entry.id] ? "1" : "0.5" }}>
                    <input type="checkbox" checked={!!selected()[entry.id]} onChange={() => setSelected(s => ({ ...s, [entry.id]: !s[entry.id] }))} />
                    <span style={{ "font-size": "11px", background: "var(--surface)", padding: "2px 5px", "border-radius": "3px" }}>k{entry.kind}</span>
                    <span style={{ "font-size": "12px", color: "var(--text-secondary)" }}>{new Date(entry.timestamp).toLocaleString(undefined, { month:"short", day:"numeric", hour:"2-digit", minute:"2-digit" })}</span>
                    <span style={{ "margin-left": "auto", "font-size": "11px", color: "var(--color-accent)" }}>{entry.estimated_fee_msat} msat</span>
                    <span title={entry.plaintext_available ? "plaintext cached" : "no plaintext (R3 pending)"} style={{ width: "7px", height: "7px", "border-radius": "50%", background: entry.plaintext_available ? "var(--color-success)" : "var(--text-secondary)" }} />
                  </div>
                )}</For>
              </div>
              <div style={{ display: "flex", "justify-content": "space-between", "padding-top": "8px", "border-top": "1px solid var(--border)", "margin-bottom": "12px" }}>
                <span style={{ "font-size": "13px", color: "var(--text-secondary)" }}>{selectedIds().length} selected</span>
                <span style={{ "font-size": "13px" }}>Cost: <b style={{ color: "var(--color-accent)" }}>{formatMsat(cost())}</b> <span style={{ "font-size": "11px", color: "var(--text-secondary)" }}>(50%% off)</span></span>
              </div>
              <button class="btn btn-primary" disabled={!selectedIds().length || fulfilling()} onClick={doFulfill}>
                {fulfilling() ? "Restoring…" : `Restore ${selectedIds().length}`}
              </button>
            </Show>
            <Show when={fulfillErr()}><p style={{ color: "var(--color-error)", "font-size": "13px", "margin-top": "8px" }}>{fulfillErr()}</p></Show>
          </div>
        )}
      </Show>

      {/* Result */}
      <Show when={result()}>{r => (
        <div class="card" style={{ "border-color": "var(--color-success)" }}>
          <h2 class="card-title" style={{ "font-size": "15px", color: "var(--color-success)", "margin-bottom": "10px" }}>Restore complete</h2>
          <div style={{ display: "grid", "grid-template-columns": "1fr 1fr", gap: "10px" }}>
            {[["Restored", r().resynced_count], ["Failed", r().failed_count], ["With plaintext", r().plaintext_count], ["Total cost", formatMsat(r().total_msat)]].map(([l, v]) => (
              <div style={{ background: "var(--surface)", padding: "10px 14px", "border-radius": "8px" }}>
                <div style={{ "font-size": "18px", "font-weight": "600" }}>{v}</div>
                <div style={{ "font-size": "12px", color: "var(--text-secondary)" }}>{l}</div>
              </div>
            ))}
          </div>
          <p style={{ "font-size": "12px", color: "var(--text-secondary)", "margin-top": "10px" }}>Messages broadcast to open chat windows.</p>
        </div>
      )}</Show>
    </div>
  );
}
