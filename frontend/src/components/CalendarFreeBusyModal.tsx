/**
 * CalendarFreeBusyModal — check a peer's availability and visualize busy blocks.
 *
 * Features:
 *   - Peer picker (autocomplete from peer list)
 *   - Date range selector (defaults to the current week)
 *   - Calls GET /api/v1/calendar/freebusy?peer=&from=&to=
 *   - Renders a 24-hour timeline per day with opaque grey bars for busy slots
 */

import { createSignal, createMemo, For, Show } from "solid-js";
import { IconX, IconPeers, IconCheck, IconClock } from "./Icons";
import { peers } from "../stores/peers";
import { api } from "../stores/auth";
import { toDateKey, todayKey } from "../stores/useCalendarApi";
import type { BusyBlock } from "../api/types";

// ── Types ─────────────────────────────────────────────────────────────────

interface Props {
  show: () => boolean;
  onClose: () => void;
}

/** Busy blocks grouped by day key (YYYY-MM-DD). */
type BusyByDay = Record<string, BusyBlock[]>;

// ── Helpers ───────────────────────────────────────────────────────────────

/** Return the Monday of the week containing dateKey. */
function weekStart(dateKey: string): Date {
  const [y, m, d] = dateKey.split("-").map(Number);
  const date = new Date(y, m - 1, d);
  const dow = date.getDay();
  const monday = new Date(date);
  monday.setDate(date.getDate() - (dow === 0 ? 6 : dow - 1));
  return monday;
}

/** Return YYYY-MM-DD for a Date. */
function toKey(d: Date): string {
  const y = d.getFullYear();
  const mo = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}-${mo}-${day}`;
}

/** Format a date key for display. */
function formatDay(dk: string): string {
  const [y, m, d] = dk.split("-").map(Number);
  return new Date(y, m - 1, d).toLocaleDateString([], {
    weekday: "short",
    month: "short",
    day: "numeric",
  });
}

/** Group a flat list of BusyBlocks by day key. */
function groupByDay(blocks: BusyBlock[]): BusyByDay {
  const result: BusyByDay = {};
  for (const block of blocks) {
    const start = new Date(block.start);
    const dk = toDateKey(start);
    if (!result[dk]) result[dk] = [];
    result[dk].push(block);
  }
  return result;
}

/** For a busy block, compute left% and width% within a 24-hour day bar. */
function blockGeometry(block: BusyBlock, dayKey: string): { left: number; width: number } {
  const [y, m, d] = dayKey.split("-").map(Number);
  const dayStartMs = new Date(y, m - 1, d, 0, 0, 0).getTime();
  const clampedStart = Math.max(block.start, dayStartMs);
  const clampedEnd = Math.min(block.end, dayStartMs + 24 * 3600 * 1000);
  const left = ((clampedStart - dayStartMs) / (24 * 3600 * 1000)) * 100;
  const width = Math.max(((clampedEnd - clampedStart) / (24 * 3600 * 1000)) * 100, 0.5);
  return { left, width };
}

/** Format a unix-ms timestamp as HH:MM local time. */
function fmtTime(ms: number): string {
  const d = new Date(ms);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
}

// ── Component ─────────────────────────────────────────────────────────────

export default function CalendarFreeBusyModal(props: Props) {
  const [peerInput, setPeerInput] = createSignal("");
  const [selectedPeer, setSelectedPeer] = createSignal<string | null>(null);
  const [showDropdown, setShowDropdown] = createSignal(false);

  // Default: current week Mon–Sun
  const monday = weekStart(todayKey());
  const sunday = new Date(monday);
  sunday.setDate(monday.getDate() + 6);

  const [fromDate, setFromDate] = createSignal(toKey(monday));
  const [toDate, setToDate] = createSignal(toKey(sunday));

  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [busyByDay, setBusyByDay] = createSignal<BusyByDay>({});
  const [queried, setQueried] = createSignal(false);

  // Peer autocomplete
  const filteredPeers = createMemo(() => {
    const q = peerInput().toLowerCase().trim();
    if (!q) return [];
    return peers
      .filter(
        (p) =>
          p.node_id.toLowerCase().includes(q) ||
          (p.label ?? "").toLowerCase().includes(q),
      )
      .slice(0, 6);
  });

  function selectPeer(nodeId: string) {
    setSelectedPeer(nodeId);
    const peer = peers.find((p) => p.node_id === nodeId);
    setPeerInput(peer?.label ?? nodeId.slice(0, 16) + "\u2026");
    setShowDropdown(false);
    setBusyByDay({});
    setQueried(false);
    setError(null);
  }

  function peerDisplay(nodeId: string): string {
    const peer = peers.find((p) => p.node_id === nodeId);
    if (peer?.label) return peer.label;
    return `${nodeId.slice(0, 8)}\u2026`;
  }

  // Days in the selected range (max 14)
  const dayKeys = createMemo<string[]>(() => {
    const from = fromDate();
    const to = toDate();
    if (!from || !to || from > to) return [];
    const result: string[] = [];
    const [fy, fm, fd] = from.split("-").map(Number);
    const cur = new Date(fy, fm - 1, fd);
    const [ty, tm, td] = to.split("-").map(Number);
    const end = new Date(ty, tm - 1, td);
    while (cur <= end && result.length < 14) {
      result.push(toKey(new Date(cur)));
      cur.setDate(cur.getDate() + 1);
    }
    return result;
  });

  async function handleCheck() {
    const peer = selectedPeer();
    if (!peer) {
      setError("Select a peer first.");
      return;
    }
    const from = fromDate();
    const to = toDate();
    if (!from || !to || from > to) {
      setError("Select a valid date range.");
      return;
    }

    const [fy, fm, fd] = from.split("-").map(Number);
    const [ty, tm, td] = to.split("-").map(Number);
    const fromMs = new Date(fy, fm - 1, fd, 0, 0, 0).getTime();
    const toMs = new Date(ty, tm - 1, td, 23, 59, 59).getTime();

    setLoading(true);
    setError(null);
    setQueried(false);
    try {
      const res = await api.getFreeBusy(peer, fromMs, toMs);
      setBusyByDay(groupByDay(res.busy));
      setQueried(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to fetch availability.");
    } finally {
      setLoading(false);
    }
  }

  function handleOverlayClick(e: MouseEvent) {
    if ((e.target as HTMLElement).classList.contains("cal-modal-overlay")) {
      props.onClose();
    }
  }

  return (
    <Show when={props.show()}>
      {/* eslint-disable-next-line jsx-a11y/click-events-have-key-events */}
      <div class="cal-modal-overlay" onClick={handleOverlayClick}>
        <div
          class="cal-modal"
          role="dialog"
          aria-modal="true"
          aria-label="Check peer availability"
          style={{ "max-width": "680px", width: "95vw" }}
        >
          {/* Header */}
          <div class="cal-modal-header">
            <span class="cal-modal-title" style={{ display: "flex", "align-items": "center", gap: "6px" }}>
              <IconClock size={14} />
              Check Availability
            </span>
            <button class="cal-nav-btn" onClick={props.onClose} aria-label="Close">
              <IconX size={16} />
            </button>
          </div>

          {/* Controls */}
          <div style={{ display: "flex", gap: "8px", "flex-wrap": "wrap", "align-items": "flex-end" }}>
            {/* Peer picker */}
            <div style={{ flex: "2 1 200px", position: "relative" }}>
              <label class="text-xs text-muted" style={{ display: "block", "margin-bottom": "4px" }}>
                <IconPeers size={11} style={{ "vertical-align": "middle", "margin-right": "4px" }} />
                Peer
              </label>
              <input
                type="text"
                class="input"
                placeholder="Search peers\u2026"
                value={peerInput()}
                onInput={(e) => {
                  setPeerInput(e.currentTarget.value);
                  setSelectedPeer(null);
                  setShowDropdown(true);
                  setBusyByDay({});
                  setQueried(false);
                }}
                onFocus={() => setShowDropdown(true)}
                onBlur={() => setTimeout(() => setShowDropdown(false), 150)}
              />
              <Show when={showDropdown() && filteredPeers().length > 0}>
                <div class="cal-attendees-dropdown">
                  <For each={filteredPeers()}>
                    {(peer) => (
                      <div
                        class="cal-attendees-option"
                        onMouseDown={() => selectPeer(peer.node_id)}
                      >
                        <div class="cal-attendees-option-label">
                          {peer.label ?? "Unnamed peer"}
                        </div>
                        <div class="cal-attendees-option-id">
                          {peer.node_id.slice(0, 16)}\u2026
                        </div>
                      </div>
                    )}
                  </For>
                </div>
              </Show>
            </div>

            {/* From date */}
            <div style={{ flex: "1 1 120px" }}>
              <label class="text-xs text-muted" style={{ display: "block", "margin-bottom": "4px" }}>
                From
              </label>
              <input
                type="date"
                class="input"
                value={fromDate()}
                onInput={(e) => { setFromDate(e.currentTarget.value); setBusyByDay({}); setQueried(false); }}
              />
            </div>

            {/* To date */}
            <div style={{ flex: "1 1 120px" }}>
              <label class="text-xs text-muted" style={{ display: "block", "margin-bottom": "4px" }}>
                To
              </label>
              <input
                type="date"
                class="input"
                value={toDate()}
                onInput={(e) => { setToDate(e.currentTarget.value); setBusyByDay({}); setQueried(false); }}
              />
            </div>

            {/* Check button */}
            <button
              class="btn btn-primary btn-sm"
              onClick={handleCheck}
              disabled={!selectedPeer() || loading()}
              style={{ "flex-shrink": 0, "align-self": "flex-end", display: "inline-flex", "align-items": "center", gap: "4px" }}
            >
              <IconCheck size={12} />
              {loading() ? "Loading\u2026" : "Check"}
            </button>
          </div>

          {/* Error */}
          <Show when={error()}>
            <div style={{
              background: "rgba(239,68,68,0.1)",
              border: "1px solid rgba(239,68,68,0.3)",
              "border-radius": "6px",
              padding: "8px 12px",
              color: "var(--error)",
              "font-size": "13px",
            }}>
              {error()}
            </div>
          </Show>

          {/* Timeline */}
          <Show when={queried()}>
            <div style={{ "margin-top": "4px" }}>
              {/* Hour labels */}
              <div style={{ display: "flex", "margin-left": "88px", "margin-bottom": "4px" }}>
                <For each={[0, 6, 12, 18]}>
                  {(h) => (
                    <div style={{
                      flex: "1 1 0",
                      "font-size": "10px",
                      color: "var(--text-muted)",
                      "text-align": "left",
                    }}>
                      {`${String(h).padStart(2, "0")}:00`}
                    </div>
                  )}
                </For>
              </div>

              {/* Day rows */}
              <For each={dayKeys()}>
                {(dk) => {
                  const blocks = () => busyByDay()[dk] ?? [];
                  const hasBusy = () => blocks().length > 0;
                  return (
                    <div style={{
                      display: "flex",
                      "align-items": "center",
                      gap: "8px",
                      "margin-bottom": "6px",
                    }}>
                      {/* Day label */}
                      <div style={{
                        "flex-shrink": 0,
                        width: "80px",
                        "font-size": "11px",
                        color: hasBusy() ? "var(--text-primary)" : "var(--text-muted)",
                        "text-align": "right",
                        "padding-right": "8px",
                      }}>
                        {formatDay(dk)}
                      </div>

                      {/* 24h bar */}
                      <div style={{
                        flex: 1,
                        height: "22px",
                        background: "rgba(255,255,255,0.04)",
                        border: "1px solid rgba(255,255,255,0.08)",
                        "border-radius": "4px",
                        position: "relative",
                        overflow: "hidden",
                      }}>
                        {/* Gridlines at 6h intervals */}
                        <For each={[25, 50, 75]}>
                          {(pct) => (
                            <div style={{
                              position: "absolute",
                              top: 0,
                              bottom: 0,
                              left: `${pct}%`,
                              width: "1px",
                              background: "rgba(255,255,255,0.06)",
                            }} />
                          )}
                        </For>

                        {/* Busy blocks — opaque grey bars */}
                        <For each={blocks()}>
                          {(block) => {
                            const geo = blockGeometry(block, dk);
                            return (
                              <div
                                title={`${fmtTime(block.start)} \u2013 ${fmtTime(block.end)}`}
                                style={{
                                  position: "absolute",
                                  top: "2px",
                                  bottom: "2px",
                                  left: `${geo.left}%`,
                                  width: `${geo.width}%`,
                                  background: "rgba(150,150,160,0.85)",
                                  "border-radius": "2px",
                                }}
                              />
                            );
                          }}
                        </For>

                        {/* "free" label when no busy blocks */}
                        <Show when={!hasBusy()}>
                          <span style={{
                            position: "absolute",
                            top: "50%",
                            left: "50%",
                            transform: "translate(-50%, -50%)",
                            "font-size": "10px",
                            color: "rgba(74,209,74,0.7)",
                          }}>
                            free
                          </span>
                        </Show>
                      </div>
                    </div>
                  );
                }}
              </For>

              {/* Legend */}
              <div style={{ display: "flex", gap: "16px", "margin-top": "8px", "font-size": "11px", color: "var(--text-muted)" }}>
                <div style={{ display: "flex", "align-items": "center", gap: "6px" }}>
                  <div style={{ width: "14px", height: "10px", background: "rgba(150,150,160,0.85)", "border-radius": "2px" }} />
                  Busy
                </div>
                <div style={{ display: "flex", "align-items": "center", gap: "6px" }}>
                  <span style={{ color: "rgba(74,209,74,0.7)" }}>free</span>
                  No known events
                </div>
              </div>

              {/* Footnote */}
              <Show when={selectedPeer()}>
                <p class="text-xs text-muted" style={{ "margin-top": "6px" }}>
                  Showing shared calendar data for <strong>{peerDisplay(selectedPeer()!)}</strong>.
                  Availability reflects events stored on this node.
                </p>
              </Show>
            </div>
          </Show>

          {/* Empty state before first query */}
          <Show when={!queried() && !loading()}>
            <div style={{ "text-align": "center", padding: "24px 0", color: "var(--text-muted)", "font-size": "13px" }}>
              Select a peer and date range, then click Check.
            </div>
          </Show>
        </div>
      </div>
    </Show>
  );
}
