/**
 * CalendarEventModal — create/edit event overlay with:
 *   - Title, date, start/end time, color, description
 *   - Attendees autocomplete from peer list
 *   - RSVP panel (Accept / Decline / Tentative) for received events
 */

import { createSignal, createMemo, For, Show, createEffect } from "solid-js";
import {
  IconX,
  IconCheck,
  IconTrash,
  IconPlus,
  IconPeers,
} from "./Icons";
import {
  upsertCalendarEvent,
  removeCalendarEvent,
  updateRsvp,
  sendRsvpToOrganizer,
  shareEventWithPeers,
  generateEventId,
  EVENT_COLORS,
  todayKey,
  formatDateDisplay,
  viewerTimezone,
  type CalendarEvent,
  type ModalDefaults,
  type RsvpStatus,
} from "../stores/useCalendarApi";
import { peers } from "../stores/peers";
import { nodeId } from "../stores/auth";
import { toast } from "../stores/toast";
import CalendarRecurrenceForm, {
  RECURRENCE_DEFAULT,
  type RecurrenceValue,
} from "./CalendarRecurrenceForm";

// ── Props ─────────────────────────────────────────────────────────────────

interface Props {
  show: () => boolean;
  event: () => CalendarEvent | null;
  defaults: () => ModalDefaults;
  onClose: () => void;
}

// ── Component ─────────────────────────────────────────────────────────────

export default function CalendarEventModal(props: Props) {
  const [title, setTitle] = createSignal("");
  const [date, setDate] = createSignal(todayKey());
  const [startTime, setStartTime] = createSignal("09:00");
  const [endTime, setEndTime] = createSignal("10:00");
  const [color, setColor] = createSignal(EVENT_COLORS[0].value);
  const [description, setDescription] = createSignal("");
  const [attendees, setAttendees] = createSignal<string[]>([]);
  const [attendeeInput, setAttendeeInput] = createSignal("");
  const [showDropdown, setShowDropdown] = createSignal(false);
  const [saving, setSaving] = createSignal(false);
  const [recurrence, setRecurrence] = createSignal<RecurrenceValue>(RECURRENCE_DEFAULT);

  // Sync form when modal opens with a new event or defaults
  createEffect(() => {
    if (!props.show()) return;
    const evt = props.event();
    if (evt) {
      setTitle(evt.title);
      setDate(evt.date);
      setStartTime(evt.startTime);
      setEndTime(evt.endTime);
      setColor(evt.color);
      setDescription(evt.description);
      setAttendees([...evt.attendees]);
      setRecurrence(evt.recurrence ?? RECURRENCE_DEFAULT);
    } else {
      const d = props.defaults();
      setTitle("");
      setDate(d.date ?? todayKey());
      setStartTime(d.startTime ?? "09:00");
      setEndTime(d.endTime ?? "10:00");
      setColor(EVENT_COLORS[0].value);
      setDescription("");
      setAttendees([]);
      setRecurrence(RECURRENCE_DEFAULT);
    }
    setAttendeeInput("");
    setShowDropdown(false);
  });

  // Attendees autocomplete
  const filteredPeers = createMemo(() => {
    const q = attendeeInput().toLowerCase().trim();
    if (!q) return [];
    return peers
      .filter(
        (p) =>
          !attendees().includes(p.node_id) &&
          (p.node_id.toLowerCase().includes(q) ||
            (p.label ?? "").toLowerCase().includes(q)),
      )
      .slice(0, 6);
  });

  function peerDisplay(nodeIdStr: string): string {
    const peer = peers.find((p) => p.node_id === nodeIdStr);
    if (peer?.label) return peer.label;
    return `${nodeIdStr.slice(0, 8)}…`;
  }

  function addAttendee(peerNodeId: string) {
    if (!attendees().includes(peerNodeId)) {
      setAttendees([...attendees(), peerNodeId]);
    }
    setAttendeeInput("");
    setShowDropdown(false);
  }

  function removeAttendee(peerNodeId: string) {
    setAttendees(attendees().filter((a) => a !== peerNodeId));
  }

  // ── Cancellation ─────────────────────────────────────────────────────────

  const isCancelled = createMemo(() => props.event()?.cancelled === true);

  // ── RSVP ────────────────────────────────────────────────────────────────

  const evt = () => props.event();
  const myNodeId = () => nodeId();
  const isReceivedEvent = createMemo(() => {
    const e = evt();
    const me = myNodeId();
    return !!(e?.organizer && me && e.organizer !== me);
  });
  const myRsvp = createMemo<RsvpStatus | null>(() => {
    const e = evt();
    const me = myNodeId();
    if (!e || !me) return null;
    return e.rsvps[me] ?? null;
  });

  async function handleRsvp(status: RsvpStatus) {
    const e = evt();
    const me = myNodeId();
    if (!e || !me) return;
    updateRsvp(e.id, me, status);
    try {
      await sendRsvpToOrganizer(e, me, status);
      toast.success(`RSVP sent: ${status}`);
    } catch {
      // Local update already applied; network failure is non-fatal
    }
  }

  // ── Save / Delete ────────────────────────────────────────────────────────

  async function handleSave() {
    if (!title().trim()) return;
    setSaving(true);
    try {
      const existing = props.event();
      const me = myNodeId();
      const rec = recurrence();
      const event: CalendarEvent = {
        id: existing?.id ?? generateEventId(),
        title: title().trim(),
        date: date(),
        startTime: startTime(),
        endTime: endTime(),
        color: color(),
        description: description().trim(),
        attendees: attendees(),
        rsvps: existing?.rsvps ?? {},
        organizer: existing?.organizer ?? me ?? undefined,
        organizerTimezone: existing?.organizerTimezone ?? viewerTimezone(),
        recurrence: rec.freq !== "NONE" ? rec : undefined,
      };
      upsertCalendarEvent(event);
      if (event.attendees.length > 0) {
        await shareEventWithPeers(event);
      }
      props.onClose();
    } finally {
      setSaving(false);
    }
  }

  function handleDelete() {
    const e = props.event();
    if (!e) return;
    removeCalendarEvent(e.id);
    props.onClose();
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
        <div class="cal-modal" role="dialog" aria-modal="true" aria-label="Calendar event">
          {/* Header */}
          <div class="cal-modal-header">
            <span class="cal-modal-title">
              {isCancelled() ? "Cancelled event" : props.event() ? "Edit event" : "New event"}
            </span>
            <button class="cal-nav-btn" onClick={props.onClose} aria-label="Close">
              <IconX size={16} />
            </button>
          </div>

          {/* Cancelled banner */}
          <Show when={isCancelled()}>
            <div style={{
              background: "rgba(239,68,68,0.1)",
              border: "1px solid rgba(239,68,68,0.3)",
              "border-radius": "6px",
              padding: "10px 12px",
              "margin-bottom": "4px",
            }}>
              <div style={{ "font-weight": 600, color: "var(--error)", "margin-bottom": "2px" }}>
                Cancelled on {formatDateDisplay(props.event()?.cancelledAt ?? props.event()?.date ?? "")}
              </div>
              <div class="text-xs text-muted">
                Attendees' calendars may still show the event marked as cancelled.
              </div>
            </div>
          </Show>

          {/* Title — strikethrough when cancelled */}
          <input
            type="text"
            class="input"
            placeholder="Event title"
            value={title()}
            onInput={(e) => setTitle(e.currentTarget.value)}
            onKeyDown={(e) => e.key === "Enter" && !saving() && !isCancelled() && handleSave()}
            disabled={isCancelled()}
            style={isCancelled() ? { "text-decoration": "line-through", opacity: "0.7" } : {}}
            autofocus={!isCancelled()}
          />

          {/* Date + times */}
          <div style={{ display: "flex", gap: "8px", "flex-wrap": "wrap" }}>
            <input
              type="date"
              class="input"
              value={date()}
              onInput={(e) => setDate(e.currentTarget.value)}
              style={{ flex: "2 1 120px" }}
            />
            <input
              type="time"
              class="input"
              value={startTime()}
              onInput={(e) => setStartTime(e.currentTarget.value)}
              style={{ flex: "1 1 90px" }}
            />
            <input
              type="time"
              class="input"
              value={endTime()}
              onInput={(e) => setEndTime(e.currentTarget.value)}
              style={{ flex: "1 1 90px" }}
            />
          </div>

          {/* Color picker */}
          <div class="cal-color-picker">
            <span class="text-xs text-muted" style={{ "margin-right": "4px" }}>Color:</span>
            <For each={EVENT_COLORS}>
              {(c) => (
                <button
                  class={`cal-color-swatch ${color() === c.value ? "active" : ""}`}
                  style={{ background: c.value }}
                  onClick={() => setColor(c.value)}
                  title={c.name}
                  aria-label={`Color: ${c.name}`}
                />
              )}
            </For>
          </div>

          {/* Description */}
          <textarea
            class="input"
            placeholder="Description (optional)"
            rows={2}
            value={description()}
            onInput={(e) => setDescription(e.currentTarget.value)}
            style={{ resize: "vertical" }}
          />

          {/* Attendees autocomplete */}
          <div class="cal-attendees-wrap">
            <label class="text-xs text-muted" style={{ "margin-bottom": "4px", display: "block" }}>
              <IconPeers size={11} style={{ "vertical-align": "middle", "margin-right": "4px" }} />
              Attendees
            </label>

            <Show when={attendees().length > 0}>
              <div class="cal-attendees-chips">
                <For each={attendees()}>
                  {(aId) => (
                    <div class="cal-attendee-chip">
                      <span>{peerDisplay(aId)}</span>
                      <button
                        class="cal-attendee-remove"
                        onClick={() => removeAttendee(aId)}
                        aria-label={`Remove ${peerDisplay(aId)}`}
                      >
                        <IconX size={10} />
                      </button>
                    </div>
                  )}
                </For>
              </div>
            </Show>

            <div style={{ position: "relative" }}>
              <input
                type="text"
                class="input"
                placeholder="Search peers to invite…"
                value={attendeeInput()}
                onInput={(e) => {
                  setAttendeeInput(e.currentTarget.value);
                  setShowDropdown(true);
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
                        onMouseDown={() => addAttendee(peer.node_id)}
                      >
                        <div class="cal-attendees-option-label">
                          {peer.label ?? "Unnamed peer"}
                        </div>
                        <div class="cal-attendees-option-id">
                          {peer.node_id.slice(0, 16)}…
                        </div>
                      </div>
                    )}
                  </For>
                </div>
              </Show>
            </div>
          </div>

          {/* Recurrence */}
          <CalendarRecurrenceForm value={recurrence} onChange={setRecurrence} />

          {/* RSVP panel — shown when viewing a received event */}
          <Show when={isReceivedEvent()}>
            <div class="cal-rsvp-section">
              <div class="cal-rsvp-label">Your RSVP</div>
              <div class="cal-rsvp-buttons">
                <button
                  class={`cal-rsvp-btn ${myRsvp() === "accepted" ? "cal-rsvp-accepted" : ""}`}
                  onClick={() => handleRsvp("accepted")}
                >
                  <IconCheck size={12} style={{ "vertical-align": "middle", "margin-right": "3px" }} />
                  Accept
                </button>
                <button
                  class={`cal-rsvp-btn ${myRsvp() === "tentative" ? "cal-rsvp-tentative" : ""}`}
                  onClick={() => handleRsvp("tentative")}
                >
                  Maybe
                </button>
                <button
                  class={`cal-rsvp-btn ${myRsvp() === "declined" ? "cal-rsvp-declined" : ""}`}
                  onClick={() => handleRsvp("declined")}
                >
                  <IconX size={12} style={{ "vertical-align": "middle", "margin-right": "3px" }} />
                  Decline
                </button>
              </div>
            </div>
          </Show>

          {/* Attendee RSVP summary — shown when editing own event */}
          <Show when={!isReceivedEvent() && props.event() && attendees().length > 0}>
            <div class="cal-rsvp-section">
              <div class="cal-rsvp-label">Attendee responses</div>
              <For each={attendees()}>
                {(aId) => {
                  const status = () => props.event()?.rsvps[aId];
                  return (
                    <div style={{ display: "flex", "align-items": "center", gap: "8px", padding: "4px 0" }}>
                      <span class="text-xs" style={{ flex: 1 }}>{peerDisplay(aId)}</span>
                      <Show when={status()}>
                        <span
                          class={`text-xs cal-rsvp-btn ${status() === "accepted" ? "cal-rsvp-accepted" : status() === "declined" ? "cal-rsvp-declined" : "cal-rsvp-tentative"}`}
                          style={{ "flex-shrink": 0, padding: "2px 8px", cursor: "default" }}
                        >
                          {status()}
                        </span>
                      </Show>
                      <Show when={!status()}>
                        <span class="text-xs text-muted">No reply</span>
                      </Show>
                    </div>
                  );
                }}
              </For>
            </div>
          </Show>

          {/* Footer actions */}
          <div class="cal-modal-footer">
            <Show when={isCancelled()}>
              <button
                class="btn btn-ghost btn-sm"
                onClick={handleDelete}
                style={{ color: "var(--error)", display: "inline-flex", "align-items": "center", gap: "4px" }}
              >
                <IconTrash size={12} /> Remove from my calendar
              </button>
              <button class="btn btn-ghost btn-sm" onClick={props.onClose} style={{ "margin-left": "auto" }}>
                Close
              </button>
            </Show>
            <Show when={!isCancelled()}>
              <button
                class="btn btn-primary btn-sm"
                onClick={handleSave}
                disabled={!title().trim() || saving()}
                style={{ display: "inline-flex", "align-items": "center", gap: "4px" }}
              >
                <IconCheck size={12} />
                {saving() ? "Saving…" : "Save"}
              </button>
              <button class="btn btn-ghost btn-sm" onClick={props.onClose}>
                Cancel
              </button>
              <Show when={props.event()}>
                <button
                  class="btn btn-ghost btn-sm"
                  onClick={handleDelete}
                  style={{ "margin-left": "auto", color: "var(--error)", display: "inline-flex", "align-items": "center", gap: "4px" }}
                >
                  <IconTrash size={12} /> Delete
                </button>
              </Show>
            </Show>
          </div>
        </div>
      </div>
    </Show>
  );
}
