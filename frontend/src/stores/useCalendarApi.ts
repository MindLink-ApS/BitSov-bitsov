/**
 * Calendar store — shared reactive state and API operations.
 *
 * Events are persisted to localStorage (v2 format) and optionally
 * broadcast to peers via KIND_CALENDAR_EVENT / KIND_CALENDAR_RSVP messages.
 * This layer replaces direct localStorage access in view components.
 */

import { createStore, produce } from "solid-js/store";
import { loadJSON, saveJSON } from "../utils/storage";
import { api } from "./auth";
import { MessageKind } from "../api/types";
import type { RecurrenceValue } from "../components/CalendarRecurrenceForm";

// ── Types ─────────────────────────────────────────────────────────────────

export type RsvpStatus = "accepted" | "declined" | "tentative";

export interface CalendarEvent {
  id: string;
  title: string;
  date: string;       // YYYY-MM-DD
  startTime: string;  // HH:MM (24h) — stored in organizerTimezone
  endTime: string;    // HH:MM (24h) — stored in organizerTimezone
  color: string;
  description: string;
  attendees: string[];  // peer node IDs
  rsvps: Record<string, RsvpStatus>;
  organizer?: string;   // creator's node ID
  organizerTimezone?: string;  // IANA timezone of the organizer, e.g. "Europe/Berlin"
  recurrence?: RecurrenceValue;
  /** True when the organizer has sent a KIND_CALENDAR_CANCEL for this event. */
  cancelled?: boolean;
  /** YYYY-MM-DD date when this event was cancelled. */
  cancelledAt?: string;
}

export interface ModalDefaults {
  date?: string;
  startTime?: string;
  endTime?: string;
}

export const EVENT_COLORS: readonly { name: string; value: string }[] = [
  { name: "Blue",   value: "#4a9eff" },
  { name: "Green",  value: "#34d399" },
  { name: "Orange", value: "#f59e0b" },
  { name: "Red",    value: "#ef4444" },
  { name: "Purple", value: "#a78bfa" },
  { name: "Teal",   value: "#2dd4bf" },
];

// ── Timezone helpers ──────────────────────────────────────────────────────

/** Returns the viewer's IANA timezone string (e.g. "Europe/Copenhagen"). */
export function viewerTimezone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  } catch {
    return "UTC";
  }
}

/**
 * UTC offset in minutes for `tz` on `dateKey`.
 * Uses noon UTC as reference to avoid hitting DST transitions (typically 02:00 local).
 */
function tzOffsetMin(dateKey: string, tz: string): number {
  try {
    const [y, m, d] = dateKey.split("-").map(Number);
    const noon = new Date(Date.UTC(y, m - 1, d, 12, 0, 0));
    let lh = 12;
    let lm = 0;
    for (const p of new Intl.DateTimeFormat("en-CA", {
      timeZone: tz,
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", hourCycle: "h23",
    }).formatToParts(noon)) {
      if (p.type === "hour")   lh = parseInt(p.value, 10);
      if (p.type === "minute") lm = parseInt(p.value, 10);
    }
    return (lh - 12) * 60 + lm;
  } catch {
    return 0;
  }
}

/**
 * Convert a HH:MM time string from one IANA timezone to another on a given date.
 * Returns a HH:MM string in `toTz`.
 */
export function convertTime(
  dateKey: string,
  timeStr: string,
  fromTz: string,
  toTz: string,
): string {
  try {
    const [h, m] = timeStr.split(":").map(Number);
    const delta = tzOffsetMin(dateKey, toTz) - tzOffsetMin(dateKey, fromTz);
    const wrapped = ((h * 60 + m + delta) % 1440 + 1440) % 1440;
    return `${String(Math.floor(wrapped / 60)).padStart(2, "0")}:${String(wrapped % 60).padStart(2, "0")}`;
  } catch {
    return timeStr;
  }
}

/**
 * Return the display time for an event, converting from the organizer's timezone
 * to the viewer's local timezone when they differ.
 */
export function localEventTime(evt: CalendarEvent, timeStr: string): string {
  if (!evt.organizerTimezone) return timeStr;
  const vTz = viewerTimezone();
  if (evt.organizerTimezone === vTz) return timeStr;
  return convertTime(evt.date, timeStr, evt.organizerTimezone, vTz);
}

/**
 * If the event's organizer is in a different timezone than the viewer, returns a
 * tooltip string like "Organizer's local: 15:00 in Europe/Berlin". Otherwise null.
 */
export function organizerTzTooltip(evt: CalendarEvent, storedTimeStr: string): string | null {
  if (!evt.organizerTimezone) return null;
  const vTz = viewerTimezone();
  if (evt.organizerTimezone === vTz) return null;
  return `Organizer's local: ${storedTimeStr} in ${evt.organizerTimezone}`;
}

// ── Date helpers ─────────────────────────────────────────────────────────

export const MONTH_NAMES = [
  "January", "February", "March", "April", "May", "June",
  "July", "August", "September", "October", "November", "December",
];
export const DAY_NAMES_SHORT = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

export function toDateKey(date: Date): string {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const d = String(date.getDate()).padStart(2, "0");
  return `${y}-${m}-${d}`;
}

export function todayKey(): string {
  return toDateKey(new Date());
}

export function isToday(dateKey: string): boolean {
  return dateKey === todayKey();
}

export function daysInMonth(year: number, month: number): number {
  return new Date(year, month + 1, 0).getDate();
}

/** Monday = 0, Sunday = 6 */
export function startDayOfMonth(year: number, month: number): number {
  const d = new Date(year, month, 1).getDay();
  return d === 0 ? 6 : d - 1;
}

/** Return the Monday of the week containing dateKey. */
export function weekMonday(dateKey: string): Date {
  const [y, m, d] = dateKey.split("-").map(Number);
  const date = new Date(y, m - 1, d);
  const dow = date.getDay();
  const monday = new Date(date);
  monday.setDate(date.getDate() - (dow === 0 ? 6 : dow - 1));
  return monday;
}

export function formatTimeDisplay(time: string): string {
  const [h, m] = time.split(":").map(Number);
  const ampm = h < 12 ? "AM" : "PM";
  const h12 = h === 0 ? 12 : h > 12 ? h - 12 : h;
  return `${h12}:${String(m).padStart(2, "0")} ${ampm}`;
}

export function formatDateDisplay(dateKey: string): string {
  const [y, m, d] = dateKey.split("-").map(Number);
  return new Date(y, m - 1, d).toLocaleDateString([], {
    weekday: "long", month: "long", day: "numeric",
  });
}

// ── Storage ───────────────────────────────────────────────────────────────

const STORAGE_KEY = "bitsov_calendar_v2";

function addOneHour(t: string): string {
  const [h, m] = t.split(":").map(Number);
  return `${String(Math.min(h + 1, 23)).padStart(2, "0")}:${String(m).padStart(2, "0")}`;
}

// ── Reactive store ────────────────────────────────────────────────────────

const [calendarEvents, setCalendarEvents] = createStore<CalendarEvent[]>([]);

export { calendarEvents };

function persist(): void {
  saveJSON(STORAGE_KEY, [...calendarEvents]);
}

// ── Operations ────────────────────────────────────────────────────────────

/** Load events from localStorage. Call once on app/view mount. */
export function initCalendar(): void {
  const raw = loadJSON<Record<string, unknown>[]>(STORAGE_KEY, []);
  const events: CalendarEvent[] = raw.map((e) => ({
    id: String(e["id"] ?? Date.now().toString(36)),
    title: String(e["title"] ?? ""),
    date: String(e["date"] ?? ""),
    // Migrate from old format (time → startTime)
    startTime: String(e["startTime"] ?? e["time"] ?? "09:00"),
    endTime: String(e["endTime"] ?? addOneHour(String(e["time"] ?? "09:00"))),
    color: String(e["color"] ?? EVENT_COLORS[0].value),
    description: String(e["description"] ?? ""),
    attendees: Array.isArray(e["attendees"]) ? (e["attendees"] as string[]) : [],
    rsvps: (typeof e["rsvps"] === "object" && e["rsvps"] !== null)
      ? (e["rsvps"] as Record<string, RsvpStatus>)
      : {},
    organizer: e["organizer"] != null ? String(e["organizer"]) : undefined,
    organizerTimezone: e["organizerTimezone"] != null ? String(e["organizerTimezone"]) : undefined,
    recurrence: (typeof e["recurrence"] === "object" && e["recurrence"] !== null)
      ? (e["recurrence"] as RecurrenceValue)
      : undefined,
    cancelled: e["cancelled"] === true,
    cancelledAt: e["cancelledAt"] != null ? String(e["cancelledAt"]) : undefined,
  }));
  setCalendarEvents(events);
}

export function generateEventId(): string {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

/** Create or update a calendar event. */
export function upsertCalendarEvent(event: CalendarEvent): void {
  setCalendarEvents(produce((evts) => {
    const idx = evts.findIndex((e) => e.id === event.id);
    if (idx >= 0) {
      evts[idx] = event;
    } else {
      evts.push(event);
    }
  }));
  persist();
}

/** Delete a calendar event by ID (permanent local removal). */
export function removeCalendarEvent(id: string): void {
  setCalendarEvents((evts) => evts.filter((e) => e.id !== id));
  persist();
}

/**
 * Mark an event as cancelled without deleting it.
 * The event remains visible (with strikethrough) until the user explicitly
 * removes it via removeCalendarEvent.
 */
export function cancelCalendarEvent(id: string): void {
  setCalendarEvents(
    (e) => e.id === id,
    produce((e) => {
      e.cancelled = true;
      e.cancelledAt = todayKey();
    }),
  );
  persist();
}

/** Update RSVP for a node on an event. */
export function updateRsvp(eventId: string, nodeId: string, status: RsvpStatus): void {
  setCalendarEvents(
    (e) => e.id === eventId,
    produce((e) => { e.rsvps[nodeId] = status; }),
  );
  persist();
}

/** Broadcast the event to all attendees via KIND_CALENDAR_EVENT. Non-fatal on error. */
export async function shareEventWithPeers(event: CalendarEvent): Promise<void> {
  if (event.attendees.length === 0) return;
  const payload = JSON.stringify({
    event_id: event.id,
    title: event.title,
    date: event.date,
    start_time: event.startTime,
    end_time: event.endTime,
    description: event.description,
    color: event.color,
    organizer: event.organizer,
  });
  await Promise.allSettled(
    event.attendees.map((peerId) =>
      api.composeMessage({
        recipient: peerId,
        kind: MessageKind.CALENDAR_EVENT,
        plaintext: payload,
      }),
    ),
  );
}

/** Send RSVP to the event organizer via KIND_CALENDAR_RSVP. */
export async function sendRsvpToOrganizer(
  event: CalendarEvent,
  fromNodeId: string,
  status: RsvpStatus,
): Promise<void> {
  if (!event.organizer) return;
  await api.composeMessage({
    recipient: event.organizer,
    kind: MessageKind.CALENDAR_RSVP,
    plaintext: JSON.stringify({
      event_id: event.id,
      responder: fromNodeId,
      status,
    }),
  });
}
