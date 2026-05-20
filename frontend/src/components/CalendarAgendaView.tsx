/**
 * CalendarAgendaView — upcoming events list grouped by date (next 90 days).
 */

import { createMemo, For, Show } from "solid-js";
import { IconPlus, IconClock } from "./Icons";
import {
  calendarEvents,
  toDateKey,
  isToday,
  formatTimeDisplay,
  localEventTime,
  organizerTzTooltip,
  type CalendarEvent,
} from "../stores/useCalendarApi";

// ── Props ─────────────────────────────────────────────────────────────────

interface Props {
  onOpenModal: () => void;
  onEditEvent: (event: CalendarEvent) => void;
}

// ── Helpers ───────────────────────────────────────────────────────────────

function formatAgendaDate(dateKey: string): string {
  const [y, m, d] = dateKey.split("-").map(Number);
  const dt = new Date(y, m - 1, d);
  if (isToday(dateKey)) return "Today";
  return dt.toLocaleDateString([], { weekday: "long", month: "long", day: "numeric" });
}

// ── Component ─────────────────────────────────────────────────────────────

export default function CalendarAgendaView(props: Props) {
  const grouped = createMemo(() => {
    const today = new Date();
    const todayKey = toDateKey(today);
    const ninetyLater = new Date(today);
    ninetyLater.setDate(today.getDate() + 90);
    const endKey = toDateKey(ninetyLater);

    const upcoming = [...calendarEvents]
      .filter((e) => e.date >= todayKey && e.date <= endKey)
      .sort((a, b) => a.date.localeCompare(b.date) || a.startTime.localeCompare(b.startTime));

    const byDate = new Map<string, CalendarEvent[]>();
    for (const evt of upcoming) {
      const existing = byDate.get(evt.date) ?? [];
      existing.push(evt);
      byDate.set(evt.date, existing);
    }
    return [...byDate.entries()];
  });

  return (
    <div class="cal-agenda-wrap">
      <div style={{ display: "flex", "align-items": "center", "justify-content": "space-between", "margin-bottom": "16px" }}>
        <h3 class="text-sm font-medium" style={{ color: "var(--text-secondary)" }}>
          Upcoming events (next 90 days)
        </h3>
        <button
          class="btn btn-secondary btn-sm"
          onClick={props.onOpenModal}
          style={{ display: "inline-flex", "align-items": "center", gap: "4px" }}
        >
          <IconPlus size={12} /> New event
        </button>
      </div>

      <Show
        when={grouped().length > 0}
        fallback={
          <div class="cal-agenda-empty">
            <IconClock size={32} style={{ opacity: "0.3", "margin-bottom": "12px" }} />
            <div>No upcoming events in the next 90 days.</div>
            <div style={{ "margin-top": "8px" }}>
              <button class="btn btn-primary btn-sm" onClick={props.onOpenModal}>
                <IconPlus size={12} /> Create event
              </button>
            </div>
          </div>
        }
      >
        <For each={grouped()}>
          {([dateKey, events]) => (
            <div class="cal-agenda-date-group">
              <div class={`cal-agenda-date-label ${isToday(dateKey) ? "cal-agenda-date-today" : ""}`}>
                {formatAgendaDate(dateKey)}
              </div>
              <For each={events}>
                {(evt) => (
                  <div
                    class="cal-agenda-event"
                    onClick={() => props.onEditEvent(evt)}
                  >
                    <span
                      class="cal-event-color"
                      style={{ background: evt.color, "min-height": "36px", "align-self": "stretch" }}
                    />
                    <div class="cal-agenda-time">
                      <span title={organizerTzTooltip(evt, evt.startTime) ?? undefined}>
                        {formatTimeDisplay(localEventTime(evt, evt.startTime))}
                      </span>
                      <Show when={evt.endTime && evt.endTime !== evt.startTime}>
                        <br />
                        <span
                          style={{ "font-size": "0.65rem" }}
                          title={organizerTzTooltip(evt, evt.endTime) ?? undefined}
                        >
                          → {formatTimeDisplay(localEventTime(evt, evt.endTime))}
                        </span>
                      </Show>
                    </div>
                    <div style={{ flex: 1, "min-width": 0 }}>
                      <div
                        class="cal-agenda-title"
                        style={evt.cancelled ? { "text-decoration": "line-through", opacity: "0.6" } : {}}
                      >
                        {evt.title}
                      </div>
                      <Show when={evt.cancelled}>
                        <div class="text-xs" style={{ color: "var(--error)", "margin-top": "2px" }}>
                          Cancelled
                        </div>
                      </Show>
                      <Show when={evt.description && !evt.cancelled}>
                        <div class="text-xs text-muted" style={{ "margin-top": "2px" }}>
                          {evt.description}
                        </div>
                      </Show>
                      <Show when={evt.attendees.length > 0 && !evt.cancelled}>
                        <div class="text-xs text-muted" style={{ "margin-top": "2px" }}>
                          {evt.attendees.length} attendee{evt.attendees.length !== 1 ? "s" : ""}
                        </div>
                      </Show>
                    </div>
                  </div>
                )}
              </For>
            </div>
          )}
        </For>
      </Show>
    </div>
  );
}
