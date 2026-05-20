/**
 * CalendarMonthView — month grid with event dots and a sidebar detail panel.
 * Reads from the global calendar store (useCalendarApi).
 */

import { createSignal, createMemo, For, Show } from "solid-js";
import {
  IconChevronRight,
  IconPlus,
  IconClock,
  IconTrash,
} from "./Icons";
import {
  calendarEvents,
  MONTH_NAMES,
  DAY_NAMES_SHORT,
  daysInMonth,
  startDayOfMonth,
  isToday,
  toDateKey,
  formatDateDisplay,
  formatTimeDisplay,
  type CalendarEvent,
  type ModalDefaults,
} from "../stores/useCalendarApi";

// ── Helpers ───────────────────────────────────────────────────────────────

function dateKey(y: number, m: number, d: number): string {
  return `${y}-${String(m + 1).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
}

// ── Props ─────────────────────────────────────────────────────────────────

interface Props {
  selectedDate: () => string;
  onSelect: (date: string) => void;
  onOpenModal: (defaults?: ModalDefaults) => void;
  onEditEvent: (event: CalendarEvent) => void;
}

// ── Component ─────────────────────────────────────────────────────────────

export default function CalendarMonthView(props: Props) {
  const today = new Date();
  const [year, setYear] = createSignal(today.getFullYear());
  const [month, setMonth] = createSignal(today.getMonth());

  const calendarDays = createMemo(() => {
    const y = year();
    const m = month();
    const totalDays = daysInMonth(y, m);
    const startDay = startDayOfMonth(y, m);
    const cells: Array<{ day: number; dateKey: string; currentMonth: boolean }> = [];

    // Previous month fill
    const prevMonth = m === 0 ? 11 : m - 1;
    const prevYear = m === 0 ? y - 1 : y;
    const prevDays = daysInMonth(prevYear, prevMonth);
    for (let i = startDay - 1; i >= 0; i--) {
      const d = prevDays - i;
      cells.push({ day: d, dateKey: dateKey(prevYear, prevMonth, d), currentMonth: false });
    }

    // Current month
    for (let d = 1; d <= totalDays; d++) {
      cells.push({ day: d, dateKey: dateKey(y, m, d), currentMonth: true });
    }

    // Next month fill (6 rows = 42 cells)
    const nextMonth = m === 11 ? 0 : m + 1;
    const nextYear = m === 11 ? y + 1 : y;
    const remaining = 42 - cells.length;
    for (let d = 1; d <= remaining; d++) {
      cells.push({ day: d, dateKey: dateKey(nextYear, nextMonth, d), currentMonth: false });
    }

    return cells;
  });

  const eventsForDate = (dk: string) =>
    calendarEvents.filter((e) => e.date === dk);

  const selectedDateEvents = createMemo(() => {
    const sel = props.selectedDate();
    return sel ? eventsForDate(sel).sort((a, b) => a.startTime.localeCompare(b.startTime)) : [];
  });

  const upcomingEvents = createMemo(() => {
    const todayDt = new Date();
    const todayDk = toDateKey(todayDt);
    const sevenLater = new Date(todayDt);
    sevenLater.setDate(sevenLater.getDate() + 7);
    const endDk = toDateKey(sevenLater);
    return [...calendarEvents]
      .filter((e) => e.date >= todayDk && e.date <= endDk)
      .sort((a, b) => a.date.localeCompare(b.date) || a.startTime.localeCompare(b.startTime));
  });

  function goPrevMonth() {
    if (month() === 0) { setMonth(11); setYear(year() - 1); }
    else { setMonth(month() - 1); }
  }

  function goNextMonth() {
    if (month() === 11) { setMonth(0); setYear(year() + 1); }
    else { setMonth(month() + 1); }
  }

  function goToday() {
    const now = new Date();
    setYear(now.getFullYear());
    setMonth(now.getMonth());
    props.onSelect(toDateKey(now));
  }

  return (
    <div class="cal-layout">
      {/* Main grid */}
      <div class="cal-main">
        {/* Navigation */}
        <div class="cal-nav">
          <button class="cal-nav-btn" onClick={goPrevMonth} aria-label="Previous month">
            <IconChevronRight size={16} style={{ transform: "rotate(180deg)" }} />
          </button>
          <div class="cal-month-title">{MONTH_NAMES[month()]} {year()}</div>
          <button class="cal-nav-btn" onClick={goNextMonth} aria-label="Next month">
            <IconChevronRight size={16} />
          </button>
          <button class="cal-today-btn" onClick={goToday}>Today</button>
        </div>

        {/* Day headers */}
        <div class="cal-grid cal-header-row">
          <For each={DAY_NAMES_SHORT}>{(d) => <div class="cal-day-header">{d}</div>}</For>
        </div>

        {/* Day cells */}
        <div class="cal-grid">
          <For each={calendarDays()}>
            {(cell) => {
              const dayEvts = () => eventsForDate(cell.dateKey);
              const selected = () => props.selectedDate() === cell.dateKey;
              return (
                <button
                  class={`cal-cell ${!cell.currentMonth ? "cal-cell-other" : ""} ${isToday(cell.dateKey) ? "cal-cell-today" : ""} ${selected() ? "cal-cell-selected" : ""}`}
                  onClick={() => props.onSelect(cell.dateKey)}
                  onDblClick={() => props.onOpenModal({ date: cell.dateKey })}
                  aria-label={`${cell.day}, ${dayEvts().length} event${dayEvts().length !== 1 ? "s" : ""}`}
                >
                  <span class="cal-cell-day">{cell.day}</span>
                  <Show when={dayEvts().length > 0}>
                    <div class="cal-cell-dots">
                      <For each={dayEvts().slice(0, 3)}>
                        {(evt) => <span class="cal-cell-dot" style={{ background: evt.color }} />}
                      </For>
                      <Show when={dayEvts().length > 3}>
                        <span class="cal-cell-more">+{dayEvts().length - 3}</span>
                      </Show>
                    </div>
                  </Show>
                </button>
              );
            }}
          </For>
        </div>
      </div>

      {/* Sidebar */}
      <div class="cal-sidebar">
        {/* Selected date panel */}
        <Show when={props.selectedDate()}>
          <div class="card cal-detail-card">
            <div class="card-header" style={{ display: "flex", "justify-content": "space-between", "align-items": "center" }}>
              <span class="text-sm font-medium">{formatDateDisplay(props.selectedDate())}</span>
              <button
                class="btn btn-secondary btn-sm"
                onClick={() => props.onOpenModal({ date: props.selectedDate() })}
                style={{ display: "inline-flex", "align-items": "center", gap: "4px" }}
              >
                <IconPlus size={12} /> Add
              </button>
            </div>

            <Show
              when={selectedDateEvents().length > 0}
              fallback={
                <div class="text-sm text-muted" style={{ padding: "16px 0", "text-align": "center" }}>
                  No events — double-click a day to add one
                </div>
              }
            >
              <div class="cal-event-list">
                <For each={selectedDateEvents()}>
                  {(evt) => (
                    <div
                      class="cal-event-item cal-event-clickable"
                      onClick={() => props.onEditEvent(evt)}
                    >
                      <span class="cal-event-color" style={{ background: evt.color }} />
                      <div style={{ flex: 1, "min-width": 0 }}>
                        <div
                          class="text-sm font-medium truncate"
                          style={evt.cancelled ? { "text-decoration": "line-through", opacity: "0.6" } : {}}
                        >
                          {evt.title}
                        </div>
                        <Show when={evt.cancelled}>
                          <div class="text-xs" style={{ color: "var(--error)" }}>Cancelled</div>
                        </Show>
                        <Show when={!evt.cancelled}>
                          <div class="text-xs text-muted" style={{ display: "flex", "align-items": "center", gap: "4px" }}>
                            <IconClock size={10} /> {formatTimeDisplay(evt.startTime)}
                            <Show when={evt.endTime}> – {formatTimeDisplay(evt.endTime)}</Show>
                          </div>
                          <Show when={evt.description}>
                            <div class="text-xs text-secondary" style={{ "margin-top": "2px" }}>{evt.description}</div>
                          </Show>
                          <Show when={evt.attendees.length > 0}>
                            <div class="text-xs text-muted" style={{ "margin-top": "2px" }}>
                              {evt.attendees.length} attendee{evt.attendees.length !== 1 ? "s" : ""}
                            </div>
                          </Show>
                        </Show>
                      </div>
                    </div>
                  )}
                </For>
              </div>
            </Show>
          </div>
        </Show>

        {/* Upcoming */}
        <div class="card">
          <div class="card-header" style={{ display: "flex", "align-items": "center", gap: "6px" }}>
            <IconClock size={14} /> Upcoming (7 days)
          </div>
          <Show
            when={upcomingEvents().length > 0}
            fallback={
              <div class="text-sm text-muted" style={{ padding: "16px 0", "text-align": "center" }}>
                No upcoming events
              </div>
            }
          >
            <div class="cal-event-list">
              <For each={upcomingEvents()}>
                {(evt) => (
                  <div
                    class="cal-event-item cal-event-clickable"
                    onClick={() => props.onEditEvent(evt)}
                  >
                    <span class="cal-event-color" style={{ background: evt.color }} />
                    <div style={{ flex: 1, "min-width": 0 }}>
                      <div
                        class="text-sm font-medium truncate"
                        style={evt.cancelled ? { "text-decoration": "line-through", opacity: "0.6" } : {}}
                      >
                        {evt.title}
                      </div>
                      <Show when={evt.cancelled}>
                        <div class="text-xs" style={{ color: "var(--error)" }}>Cancelled</div>
                      </Show>
                      <Show when={!evt.cancelled}>
                        <div class="text-xs text-muted">
                          {new Date(evt.date + "T00:00").toLocaleDateString([], { weekday: "short", month: "short", day: "numeric" })}
                          {" at "}{formatTimeDisplay(evt.startTime)}
                        </div>
                      </Show>
                    </div>
                    <IconTrash
                      size={12}
                      class="cal-event-delete"
                      style={{ cursor: "pointer", opacity: "0.5" }}
                    />
                  </div>
                )}
              </For>
            </div>
          </Show>
        </div>
      </div>
    </div>
  );
}
