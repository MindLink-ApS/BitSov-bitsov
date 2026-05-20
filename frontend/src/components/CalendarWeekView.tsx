/**
 * CalendarWeekView — 7-column × 24-row time grid with drag-to-create.
 * Each column is a day; each row is one hour. Dragging across rows
 * pre-fills start/end time in the event modal.
 */

import { createSignal, createMemo, For, Show, onMount } from "solid-js";
import { IconChevronRight } from "./Icons";
import {
  calendarEvents,
  weekMonday,
  toDateKey,
  isToday,
  DAY_NAMES_SHORT,
  formatTimeDisplay,
  localEventTime,
  organizerTzTooltip,
  type CalendarEvent,
  type ModalDefaults,
} from "../stores/useCalendarApi";

// ── Constants ─────────────────────────────────────────────────────────────

const SLOT_H = 60; // px per hour
const HOURS = Array.from({ length: 24 }, (_, i) => i);

// ── Props ─────────────────────────────────────────────────────────────────

interface Props {
  selectedDate: () => string;
  onNavigate: (dateKey: string) => void;
  onOpenModal: (defaults?: ModalDefaults) => void;
  onEditEvent: (event: CalendarEvent) => void;
}

// ── Types ─────────────────────────────────────────────────────────────────

interface WeekDay {
  dateKey: string;
  label: string;
  dayNum: number;
  isToday: boolean;
}

interface DragState {
  col: number;
  startHour: number;
  endHour: number;
}

// ── Helpers ───────────────────────────────────────────────────────────────

function eventTopPx(evt: CalendarEvent): number {
  const [h, m] = evt.startTime.split(":").map(Number);
  return h * SLOT_H + m;
}

function eventHeightPx(evt: CalendarEvent): number {
  const [sh, sm] = evt.startTime.split(":").map(Number);
  const [eh, em] = evt.endTime.split(":").map(Number);
  const durationMin = (eh * 60 + em) - (sh * 60 + sm);
  return Math.max(20, durationMin);
}

function nowPx(): number {
  const now = new Date();
  return now.getHours() * SLOT_H + now.getMinutes();
}

function padHH(n: number): string {
  return String(n).padStart(2, "0");
}

// ── Component ─────────────────────────────────────────────────────────────

export default function CalendarWeekView(props: Props) {
  let bodyRef: HTMLDivElement | undefined;
  const colRefs: (HTMLDivElement | undefined)[] = Array(7).fill(undefined);
  const [drag, setDrag] = createSignal<DragState | null>(null);

  onMount(() => {
    // Scroll to 7 AM on mount
    if (bodyRef) {
      bodyRef.scrollTop = 7 * SLOT_H - 20;
    }
  });

  const weekDays = createMemo<WeekDay[]>(() => {
    const monday = weekMonday(props.selectedDate());
    return Array.from({ length: 7 }, (_, i) => {
      const date = new Date(monday);
      date.setDate(monday.getDate() + i);
      return {
        dateKey: toDateKey(date),
        label: `${DAY_NAMES_SHORT[i]} ${date.getDate()}`,
        dayNum: date.getDate(),
        isToday: isToday(toDateKey(date)),
      };
    });
  });

  const eventsForDate = (dateKey: string) =>
    calendarEvents.filter((e) => e.date === dateKey);

  function goPrevWeek() {
    const monday = weekMonday(props.selectedDate());
    monday.setDate(monday.getDate() - 7);
    props.onNavigate(toDateKey(monday));
  }

  function goNextWeek() {
    const monday = weekMonday(props.selectedDate());
    monday.setDate(monday.getDate() + 7);
    props.onNavigate(toDateKey(monday));
  }

  function goThisWeek() {
    props.onNavigate(toDateKey(new Date()));
  }

  // ── Drag-to-create ────────────────────────────────────────────────────

  function hourFromPointer(e: PointerEvent, col: number): number {
    const el = colRefs[col];
    if (!el) return 0;
    const rect = el.getBoundingClientRect();
    const y = Math.max(0, e.clientY - rect.top);
    return Math.min(23, Math.floor(y / SLOT_H));
  }

  function onColPointerDown(col: number, e: PointerEvent) {
    if (e.button !== 0) return;
    const el = colRefs[col];
    if (!el) return;
    el.setPointerCapture(e.pointerId);
    const h = hourFromPointer(e, col);
    setDrag({ col, startHour: h, endHour: h });
    e.preventDefault();
  }

  function onColPointerMove(col: number, e: PointerEvent) {
    const d = drag();
    if (!d || d.col !== col) return;
    const h = hourFromPointer(e, col);
    if (h !== d.endHour) setDrag({ ...d, endHour: h });
  }

  function onColPointerUp(col: number) {
    const d = drag();
    if (!d || d.col !== col) return;
    const s = Math.min(d.startHour, d.endHour);
    const e = Math.max(d.startHour, d.endHour) + 1;
    const day = weekDays()[col];
    setDrag(null);
    if (day) {
      props.onOpenModal({
        date: day.dateKey,
        startTime: `${padHH(s)}:00`,
        endTime: `${padHH(Math.min(e, 23))}:00`,
      });
    }
  }

  function isDragHighlight(col: number, hour: number): boolean {
    const d = drag();
    if (!d || d.col !== col) return false;
    const s = Math.min(d.startHour, d.endHour);
    const e = Math.max(d.startHour, d.endHour);
    return hour >= s && hour <= e;
  }

  return (
    <div class="cal-week-wrap">
      {/* Navigation */}
      <div class="cal-week-nav">
        <button class="cal-nav-btn" onClick={goPrevWeek} aria-label="Previous week">
          <IconChevronRight size={16} style={{ transform: "rotate(180deg)" }} />
        </button>
        <div class="cal-month-title">
          Week of {(() => {
            const monday = weekMonday(props.selectedDate());
            return monday.toLocaleDateString([], { month: "long", day: "numeric", year: "numeric" });
          })()}
        </div>
        <button class="cal-nav-btn" onClick={goNextWeek} aria-label="Next week">
          <IconChevronRight size={16} />
        </button>
        <button class="cal-today-btn" onClick={goThisWeek}>This week</button>
      </div>

      {/* Day headers */}
      <div class="cal-week-header">
        <div class="cal-week-th-time" />
        <For each={weekDays()}>
          {(day) => (
            <div class={`cal-week-th-day ${day.isToday ? "cal-week-th-today" : ""}`}>
              {day.label}
            </div>
          )}
        </For>
      </div>

      {/* Scrollable body */}
      <div class="cal-week-body" ref={bodyRef}>
        {/* Time labels */}
        <div class="cal-week-time-col">
          <For each={HOURS}>
            {(h) => (
              <div class="cal-week-time-label">
                {h === 0 ? "" : `${padHH(h)}:00`}
              </div>
            )}
          </For>
        </div>

        {/* Day columns */}
        <For each={weekDays()}>
          {(day, colIdx) => (
            <div
              class="cal-week-day-col"
              ref={(el) => { colRefs[colIdx()] = el; }}
              onPointerDown={(e) => onColPointerDown(colIdx(), e)}
              onPointerMove={(e) => onColPointerMove(colIdx(), e)}
              onPointerUp={() => onColPointerUp(colIdx())}
            >
              {/* Hour slots */}
              <For each={HOURS}>
                {(h) => (
                  <div
                    class={`cal-week-slot ${isDragHighlight(colIdx(), h) ? "cal-week-slot-drag" : ""}`}
                  />
                )}
              </For>

              {/* Events overlaid */}
              <For each={eventsForDate(day.dateKey)}>
                {(evt) => (
                  <div
                    class="cal-week-event"
                    style={{
                      top: `${eventTopPx(evt)}px`,
                      height: `${eventHeightPx(evt)}px`,
                      background: evt.cancelled ? "rgba(100,100,100,0.35)" : evt.color,
                    }}
                    onClick={(e) => { e.stopPropagation(); props.onEditEvent(evt); }}
                  >
                    <span
                      class="cal-week-event-title"
                      style={evt.cancelled ? { "text-decoration": "line-through" } : {}}
                    >
                      {evt.title}
                    </span>
                    <Show when={eventHeightPx(evt) >= 40}>
                      <span
                        class="cal-week-event-time"
                        title={organizerTzTooltip(evt, evt.startTime) ?? undefined}
                      >
                        {evt.cancelled ? "Cancelled" : formatTimeDisplay(localEventTime(evt, evt.startTime))}
                      </span>
                    </Show>
                  </div>
                )}
              </For>

              {/* Current time indicator */}
              <Show when={day.isToday}>
                <div class="cal-week-now-line" style={{ top: `${nowPx()}px` }}>
                  <div class="cal-week-now-dot" />
                </div>
              </Show>
            </div>
          )}
        </For>
      </div>
    </div>
  );
}
