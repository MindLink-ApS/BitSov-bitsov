/**
 * CalendarDayView — single-day hourly agenda.
 * Clicking an empty hour slot opens the event modal pre-filled with that time.
 */

import { createMemo, For, Show, onMount } from "solid-js";
import { IconChevronRight } from "./Icons";
import {
  calendarEvents,
  toDateKey,
  isToday,
  formatDateDisplay,
  formatTimeDisplay,
  localEventTime,
  organizerTzTooltip,
  type CalendarEvent,
  type ModalDefaults,
} from "../stores/useCalendarApi";

// ── Constants ─────────────────────────────────────────────────────────────

const SLOT_H = 60;
const HOURS = Array.from({ length: 24 }, (_, i) => i);

// ── Helpers ───────────────────────────────────────────────────────────────

function eventTopPx(evt: CalendarEvent): number {
  const [h, m] = evt.startTime.split(":").map(Number);
  return h * SLOT_H + m;
}

function eventHeightPx(evt: CalendarEvent): number {
  const [sh, sm] = evt.startTime.split(":").map(Number);
  const [eh, em] = evt.endTime.split(":").map(Number);
  return Math.max(20, (eh * 60 + em) - (sh * 60 + sm));
}

function nowPx(): number {
  const now = new Date();
  return now.getHours() * SLOT_H + now.getMinutes();
}

function padHH(n: number): string {
  return String(n).padStart(2, "0");
}

function prevDay(dateKey: string): string {
  const [y, m, d] = dateKey.split("-").map(Number);
  const dt = new Date(y, m - 1, d);
  dt.setDate(dt.getDate() - 1);
  return toDateKey(dt);
}

function nextDay(dateKey: string): string {
  const [y, m, d] = dateKey.split("-").map(Number);
  const dt = new Date(y, m - 1, d);
  dt.setDate(dt.getDate() + 1);
  return toDateKey(dt);
}

// ── Props ─────────────────────────────────────────────────────────────────

interface Props {
  selectedDate: () => string;
  onNavigate: (dateKey: string) => void;
  onOpenModal: (defaults?: ModalDefaults) => void;
  onEditEvent: (event: CalendarEvent) => void;
}

// ── Component ─────────────────────────────────────────────────────────────

export default function CalendarDayView(props: Props) {
  let bodyRef: HTMLDivElement | undefined;

  onMount(() => {
    if (bodyRef) {
      bodyRef.scrollTop = 7 * SLOT_H - 20;
    }
  });

  const dayEvents = createMemo(() =>
    calendarEvents
      .filter((e) => e.date === props.selectedDate())
      .sort((a, b) => a.startTime.localeCompare(b.startTime)),
  );

  function handleSlotClick(hour: number) {
    props.onOpenModal({
      date: props.selectedDate(),
      startTime: `${padHH(hour)}:00`,
      endTime: `${padHH(Math.min(hour + 1, 23))}:00`,
    });
  }

  return (
    <div class="cal-day-wrap">
      {/* Navigation */}
      <div class="cal-week-nav">
        <button
          class="cal-nav-btn"
          onClick={() => props.onNavigate(prevDay(props.selectedDate()))}
          aria-label="Previous day"
        >
          <IconChevronRight size={16} style={{ transform: "rotate(180deg)" }} />
        </button>
        <div class="cal-month-title">
          {formatDateDisplay(props.selectedDate())}
        </div>
        <button
          class="cal-nav-btn"
          onClick={() => props.onNavigate(nextDay(props.selectedDate()))}
          aria-label="Next day"
        >
          <IconChevronRight size={16} />
        </button>
        <button class="cal-today-btn" onClick={() => props.onNavigate(toDateKey(new Date()))}>
          Today
        </button>
      </div>

      {/* Day timeline */}
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

        {/* Day column */}
        <div class="cal-week-day-col" style={{ flex: 1 }}>
          {/* Clickable hour slots */}
          <For each={HOURS}>
            {(h) => (
              <div
                class="cal-week-slot"
                onClick={() => handleSlotClick(h)}
                title={`Add event at ${padHH(h)}:00`}
              />
            )}
          </For>

          {/* Events */}
          <For each={dayEvents()}>
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
                    {evt.cancelled
                      ? "Cancelled"
                      : `${formatTimeDisplay(localEventTime(evt, evt.startTime))} – ${formatTimeDisplay(localEventTime(evt, evt.endTime))}`}
                  </span>
                </Show>
              </div>
            )}
          </For>

          {/* Current time line */}
          <Show when={isToday(props.selectedDate())}>
            <div class="cal-week-now-line" style={{ top: `${nowPx()}px` }}>
              <div class="cal-week-now-dot" />
            </div>
          </Show>
        </div>
      </div>
    </div>
  );
}
