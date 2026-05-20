/**
 * CalendarView — container with view switcher (Month / Week / Day / Agenda)
 * and timezone header. Delegates rendering to the appropriate sub-view.
 * Event modal is managed here and shared across all views.
 */

import { createSignal, onMount } from "solid-js";
import {
  initCalendar,
  todayKey,
  type CalendarEvent,
  type ModalDefaults,
} from "../stores/useCalendarApi";
import CalendarMonthView from "./CalendarMonthView";
import CalendarWeekView from "./CalendarWeekView";
import CalendarDayView from "./CalendarDayView";
import CalendarAgendaView from "./CalendarAgendaView";
import CalendarEventModal from "./CalendarEventModal";
import CalendarFreeBusyModal from "./CalendarFreeBusyModal";
import { IconCalendar, IconClock } from "./Icons";

// ── Types ─────────────────────────────────────────────────────────────────

type ViewMode = "month" | "week" | "day" | "agenda";

const VIEW_TABS: { id: ViewMode; label: string }[] = [
  { id: "month",  label: "Month" },
  { id: "week",   label: "Week" },
  { id: "day",    label: "Day" },
  { id: "agenda", label: "Agenda" },
];

// ── Timezone helper ───────────────────────────────────────────────────────

function tzBadge(): string {
  try {
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    return `Shown in ${tz}`;
  } catch {
    return "Local time";
  }
}

// ── Component ─────────────────────────────────────────────────────────────

export default function CalendarView() {
  const [view, setView] = createSignal<ViewMode>("month");
  const [selectedDate, setSelectedDate] = createSignal(todayKey());
  const [showModal, setShowModal] = createSignal(false);
  const [editingEvent, setEditingEvent] = createSignal<CalendarEvent | null>(null);
  const [modalDefaults, setModalDefaults] = createSignal<ModalDefaults>({});
  const [showFreeBusy, setShowFreeBusy] = createSignal(false);

  onMount(() => {
    initCalendar();
  });

  function openModal(defaults?: ModalDefaults, event?: CalendarEvent) {
    setModalDefaults(defaults ?? {});
    setEditingEvent(event ?? null);
    setShowModal(true);
  }

  function closeModal() {
    setShowModal(false);
    setEditingEvent(null);
    setModalDefaults({});
  }

  return (
    <div class="page" style={{ "max-width": "var(--content-max)" }}>
      {/* Page header */}
      <div class="page-header">
        <h2 class="page-title" style={{ display: "flex", "align-items": "center", gap: "8px" }}>
          <IconCalendar size={20} />
          Calendar
          <span class="preview-badge">Preview</span>
        </h2>
        <div style={{ display: "flex", "align-items": "center", gap: "12px", "flex-wrap": "wrap" }}>
          <span class="cal-tz-badge">{tzBadge()}</span>
          <button
            class="btn btn-ghost btn-sm"
            onClick={() => setShowFreeBusy(true)}
            style={{ display: "inline-flex", "align-items": "center", gap: "4px", "font-size": "12px" }}
            title="Check peer availability"
          >
            <IconClock size={13} />
            Availability
          </button>
          <div class="cal-view-tabs">
            {VIEW_TABS.map(({ id, label }) => (
              <button
                class={`cal-view-tab ${view() === id ? "cal-view-tab-active" : ""}`}
                onClick={() => setView(id)}
                aria-pressed={view() === id}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Views */}
      {view() === "month" && (
        <CalendarMonthView
          selectedDate={selectedDate}
          onSelect={setSelectedDate}
          onOpenModal={(defaults) => openModal(defaults)}
          onEditEvent={(evt) => openModal(undefined, evt)}
        />
      )}
      {view() === "week" && (
        <CalendarWeekView
          selectedDate={selectedDate}
          onNavigate={(dk) => setSelectedDate(dk)}
          onOpenModal={(defaults) => openModal(defaults)}
          onEditEvent={(evt) => openModal(undefined, evt)}
        />
      )}
      {view() === "day" && (
        <CalendarDayView
          selectedDate={selectedDate}
          onNavigate={(dk) => setSelectedDate(dk)}
          onOpenModal={(defaults) => openModal(defaults)}
          onEditEvent={(evt) => openModal(undefined, evt)}
        />
      )}
      {view() === "agenda" && (
        <CalendarAgendaView
          onOpenModal={() => openModal()}
          onEditEvent={(evt) => openModal(undefined, evt)}
        />
      )}

      {/* Event modal — shared across all views */}
      <CalendarEventModal
        show={showModal}
        event={editingEvent}
        defaults={modalDefaults}
        onClose={closeModal}
      />

      {/* Free/busy availability modal */}
      <CalendarFreeBusyModal
        show={showFreeBusy}
        onClose={() => setShowFreeBusy(false)}
      />
    </div>
  );
}
