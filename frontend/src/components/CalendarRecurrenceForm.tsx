/**
 * CalendarRecurrenceForm — inline recurrence rule editor.
 *
 * Renders inside CalendarEventModal when the user enables repeat.
 *
 * Supports:
 *   - Frequency: None / Daily / Weekly / Monthly
 *   - Interval (every N days/weeks/months)
 *   - Until-date OR count termination (radio toggle)
 *   - BYDAY checkboxes for weekly recurrence (Mon–Sun)
 */

import { createMemo, For, Show } from "solid-js";

// ── Types ─────────────────────────────────────────────────────────────────

export type RecurrenceFreq = "NONE" | "DAILY" | "WEEKLY" | "MONTHLY";
export type EndKind = "forever" | "until" | "count";

export interface RecurrenceValue {
  freq: RecurrenceFreq;
  interval: number;
  endKind: EndKind;
  until: string;   // YYYY-MM-DD, used when endKind === "until"
  count: number;   // used when endKind === "count"
  byday: string[]; // RFC 5545 two-letter codes: MO,TU,WE,TH,FR,SA,SU
}

export const RECURRENCE_DEFAULT: RecurrenceValue = {
  freq: "NONE",
  interval: 1,
  endKind: "forever",
  until: "",
  count: 10,
  byday: [],
};

// ── Constants ─────────────────────────────────────────────────────────────

const FREQ_OPTIONS: { label: string; value: RecurrenceFreq }[] = [
  { label: "Does not repeat", value: "NONE" },
  { label: "Daily",           value: "DAILY" },
  { label: "Weekly",          value: "WEEKLY" },
  { label: "Monthly",         value: "MONTHLY" },
];

const BYDAY_OPTIONS: { label: string; value: string }[] = [
  { label: "Mon", value: "MO" },
  { label: "Tue", value: "TU" },
  { label: "Wed", value: "WE" },
  { label: "Thu", value: "TH" },
  { label: "Fri", value: "FR" },
  { label: "Sat", value: "SA" },
  { label: "Sun", value: "SU" },
];

// ── Props ─────────────────────────────────────────────────────────────────

interface Props {
  value: () => RecurrenceValue;
  onChange: (v: RecurrenceValue) => void;
}

// ── Component ─────────────────────────────────────────────────────────────

export default function CalendarRecurrenceForm(props: Props) {
  const v = props.value;

  function update(partial: Partial<RecurrenceValue>) {
    props.onChange({ ...v(), ...partial });
  }

  const intervalLabel = createMemo(() => {
    switch (v().freq) {
      case "DAILY":   return "day(s)";
      case "WEEKLY":  return "week(s)";
      case "MONTHLY": return "month(s)";
      default:        return "";
    }
  });

  const isWeekly  = () => v().freq === "WEEKLY";
  const hasRepeat = () => v().freq !== "NONE";

  function toggleByday(code: string) {
    const current = v().byday;
    const next = current.includes(code)
      ? current.filter((d) => d !== code)
      : [...current, code];
    update({ byday: next });
  }

  return (
    <div class="cal-recurrence-form">
      {/* Frequency selector */}
      <div class="cal-recurrence-row">
        <label class="text-xs text-muted" style={{ "min-width": "56px" }}>Repeat</label>
        <select
          class="input"
          style={{ flex: 1 }}
          value={v().freq}
          onChange={(e) => update({ freq: e.currentTarget.value as RecurrenceFreq })}
        >
          <For each={FREQ_OPTIONS}>
            {(opt) => <option value={opt.value}>{opt.label}</option>}
          </For>
        </select>
      </div>

      <Show when={hasRepeat()}>
        {/* Interval */}
        <div class="cal-recurrence-row">
          <label class="text-xs text-muted" style={{ "min-width": "56px" }}>Every</label>
          <input
            type="number"
            class="input"
            min={1}
            max={99}
            style={{ width: "64px", flex: "none" }}
            value={v().interval}
            onInput={(e) => {
              const n = parseInt(e.currentTarget.value, 10);
              if (!isNaN(n) && n >= 1) update({ interval: n });
            }}
          />
          <span class="text-xs text-muted" style={{ "margin-left": "6px" }}>
            {intervalLabel()}
          </span>
        </div>

        {/* BYDAY checkboxes — weekly only */}
        <Show when={isWeekly()}>
          <div class="cal-recurrence-row" style={{ "flex-wrap": "wrap", gap: "4px" }}>
            <span class="text-xs text-muted" style={{ "min-width": "56px" }}>On</span>
            <For each={BYDAY_OPTIONS}>
              {(day) => {
                const active = () => v().byday.includes(day.value);
                return (
                  <button
                    type="button"
                    class={`cal-byday-btn ${active() ? "active" : ""}`}
                    onClick={() => toggleByday(day.value)}
                    aria-pressed={active()}
                    title={day.label}
                  >
                    {day.label}
                  </button>
                );
              }}
            </For>
          </div>
        </Show>

        {/* End condition */}
        <div class="cal-recurrence-row" style={{ "flex-direction": "column", gap: "6px" }}>
          <span class="text-xs text-muted">Ends</span>

          {/* Forever */}
          <label class="cal-recurrence-end-opt">
            <input
              type="radio"
              name="cal-end-kind"
              checked={v().endKind === "forever"}
              onChange={() => update({ endKind: "forever" })}
            />
            <span class="text-xs">Never</span>
          </label>

          {/* Until date */}
          <label class="cal-recurrence-end-opt">
            <input
              type="radio"
              name="cal-end-kind"
              checked={v().endKind === "until"}
              onChange={() => update({ endKind: "until" })}
            />
            <span class="text-xs" style={{ "margin-right": "6px" }}>On</span>
            <input
              type="date"
              class="input"
              style={{ flex: "1 1 120px" }}
              disabled={v().endKind !== "until"}
              value={v().until}
              onInput={(e) => update({ until: e.currentTarget.value })}
              onClick={() => update({ endKind: "until" })}
            />
          </label>

          {/* Count */}
          <label class="cal-recurrence-end-opt">
            <input
              type="radio"
              name="cal-end-kind"
              checked={v().endKind === "count"}
              onChange={() => update({ endKind: "count" })}
            />
            <span class="text-xs" style={{ "margin-right": "6px" }}>After</span>
            <input
              type="number"
              class="input"
              min={1}
              max={999}
              style={{ width: "60px", flex: "none" }}
              disabled={v().endKind !== "count"}
              value={v().count}
              onInput={(e) => {
                const n = parseInt(e.currentTarget.value, 10);
                if (!isNaN(n) && n >= 1) update({ count: n });
              }}
              onClick={() => update({ endKind: "count" })}
            />
            <span class="text-xs" style={{ "margin-left": "6px" }}>occurrences</span>
          </label>
        </div>
      </Show>
    </div>
  );
}
