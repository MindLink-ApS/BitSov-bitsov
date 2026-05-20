//! Calendar domain types — CalendarEvent, RsvpStatus, RRule, and recurrence expansion.
//!
//! These are the in-memory / API-facing types. The wire payload (inside the
//! UKM envelope ciphertext) lives in `payloads::calendar`.
//!
//! ## DST-safe recurrence
//! `expand_occurrences` advances in *wall-clock* (naive-local) space and then
//! re-localises via `chrono_tz`. This means a 09:00 weekly event remains at
//! 09:00 local time after spring-forward instead of shifting by ±1 hour.

use std::collections::HashSet;

use chrono::{Datelike, DateTime, Duration, NaiveDate, NaiveDateTime, TimeZone, Weekday};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};

// ── RRule ───────────────────────────────────────────────────────────────────

/// Recurrence frequency for calendar events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum Freq {
    #[default]
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

/// RFC 5545-inspired recurrence rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RRule {
    /// Recurrence frequency.
    pub freq: Freq,
    /// Interval between recurrences (default 1).
    #[serde(default = "default_interval")]
    pub interval: u32,
    /// End date as Unix timestamp milliseconds (inclusive). None = no end.
    #[serde(default)]
    pub until: Option<u64>,
    /// Maximum number of occurrences. None = unlimited.
    #[serde(default)]
    pub count: Option<u32>,
    /// Days of the week (RFC 5545: MO,TU,WE,TH,FR,SA,SU). Empty = no constraint.
    #[serde(default)]
    pub byday: Vec<String>,
    /// Days of the month (RFC 5545 BYMONTHDAY). Negative values count from end:
    /// -1 = last day, -2 = second-to-last, etc. Empty = no constraint.
    #[serde(default)]
    pub bymonthday: Vec<i32>,
}

fn default_interval() -> u32 {
    1
}

// ── RSVP ────────────────────────────────────────────────────────────────────

/// RSVP response status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RsvpStatus {
    /// Accepted / attending.
    Accepted,
    /// Declined / not attending.
    Declined,
    /// Tentative / maybe attending.
    Tentative,
}

// ── CalendarEvent ────────────────────────────────────────────────────────────

/// A calendar event as stored/exposed by the local node.
///
/// This is the domain model used by the API and storage layers. The wire
/// representation (inside the UKM envelope ciphertext) is
/// `payloads::calendar::CalendarEventPayload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalendarEvent {
    /// Unique event identifier (UUID).
    pub id: String,
    /// Node ID (hex) of the event organizer.
    pub organizer: String,
    /// Human-readable event title.
    pub title: String,
    /// Optional description / agenda.
    #[serde(default)]
    pub description: Option<String>,
    /// Event start time as Unix timestamp milliseconds.
    pub start: u64,
    /// Event end time as Unix timestamp milliseconds.
    pub end: u64,
    /// IANA timezone identifier (e.g. "UTC", "America/New_York").
    pub tz: String,
    /// Optional physical or virtual location.
    #[serde(default)]
    pub location: Option<String>,
    /// Node IDs (hex) of invited attendees.
    #[serde(default)]
    pub attendees: Vec<String>,
    /// Optional recurrence rule.
    #[serde(default)]
    pub recurrence: Option<RRule>,
    /// Optional display color (CSS hex, e.g. "#3498db").
    #[serde(default)]
    pub color: Option<String>,
    /// ISO 8601 timestamp when the event was created on this node.
    pub created_at: String,
    /// For exception / override records: the ID of the master recurring event.
    /// `None` for master events and one-off events.
    #[serde(default)]
    pub parent_id: Option<String>,
}

// ── Recurrence expansion ─────────────────────────────────────────────────────

/// Expand a recurring event into its occurrences within `[from_ms, to_ms)`.
///
/// ## DST safety
/// Recurrence steps are taken in *wall-clock* space (naive local time) and then
/// re-localised to the event's timezone. A weekly 09:00 event stays at 09:00
/// after spring-forward; times that land in a DST gap are shifted forward by 1 h.
///
/// ## Parameters
/// - `base`       — master event (must have `recurrence` set; otherwise returns `[]`)
/// - `from_ms`    — window start (inclusive), Unix ms
/// - `to_ms`      — window end (exclusive), Unix ms
/// - `exceptions` — events with `parent_id == base.id`; occurrence starts that
///   match are suppressed (replaced by the exception record by the caller)
pub fn expand_occurrences(
    base: &CalendarEvent,
    from_ms: u64,
    to_ms: u64,
    exceptions: &[&CalendarEvent],
) -> Vec<CalendarEvent> {
    let rule = match &base.recurrence {
        Some(r) => r,
        None => return Vec::new(),
    };

    if from_ms >= to_ms {
        return Vec::new();
    }

    let duration_ms = base.end.saturating_sub(base.start);

    // Parse timezone; fall back to UTC on unknown zone.
    let tz: Tz = base.tz.parse().unwrap_or(chrono_tz::UTC);

    // Decompose the base event's start into wall-clock (naive-local) time.
    let anchor_naive: NaiveDateTime = {
        use chrono::LocalResult;
        match tz.timestamp_millis_opt(base.start as i64) {
            LocalResult::Single(dt) | LocalResult::Ambiguous(dt, _) => {
                let dt: DateTime<Tz> = dt;
                dt.naive_local()
            }
            LocalResult::None => {
                // Shouldn't happen for a valid stored timestamp; fall back to UTC naive.
                let secs = base.start as i64 / 1000;
                let nsecs = ((base.start % 1000) * 1_000_000) as u32;
                chrono::Utc
                    .timestamp_opt(secs, nsecs)
                    .single()
                    .map(|d| d.naive_utc())
                    .unwrap_or_default()
            }
        }
    };

    let excepted: HashSet<u64> = exceptions.iter().map(|e| e.start).collect();
    let byday_weekdays = parse_byday(&rule.byday);

    let mut results: Vec<CalendarEvent> = Vec::new();
    let mut count_all: u32 = 0;

    // Optimisation: for open-ended (no COUNT) recurrences skip steps that
    // cannot possibly produce occurrences in [from_ms, to_ms).
    let start_step: u32 = if rule.count.is_none() && base.start < from_ms {
        let delta_ms = from_ms.saturating_sub(base.start);
        let approx = match rule.freq {
            Freq::Daily => delta_ms / (86_400_000 * rule.interval as u64),
            Freq::Weekly => delta_ms / (7 * 86_400_000 * rule.interval as u64),
            Freq::Monthly => delta_ms / (30 * 86_400_000 * rule.interval as u64),
            Freq::Yearly => delta_ms / (365 * 86_400_000 * rule.interval as u64),
        };
        // Back off 2 steps to be safe near DST / month-length boundaries.
        (approx as u32).saturating_sub(2)
    } else {
        0
    };

    'outer: for step in start_step.. {
        if step.saturating_sub(start_step) > 5_000 {
            break; // safety limit
        }

        // Compute candidate wall-clock NaiveDateTimes for this step.
        let candidates: Vec<NaiveDateTime> = match rule.freq {
            Freq::Daily => {
                let offset = Duration::days((step * rule.interval) as i64);
                vec![anchor_naive + offset]
            }

            Freq::Weekly => {
                let offset_weeks = (step * rule.interval) as i64;
                if byday_weekdays.is_empty() {
                    // Simple weekly: same weekday every N weeks.
                    vec![anchor_naive + Duration::weeks(offset_weeks)]
                } else {
                    // Weekly + BYDAY: enumerate matching weekdays in the step's week.
                    let days_from_mon = anchor_naive.weekday().num_days_from_monday() as i64;
                    let mon_of_anchor =
                        anchor_naive.date() - Duration::days(days_from_mon);
                    let mon_of_step = mon_of_anchor + Duration::weeks(offset_weeks);

                    let mut week_cands = Vec::new();
                    for &wd in &byday_weekdays {
                        let day_offset = wd.num_days_from_monday() as i64;
                        let naive_date = mon_of_step + Duration::days(day_offset);
                        let naive_dt = NaiveDateTime::new(naive_date, anchor_naive.time());
                        // For step 0 only include days on/after the anchor.
                        if step > 0 || naive_dt >= anchor_naive {
                            week_cands.push(naive_dt);
                        }
                    }
                    week_cands.sort_unstable();
                    week_cands
                }
            }

            Freq::Monthly => {
                let months = step * rule.interval;
                if rule.bymonthday.is_empty() {
                    // Simple monthly: same day of month (clamped to last valid day).
                    match add_months_to_naive(anchor_naive, months) {
                        Some(dt) => vec![dt],
                        None => continue,
                    }
                } else {
                    // Monthly + BYMONTHDAY: map each bymonthday to a NaiveDate.
                    let (ty, tm) = advance_year_month(
                        anchor_naive.year(),
                        anchor_naive.month(),
                        months,
                    );
                    let mut month_cands = Vec::new();
                    for &mday in &rule.bymonthday {
                        if let Some(nd) = resolve_bymonthday(ty, tm, mday) {
                            let naive_dt = NaiveDateTime::new(nd, anchor_naive.time());
                            // For step 0 only include days on/after the anchor.
                            if step > 0 || naive_dt >= anchor_naive {
                                month_cands.push(naive_dt);
                            }
                        }
                    }
                    month_cands.sort_unstable();
                    month_cands
                }
            }

            Freq::Yearly => {
                let years = (step * rule.interval) as i32;
                match NaiveDate::from_ymd_opt(
                    anchor_naive.year() + years,
                    anchor_naive.month(),
                    anchor_naive.day(),
                ) {
                    Some(d) => vec![NaiveDateTime::new(d, anchor_naive.time())],
                    None => continue,
                }
            }
        };

        for cand_naive in candidates {
            // Re-localise the wall-clock time (DST-safe).
            let cand_ms = match localize_earliest(&tz, cand_naive) {
                Some(dt) => dt.timestamp_millis() as u64,
                None => continue,
            };

            // Hard stop: UNTIL exceeded.
            if let Some(until_ms) = rule.until {
                if cand_ms > until_ms {
                    break 'outer;
                }
            }

            // Hard stop: COUNT exhausted.
            if let Some(max_count) = rule.count {
                if count_all >= max_count {
                    break 'outer;
                }
            }

            count_all += 1;

            // Collect if inside the query window and not overridden by an exception.
            if cand_ms >= from_ms && cand_ms < to_ms && !excepted.contains(&cand_ms) {
                let mut occ = base.clone();
                occ.id = format!("{}-{}", base.id, cand_ms);
                occ.parent_id = Some(base.id.clone());
                occ.start = cand_ms;
                occ.end = cand_ms + duration_ms;
                results.push(occ);
            }

            // Optimisation: past window with no terminating constraints — done.
            if cand_ms >= to_ms && rule.count.is_none() && rule.until.is_none() {
                break 'outer;
            }
        }
    }

    results
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Parse RFC 5545 two-letter day codes into `chrono::Weekday` values.
fn parse_byday(byday: &[String]) -> Vec<Weekday> {
    byday
        .iter()
        .filter_map(|s| match s.as_str() {
            "MO" => Some(Weekday::Mon),
            "TU" => Some(Weekday::Tue),
            "WE" => Some(Weekday::Wed),
            "TH" => Some(Weekday::Thu),
            "FR" => Some(Weekday::Fri),
            "SA" => Some(Weekday::Sat),
            "SU" => Some(Weekday::Sun),
            _ => None,
        })
        .collect()
}

/// Number of days in a given month (handles leap years).
fn days_in_month(year: i32, month: u32) -> u32 {
    let (y, m) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    NaiveDate::from_ymd_opt(y, m, 1)
        .and_then(|d| d.pred_opt())
        .map(|d| d.day())
        .unwrap_or(30)
}

/// Resolve a BYMONTHDAY value (positive or negative) to a concrete `NaiveDate`.
///
/// Positive: 1 = first day, 28 = 28th (clamped to last day of month).
/// Negative: -1 = last day, -2 = second-to-last, etc.
pub fn resolve_bymonthday(year: i32, month: u32, mday: i32) -> Option<NaiveDate> {
    let dim = days_in_month(year, month) as i32;
    let day = if mday > 0 {
        if mday > dim {
            return None;
        }
        mday as u32
    } else if mday < 0 {
        let d = dim + mday + 1; // -1 → dim, -2 → dim-1, …
        if d < 1 {
            return None;
        }
        d as u32
    } else {
        return None; // 0 is invalid per RFC 5545
    };
    NaiveDate::from_ymd_opt(year, month, day)
}

/// Advance (year, month) by `months` months without overflow.
fn advance_year_month(year: i32, month: u32, months: u32) -> (i32, u32) {
    let total = (year as i64) * 12 + (month as i64 - 1) + months as i64;
    let new_year = (total / 12) as i32;
    let new_month = (total % 12 + 1) as u32;
    (new_year, new_month)
}

/// Add `months` months to a `NaiveDateTime`, clamping the day to the last
/// valid day in the target month (e.g. Jan 31 + 1 month → Feb 28/29).
fn add_months_to_naive(dt: NaiveDateTime, months: u32) -> Option<NaiveDateTime> {
    let (new_year, new_month) = advance_year_month(dt.year(), dt.month(), months);
    let dim = days_in_month(new_year, new_month);
    let day = dt.day().min(dim);
    NaiveDate::from_ymd_opt(new_year, new_month, day).map(|d| d.and_time(dt.time()))
}

/// Localise a `NaiveDateTime` in the given timezone, preferring the earlier
/// interpretation on fold-back (autumn) and advancing 1 h through a DST gap
/// (spring-forward) when the time would otherwise be invalid.
fn localize_earliest(tz: &Tz, naive: NaiveDateTime) -> Option<chrono::DateTime<Tz>> {
    use chrono::LocalResult;
    match tz.from_local_datetime(&naive) {
        LocalResult::Single(dt) | LocalResult::Ambiguous(dt, _) => Some(dt),
        LocalResult::None => {
            // Time was skipped (spring-forward gap); advance 1 h.
            let shifted = naive + Duration::hours(1);
            match tz.from_local_datetime(&shifted) {
                LocalResult::Single(dt) | LocalResult::Ambiguous(dt, _) => Some(dt),
                LocalResult::None => None,
            }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_base(start: u64, tz: &str, rule: RRule) -> CalendarEvent {
        CalendarEvent {
            id: "evt-001".to_string(),
            organizer: "aa".to_string(),
            title: "Recurring".to_string(),
            description: None,
            start,
            end: start + 3_600_000, // 1 h duration
            tz: tz.to_string(),
            location: None,
            attendees: vec![],
            recurrence: Some(rule),
            color: None,
            created_at: "2026-01-01T00:00:00.000Z".to_string(),
            parent_id: None,
        }
    }

    /// Start of 2026-01-01 09:00 UTC in ms.
    fn utc_ms(year: i32, month: u32, day: u32, hour: u32, min: u32) -> u64 {
        use chrono::{TimeZone, Utc};
        Utc.with_ymd_and_hms(year, month, day, hour, min, 0)
            .unwrap()
            .timestamp_millis() as u64
    }

    #[test]
    fn daily_basic() {
        let start = utc_ms(2026, 1, 1, 9, 0);
        let rule = RRule { freq: Freq::Daily, interval: 1, count: Some(5), ..Default::default() };
        let base = make_base(start, "UTC", rule);
        let from = start;
        let to = start + 10 * 86_400_000;
        let occs = expand_occurrences(&base, from, to, &[]);
        assert_eq!(occs.len(), 5);
        for (i, occ) in occs.iter().enumerate() {
            assert_eq!(occ.start, start + i as u64 * 86_400_000);
            assert_eq!(occ.parent_id.as_deref(), Some("evt-001"));
        }
    }

    #[test]
    fn weekly_count_5() {
        let start = utc_ms(2026, 1, 5, 9, 0); // Monday
        let rule = RRule { freq: Freq::Weekly, interval: 1, count: Some(5), ..Default::default() };
        let base = make_base(start, "UTC", rule);
        let occs = expand_occurrences(&base, start, start + 40 * 86_400_000, &[]);
        assert_eq!(occs.len(), 5);
        for (i, occ) in occs.iter().enumerate() {
            assert_eq!(occ.start, start + i as u64 * 7 * 86_400_000);
        }
    }

    #[test]
    fn weekly_byday_mwf() {
        // 2026-01-05 is a Monday; byday=MO,WE,FR
        let start = utc_ms(2026, 1, 5, 9, 0);
        let rule = RRule {
            freq: Freq::Weekly,
            interval: 1,
            count: Some(6),
            byday: vec!["MO".into(), "WE".into(), "FR".into()],
            ..Default::default()
        };
        let base = make_base(start, "UTC", rule);
        let occs = expand_occurrences(&base, start, start + 14 * 86_400_000, &[]);
        assert_eq!(occs.len(), 6);
    }

    #[test]
    fn monthly_last_day() {
        // Anchor: 2026-01-31 09:00 UTC; bymonthday=-1
        let start = utc_ms(2026, 1, 31, 9, 0);
        let rule = RRule {
            freq: Freq::Monthly,
            interval: 1,
            count: Some(4),
            bymonthday: vec![-1],
            ..Default::default()
        };
        let base = make_base(start, "UTC", rule);
        let occs = expand_occurrences(&base, start, start + 200 * 86_400_000, &[]);
        assert_eq!(occs.len(), 4);
        // Check the second occurrence (Feb): should be Feb 28
        use chrono::{TimeZone, Utc};
        let feb_occ = Utc.timestamp_millis_opt(occs[1].start as i64).unwrap();
        assert_eq!(feb_occ.day(), 28);
        assert_eq!(feb_occ.month(), 2);
    }

    #[test]
    fn until_terminates() {
        let start = utc_ms(2026, 1, 1, 9, 0);
        let until = utc_ms(2026, 1, 15, 9, 0);
        let rule = RRule { freq: Freq::Daily, interval: 1, until: Some(until), ..Default::default() };
        let base = make_base(start, "UTC", rule);
        let occs = expand_occurrences(&base, start, start + 60 * 86_400_000, &[]);
        assert!(occs.iter().all(|o| o.start <= until));
        assert_eq!(occs.len(), 15); // Jan 1–15
    }

    #[test]
    fn exception_suppresses_occurrence() {
        let start = utc_ms(2026, 1, 5, 9, 0);
        let rule = RRule { freq: Freq::Weekly, interval: 1, count: Some(4), ..Default::default() };
        let base = make_base(start, "UTC", rule);
        // Exception for occurrence 2 (Jan 12)
        let exc_start = utc_ms(2026, 1, 12, 9, 0);
        let exc = CalendarEvent {
            id: "exc-1".to_string(),
            parent_id: Some("evt-001".to_string()),
            start: exc_start,
            end: exc_start + 3_600_000,
            title: "Rescheduled".to_string(),
            ..base.clone()
        };
        let occs = expand_occurrences(&base, start, start + 30 * 86_400_000, &[&exc]);
        assert!(!occs.iter().any(|o| o.start == exc_start));
    }

    #[test]
    fn rrule_roundtrip() {
        let rule = RRule {
            freq: Freq::Weekly,
            interval: 2,
            until: Some(1_800_000_000_000),
            count: None,
            byday: vec!["MO".to_string(), "WE".to_string(), "FR".to_string()],
            bymonthday: vec![],
        };
        let json = serde_json::to_string(&rule).unwrap();
        let decoded: RRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, decoded);
    }

    #[test]
    fn rrule_default_interval() {
        let json = r#"{"freq":"WEEKLY"}"#;
        let rule: RRule = serde_json::from_str(json).unwrap();
        assert_eq!(rule.interval, 1);
        assert!(rule.until.is_none());
        assert!(rule.count.is_none());
        assert!(rule.byday.is_empty());
        assert!(rule.bymonthday.is_empty());
    }

    #[test]
    fn rsvp_status_serialization() {
        assert_eq!(serde_json::to_string(&RsvpStatus::Accepted).unwrap(), "\"accepted\"");
        assert_eq!(serde_json::to_string(&RsvpStatus::Declined).unwrap(), "\"declined\"");
        assert_eq!(serde_json::to_string(&RsvpStatus::Tentative).unwrap(), "\"tentative\"");
    }

    #[test]
    fn calendar_event_roundtrip() {
        let event = CalendarEvent {
            id: "evt-001".to_string(),
            organizer: "aabbcc".to_string(),
            title: "Team Sync".to_string(),
            description: Some("Weekly standup".to_string()),
            start: 1_700_000_000_000,
            end: 1_700_003_600_000,
            tz: "UTC".to_string(),
            location: Some("https://meet.example.com/room".to_string()),
            attendees: vec!["ddeeff".to_string()],
            recurrence: Some(RRule {
                freq: Freq::Weekly,
                interval: 1,
                until: None,
                count: Some(10),
                byday: vec!["MO".to_string()],
                bymonthday: vec![],
            }),
            color: Some("#3498db".to_string()),
            created_at: "2026-04-16T00:00:00.000Z".to_string(),
            parent_id: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let decoded: CalendarEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event.id, decoded.id);
        assert_eq!(event.title, decoded.title);
        assert_eq!(event.attendees, decoded.attendees);
        assert!(decoded.parent_id.is_none());
    }

    #[test]
    fn resolve_bymonthday_positive() {
        assert_eq!(
            resolve_bymonthday(2026, 2, 1),
            NaiveDate::from_ymd_opt(2026, 2, 1)
        );
        assert_eq!(resolve_bymonthday(2026, 2, 29), None); // 2026 not a leap year
    }

    #[test]
    fn resolve_bymonthday_negative() {
        // -1 = last day of month
        assert_eq!(
            resolve_bymonthday(2026, 1, -1),
            NaiveDate::from_ymd_opt(2026, 1, 31)
        );
        assert_eq!(
            resolve_bymonthday(2026, 2, -1),
            NaiveDate::from_ymd_opt(2026, 2, 28)
        );
        // -1 in leap year February
        assert_eq!(
            resolve_bymonthday(2028, 2, -1),
            NaiveDate::from_ymd_opt(2028, 2, 29)
        );
        // -2 = second-to-last
        assert_eq!(
            resolve_bymonthday(2026, 1, -2),
            NaiveDate::from_ymd_opt(2026, 1, 30)
        );
    }

    #[test]
    fn no_recurrence_returns_empty() {
        let start = utc_ms(2026, 1, 1, 9, 0);
        let event = CalendarEvent {
            id: "e".to_string(),
            organizer: "aa".to_string(),
            title: "One-off".to_string(),
            description: None,
            start,
            end: start + 3_600_000,
            tz: "UTC".to_string(),
            location: None,
            attendees: vec![],
            recurrence: None,
            color: None,
            created_at: "2026-01-01T00:00:00.000Z".to_string(),
            parent_id: None,
        };
        let occs = expand_occurrences(&event, start, start + 30 * 86_400_000, &[]);
        assert!(occs.is_empty());
    }
}

// ── Property-based tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod proptests {
    use super::*;
    use chrono::{LocalResult, TimeZone, Timelike};
    use proptest::prelude::*;

    fn base_event(start_ms: u64, tz: &str, rule: RRule) -> CalendarEvent {
        CalendarEvent {
            id: "prop-evt".to_string(),
            organizer: "aa".to_string(),
            title: "Prop".to_string(),
            description: None,
            start: start_ms,
            end: start_ms + 3_600_000,
            tz: tz.to_string(),
            location: None,
            attendees: vec![],
            recurrence: Some(rule),
            color: None,
            created_at: "2026-01-01T00:00:00.000Z".to_string(),
            parent_id: None,
        }
    }

    proptest! {
        /// Weekly events in America/New_York preserve wall-clock hour across
        /// the spring-forward DST transition (2026-03-08).
        /// We avoid the 2 AM gap (the skipped hour) by restricting start_hour
        /// to 3..=23.
        #[test]
        fn prop_weekly_across_dst(
            start_hour in 3u32..24u32,
            start_day  in 0i64..59i64, // 2026-01-01 … 2026-03-01
        ) {
            let tz: Tz = "America/New_York".parse().unwrap();
            let base_naive = NaiveDate::from_ymd_opt(2026, 1, 1)
                .unwrap()
                .checked_add_days(chrono::Days::new(start_day as u64))
                .unwrap()
                .and_hms_opt(start_hour, 0, 0)
                .unwrap();

            let base_local = match tz.from_local_datetime(&base_naive) {
                LocalResult::Single(dt) | LocalResult::Ambiguous(dt, _) => dt,
                LocalResult::None => return Ok(()), // skip anchors in DST gap
            };
            let base_ms = base_local.timestamp_millis() as u64;

            let rule = RRule {
                freq: Freq::Weekly,
                interval: 1,
                until: None,
                count: None,
                byday: vec![],
                bymonthday: vec![],
            };
            let event = base_event(base_ms, "America/New_York", rule);

            // Expand 20 weeks from the anchor (crosses the March 8 spring-forward).
            let to = base_ms + 20 * 7 * 24 * 3_600_000;
            let occs = expand_occurrences(&event, base_ms, to, &[]);

            prop_assert!(!occs.is_empty(), "no occurrences returned");
            for occ in &occs {
                let local = match tz.timestamp_millis_opt(occ.start as i64) {
                    LocalResult::Single(dt) | LocalResult::Ambiguous(dt, _) => dt,
                    LocalResult::None => continue,
                };
                prop_assert_eq!(
                    local.hour(),
                    start_hour,
                    "DST shifted wall-clock hour: occurrence at {} has hour {}, expected {}",
                    occ.start,
                    local.hour(),
                    start_hour,
                );
            }
        }

        /// Monthly recurrence with negative BYMONTHDAY always lands on the
        /// correct day counting from the end of each month.
        #[test]
        fn prop_monthly_bymonthday_negative(
            neg_day in -28i32..=-1i32,
            months  in 1u32..25u32,
        ) {
            use chrono::Utc;
            // Anchor: 2026-01-01 12:00 UTC
            let anchor_ms = Utc
                .with_ymd_and_hms(2026, 1, 1, 12, 0, 0)
                .unwrap()
                .timestamp_millis() as u64;

            let rule = RRule {
                freq: Freq::Monthly,
                interval: 1,
                count: Some(months),
                bymonthday: vec![neg_day],
                ..Default::default()
            };
            let event = base_event(anchor_ms, "UTC", rule);

            let to = anchor_ms + months as u64 * 35 * 86_400_000;
            let occs = expand_occurrences(&event, anchor_ms, to, &[]);

            for occ in &occs {
                let dt = Utc.timestamp_millis_opt(occ.start as i64).unwrap();
                let y = dt.year();
                let m = dt.month();
                let dim = days_in_month(y, m) as i32;
                let expected_day = (dim + neg_day + 1) as u32;
                prop_assert_eq!(
                    dt.day(),
                    expected_day,
                    "occurrence {:?} has day {} but expected {} for neg_day={}",
                    dt,
                    dt.day(),
                    expected_day,
                    neg_day,
                );
            }
        }

        /// Any recurrence with COUNT=10 produces exactly 10 occurrences
        /// when queried over a window large enough to contain all of them.
        #[test]
        fn prop_count_10_termination(
            freq_idx in 0usize..3usize,
            interval in 1u32..6u32,
        ) {
            use chrono::{TimeZone, Utc};
            let freqs = [Freq::Daily, Freq::Weekly, Freq::Monthly];
            let freq = freqs[freq_idx];

            let anchor_ms = Utc
                .with_ymd_and_hms(2026, 1, 1, 9, 0, 0)
                .unwrap()
                .timestamp_millis() as u64;

            let rule = RRule {
                freq,
                interval,
                count: Some(10),
                ..Default::default()
            };
            let event = base_event(anchor_ms, "UTC", rule);

            // 20-year window — more than enough for any interval 1..=5.
            let to = anchor_ms + 20 * 365 * 86_400_000u64;
            let occs = expand_occurrences(&event, anchor_ms, to, &[]);

            prop_assert_eq!(
                occs.len(),
                10,
                "Expected 10 occurrences for freq={:?}, interval={}, got {}",
                freq,
                interval,
                occs.len(),
            );
        }
    }
}
