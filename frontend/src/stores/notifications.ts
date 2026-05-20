/**
 * Desktop notification store — OS-level alerts for messages and peer events.
 *
 * Uses the Web Notification API which works in both browsers and Tauri webviews.
 * Notifications are opt-in: the user must grant permission and enable them in Settings.
 * Respects Do Not Disturb mode and per-category toggles.
 */

import { createSignal } from "solid-js";
import { loadJSON, saveJSON } from "../utils/storage";

// ─── Settings (persisted to localStorage) ───────────────────────

interface NotificationSettings {
  /** Master switch — no notifications when false. */
  enabled: boolean;
  /** Notify on new messages from peers. */
  messages: boolean;
  /** Notify on peer online/offline events. */
  peerEvents: boolean;
  /** Notify on payment confirmations. */
  payments: boolean;
}

const STORAGE_KEY = "konsensus_notification_settings";

function loadSettings(): NotificationSettings {
  return loadJSON<NotificationSettings>(STORAGE_KEY, { enabled: false, messages: true, peerEvents: true, payments: true });
}

function persistSettings(s: NotificationSettings): void {
  saveJSON(STORAGE_KEY, s);
}

const [notifSettings, setNotifSettings] = createSignal<NotificationSettings>(loadSettings());
const [notifPermission, setNotifPermission] = createSignal<NotificationPermission>(
  typeof Notification !== "undefined" ? Notification.permission : "denied",
);

export { notifSettings, notifPermission };

/** Request browser notification permission. */
export async function requestPermission(): Promise<NotificationPermission> {
  if (typeof Notification === "undefined") return "denied";
  const perm = await Notification.requestPermission();
  setNotifPermission(perm);
  return perm;
}

/** Update notification settings. */
export function updateNotifSettings(patch: Partial<NotificationSettings>): void {
  const next = { ...notifSettings(), ...patch };
  setNotifSettings(next);
  persistSettings(next);
}

/** Toggle the master notifications switch (requests permission if needed). */
export async function toggleNotifications(on: boolean): Promise<void> {
  if (on && notifPermission() !== "granted") {
    const perm = await requestPermission();
    if (perm !== "granted") {
      updateNotifSettings({ enabled: false });
      return;
    }
  }
  updateNotifSettings({ enabled: on });
}

// ─── Send notification ──────────────────────────────────────────

/** Send an OS-level notification if enabled and permitted. */
export function sendNotification(
  title: string,
  body: string,
  category: "messages" | "peerEvents" | "payments",
  tag?: string,
): void {
  if (typeof Notification === "undefined") return;
  const s = notifSettings();
  if (!s.enabled || !s[category]) return;
  if (Notification.permission !== "granted") return;

  // Don't notify if the window is focused
  if (document.hasFocus()) return;

  try {
    new Notification(title, {
      body,
      tag: tag ?? category,
      icon: "/favicon.ico",
    });
  } catch {
    // Notification constructor may throw in some environments
  }
}
