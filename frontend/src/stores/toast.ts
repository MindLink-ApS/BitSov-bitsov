/**
 * Toast notification store — centralized feedback system.
 *
 * Toasts slide in from bottom-right, auto-dismiss after a configurable
 * duration, and can be manually dismissed. Four types: success, error,
 * warning, info — each with accent-colored styling.
 */

import { createSignal } from "solid-js";

export type ToastType = "success" | "error" | "warning" | "info";

export interface Toast {
  id: number;
  type: ToastType;
  message: string;
  duration: number;
}

let nextId = 0;

const [toasts, setToasts] = createSignal<Toast[]>([]);

export { toasts };

/** Show a toast notification. Returns the toast ID for manual dismissal. */
export function showToast(
  message: string,
  type: ToastType = "info",
  duration = 4000,
): number {
  const id = nextId++;
  const toast: Toast = { id, type, message, duration };
  setToasts((prev) => [...prev, toast]);

  if (duration > 0) {
    setTimeout(() => dismissToast(id), duration);
  }

  return id;
}

/** Dismiss a specific toast by ID. */
export function dismissToast(id: number): void {
  setToasts((prev) => prev.filter((t) => t.id !== id));
}

/** Convenience helpers. */
export const toast = {
  success: (msg: string, duration?: number) => showToast(msg, "success", duration),
  error: (msg: string, duration?: number) => showToast(msg, "error", duration ?? 6000),
  warning: (msg: string, duration?: number) => showToast(msg, "warning", duration),
  info: (msg: string, duration?: number) => showToast(msg, "info", duration),
};
