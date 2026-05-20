/** Toast notification container — renders active toasts with slide-in animation. */

import { For } from "solid-js";
import type { JSX } from "solid-js";
import { toasts, dismissToast, type ToastType } from "../stores/toast";
import { IconCheck, IconX, IconWarning, IconInfo } from "./Icons";

const ICONS: Record<ToastType, (props?: { size?: number }) => JSX.Element> = {
  success: IconCheck,
  error: IconX,
  warning: IconWarning,
  info: IconInfo,
};

export default function ToastContainer() {
  return (
    <div class="toast-container" aria-live="polite" aria-label="Notifications">
      <For each={toasts()}>
        {(t) => (
          <div
            class={`toast toast-${t.type} animate-slide-up`}
            role="alert"
            onClick={() => dismissToast(t.id)}
          >
            <span class="toast-icon">{ICONS[t.type]({ size: 14 })}</span>
            <span class="toast-message">{t.message}</span>
          </div>
        )}
      </For>
    </div>
  );
}
