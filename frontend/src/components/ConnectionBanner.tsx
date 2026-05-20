/**
 * ConnectionBanner — persistent banner shown when WebSocket is disconnected or reconnecting.
 * Slides down from the top of the main content area. Auto-dismisses when connection restores.
 */

import { Show, createSignal, createEffect, on } from "solid-js";
import { wsStatus } from "../stores/auth";
import { IconWarning, IconRefresh, IconCheck } from "./Icons";

export default function ConnectionBanner() {
  const [justReconnected, setJustReconnected] = createSignal(false);
  const [wasDisconnected, setWasDisconnected] = createSignal(false);

  // Track reconnection: show brief "Connected" message when recovering
  createEffect(on(wsStatus, (status, prev) => {
    if (prev && prev !== "connected" && status === "connected" && wasDisconnected()) {
      setJustReconnected(true);
      setWasDisconnected(false);
      const timer = setTimeout(() => setJustReconnected(false), 3000);
      return () => clearTimeout(timer);
    }
    if (status === "disconnected" || status === "error") {
      setWasDisconnected(true);
    }
  }));

  const isOffline = () => {
    const s = wsStatus();
    return s === "disconnected" || s === "error";
  };

  const isConnecting = () => wsStatus() === "connecting";

  return (
    <>
      <Show when={isOffline()}>
        <div class="connection-banner connection-banner-offline" role="alert">
          <IconWarning size={14} />
          <span>Disconnected from node — reconnecting automatically</span>
        </div>
      </Show>
      <Show when={isConnecting()}>
        <div class="connection-banner connection-banner-connecting" role="status">
          <span class="connection-spinner"><IconRefresh size={14} /></span>
          <span>Reconnecting to node...</span>
        </div>
      </Show>
      <Show when={justReconnected()}>
        <div class="connection-banner connection-banner-restored" role="status">
          <IconCheck size={14} />
          <span>Connected</span>
        </div>
      </Show>
    </>
  );
}
