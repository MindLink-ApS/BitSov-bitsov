/**
 * NodeOffline — full-page overlay shown when the node is unreachable.
 * Displays after multiple failed health checks with a retry button.
 */

import { createSignal, Show, onMount, onCleanup } from "solid-js";
import { wsStatus } from "../stores/auth";
import { api } from "../stores/auth";
import { IconWarning, IconRefresh, IconNetwork } from "./Icons";

export default function NodeOffline() {
  const [nodeDown, setNodeDown] = createSignal(false);
  const [checking, setChecking] = createSignal(false);
  const [failCount, setFailCount] = createSignal(0);

  // After 3 consecutive WS disconnections, start health-checking the node
  let checkTimer: ReturnType<typeof setInterval> | undefined;

  async function checkHealth() {
    setChecking(true);
    try {
      await api.health();
      setNodeDown(false);
      setFailCount(0);
    } catch {
      setFailCount((c) => c + 1);
      if (failCount() >= 2) {
        setNodeDown(true);
      }
    } finally {
      setChecking(false);
    }
  }

  onMount(() => {
    // Check health when WS status indicates persistent offline
    checkTimer = setInterval(() => {
      const status = wsStatus();
      if (status === "disconnected" || status === "error") {
        checkHealth();
      } else {
        setNodeDown(false);
        setFailCount(0);
      }
    }, 10000);
  });

  onCleanup(() => {
    if (checkTimer) clearInterval(checkTimer);
  });

  const handleRetry = async () => {
    setChecking(true);
    try {
      await api.health();
      setNodeDown(false);
      setFailCount(0);
      // Trigger a page reload to re-establish WS connection
      window.location.reload();
    } catch {
      setNodeDown(true);
    } finally {
      setChecking(false);
    }
  };

  return (
    <Show when={nodeDown()}>
      <div class="node-offline-overlay" role="alert">
        <div class="node-offline-card">
          <div class="node-offline-icon">
            <IconNetwork size={48} />
          </div>
          <h2 class="node-offline-title">Node Unreachable</h2>
          <p class="node-offline-desc">
            Cannot connect to your BitSov node. This could mean:
          </p>
          <ul class="node-offline-list">
            <li>The node process is not running</li>
            <li>The network connection is down</li>
            <li>The node address has changed</li>
          </ul>
          <p class="node-offline-hint">
            <strong>Connected to:</strong>{" "}
            <span class="mono">{api.getBaseUrl()}</span>
          </p>
          <button
            class="btn btn-primary icon-text"
            onClick={handleRetry}
            disabled={checking()}
          >
            <Show when={checking()} fallback={<><IconRefresh size={14} /> Retry Connection</>}>
              <span class="connection-spinner"><IconRefresh size={14} /></span> Checking...
            </Show>
          </button>
        </div>
      </div>
    </Show>
  );
}
