/** Right panel — AI Control Room and context-sensitive tools. */

import { Show } from "solid-js";
import { rightPanelOpen } from "../stores/layout";
import { IconAI } from "./Icons";

export default function RightPanel() {
  return (
    <aside
      class={`right-panel glass ${rightPanelOpen() ? "right-panel-open" : "right-panel-collapsed"}`}
      aria-label="AI Control Room"
    >
      <Show
        when={rightPanelOpen()}
        fallback={
          <div class="right-panel-rail">
            <span class="right-panel-rail-icon" title="AI Control Room">
              <IconAI size={20} />
            </span>
          </div>
        }
      >
        <div class="right-panel-placeholder">
          AI Control Room — coming next
        </div>
      </Show>
    </aside>
  );
}
