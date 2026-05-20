/**
 * Layout store — right panel open/collapsed state with localStorage persistence.
 */

import { createSignal } from "solid-js";
import { loadJSON, saveJSON } from "../utils/storage";

const STORAGE_KEY = "bitsov_right_panel_open";

function getStoredPanelState(): boolean {
  return loadJSON<boolean>(STORAGE_KEY, true);
}

const [rightPanelOpen, setRightPanelOpen] = createSignal<boolean>(getStoredPanelState());

export { rightPanelOpen };

export function toggleRightPanel(): void {
  const next = !rightPanelOpen();
  setRightPanelOpen(next);
  saveLayoutState();
}

export function loadLayoutState(): void {
  setRightPanelOpen(getStoredPanelState());
}

export function saveLayoutState(): void {
  saveJSON<boolean>(STORAGE_KEY, rightPanelOpen());
}
