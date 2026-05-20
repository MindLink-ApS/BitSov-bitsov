/**
 * Theme store — dark/light mode toggle with localStorage persistence.
 */

import { createSignal } from "solid-js";
import { loadString, saveString } from "../utils/storage";

export type Theme = "dark" | "light";

function getStoredTheme(): Theme {
  const stored = loadString("konsensus-theme");
  if (stored === "light" || stored === "dark") return stored;
  return "dark";
}

const [theme, setThemeSignal] = createSignal<Theme>(getStoredTheme());

// Apply initial theme
if (getStoredTheme() === "light") {
  document.documentElement.setAttribute("data-theme", "light");
}

export { theme };

export function toggleTheme(): void {
  const next = theme() === "dark" ? "light" : "dark";
  setThemeSignal(next);

  if (next === "light") {
    document.documentElement.setAttribute("data-theme", "light");
  } else {
    document.documentElement.removeAttribute("data-theme");
  }

  saveString("konsensus-theme", next);
}
