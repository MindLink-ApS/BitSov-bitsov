/**
 * Profile seeding for beta distribution.
 *
 * On first login, if the user's ProfileView localStorage is empty and their
 * node_id matches a key in /profile-registry.json, copy that entry in as the
 * initial profile. This lets us ship one desktop build that auto-populates
 * Maya's identity on Maya's node and Josh's on Josh's.
 *
 * Temporary seam until NodeProfile P2P exchange + a [profile] section in
 * konsensus.toml replace the frontend-only approach.
 */

import { loadJSON, saveJSON } from "../utils/storage";

const PROFILE_KEY = "konsensus_user_profile";
const SEEDED_KEY = "konsensus_profile_seeded";

interface SeededProfile {
  displayName: string;
  title: string;
  bio: string;
  status: "online" | "idle" | "dnd" | "invisible";
  x_handle?: string;
  x_url?: string;
  avatarDataUrl?: string;
}

type ProfileRegistry = Record<string, SeededProfile>;

export async function seedProfileIfEmpty(nodeId: string): Promise<void> {
  if (!nodeId) return;
  if (localStorage.getItem(SEEDED_KEY) === "true") return;

  const existing = loadJSON<SeededProfile | null>(PROFILE_KEY, null);
  if (existing && existing.displayName?.trim()) return;

  try {
    const resp = await fetch("/profile-registry.json", { cache: "no-store" });
    if (!resp.ok) return;
    const registry: ProfileRegistry = await resp.json();
    const entry = registry[nodeId];
    if (!entry) return;

    saveJSON(PROFILE_KEY, {
      displayName: entry.displayName ?? "",
      title: entry.title ?? "",
      bio: entry.bio ?? "",
      status: entry.status ?? "online",
      x_handle: entry.x_handle,
      x_url: entry.x_url,
      avatarDataUrl: entry.avatarDataUrl,
    });
    localStorage.setItem(SEEDED_KEY, "true");
  } catch {
    // Registry not bundled or malformed — leave profile empty.
  }
}
