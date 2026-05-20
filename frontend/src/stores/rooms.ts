/**
 * Rooms store — caches room list and provides name lookup.
 *
 * Used by ChatView to display room names and by Rooms view to navigate
 * to room conversations.
 */

import { createSignal } from "solid-js";
import { createStore } from "solid-js/store";
import type { RoomResponse } from "../api/types";
import { api } from "./auth";

/** Cached rooms indexed by ID. */
const [roomsById, setRoomsById] = createStore<Record<string, RoomResponse>>({});

/** Signal to request ChatView to open a specific conversation. */
const [pendingConversation, setPendingConversation] = createSignal<{
  key: string;
  isRoom: boolean;
} | null>(null);

/** Load rooms from the API and cache them. */
export async function refreshRooms(): Promise<void> {
  try {
    const rooms = await api.listRooms();
    const byId: Record<string, RoomResponse> = {};
    for (const room of rooms) {
      byId[room.id] = room;
    }
    setRoomsById(byId);
  } catch {
    // Room loading failed — UI shows stale or empty data
  }
}

/** Get a room name by ID, or null if not cached. */
export function getRoomName(roomId: string): string | null {
  return roomsById[roomId]?.name ?? null;
}

/** Check whether a conversation key is a room UUID (contains dashes). */
export function isRoomKey(key: string): boolean {
  // UUIDs have dashes (e.g. "550e8400-e29b-41d4-a716-446655440000")
  // Node IDs are 64-char hex without dashes
  return key.includes("-");
}

export { pendingConversation, setPendingConversation, roomsById };
