/** Group management view — glass cards with expandable member lists. */

import { createSignal, createResource, For, Show } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { api } from "../stores/auth";
import type { RoomResponse } from "../api/types";
import { setPendingConversation, refreshRooms } from "../stores/rooms";
import { toast } from "../stores/toast";
import { IconGroups, IconTrash } from "./Icons";

export default function Groups() {
  const navigate = useNavigate();
  const [roomsData, { refetch }] = createResource<RoomResponse[]>(
    () => api.listRooms(),
  );
  const [showCreate, setShowCreate] = createSignal(false);
  const [newName, setNewName] = createSignal("");
  const [expandedRoom, setExpandedRoom] = createSignal<string | null>(null);
  const [members, setMembers] = createSignal<string[]>([]);
  const [addMemberId, setAddMemberId] = createSignal("");
  const [confirmDelete, setConfirmDelete] = createSignal<string | null>(null);

  const handleCreate = async (e: Event) => {
    e.preventDefault();
    const name = newName().trim();
    if (!name) return;
    try {
      await api.createRoom({ name });
      setNewName("");
      setShowCreate(false);
      refetch();
      refreshRooms();
      toast.success("Group created");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to create group");
    }
  };

  const toggleExpand = async (roomId: string) => {
    if (expandedRoom() === roomId) {
      setExpandedRoom(null);
      return;
    }
    setExpandedRoom(roomId);
    const m = await api.listRoomMembers(roomId);
    setMembers(m);
  };

  const handleAddMember = async (roomId: string) => {
    const id = addMemberId().trim();
    if (!id) return;
    try {
      await api.addRoomMember(roomId, id);
      setAddMemberId("");
      const m = await api.listRoomMembers(roomId);
      setMembers(m);
      toast.success("Member added");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to add member");
    }
  };

  const handleRemoveMember = async (roomId: string, nodeId: string) => {
    try {
      await api.removeRoomMember(roomId, nodeId);
      const m = await api.listRoomMembers(roomId);
      setMembers(m);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to remove member");
    }
  };

  const handleDeleteRoom = async (roomId: string) => {
    try {
      await api.deleteRoom(roomId);
      setConfirmDelete(null);
      setExpandedRoom(null);
      refetch();
      refreshRooms();
      toast.success("Group deleted");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to delete group");
    }
  };

  return (
    <div class="page content-max">
      <div class="page-header">
        <h2 class="page-title">Groups</h2>
        <div class="flex gap-8">
          <button class="btn btn-secondary btn-sm" onClick={refetch}>
            Refresh
          </button>
          <button
            class="btn btn-primary btn-sm"
            onClick={() => setShowCreate(!showCreate())}
          >
            {showCreate() ? "Cancel" : "Create Group"}
          </button>
        </div>
      </div>

      {/* Create group form */}
      <Show when={showCreate()}>
        <form
          onSubmit={handleCreate}
          class="card animate-fade-in flex gap-8 items-center mb-20"
        >
          <input
            type="text"
            value={newName()}
            onInput={(e) => setNewName(e.currentTarget.value)}
            placeholder="Group name..."
            class="flex-1"
          />
          <button
            type="submit"
            class="btn btn-primary btn-sm"
            disabled={!newName().trim()}
          >
            Create
          </button>
        </form>
      </Show>

      {/* Loading */}
      <Show when={roomsData.loading}>
        <div class="empty-state">
          <div class="skeleton mb-8" style={{ height: "40px" }} />
          <div class="skeleton" style={{ height: "40px" }} />
        </div>
      </Show>

      {/* Group list */}
      <For
        each={roomsData()}
        fallback={
          <Show when={!roomsData.loading}>
            <div class="empty-state">
              <div class="empty-state-icon"><IconGroups size={32} /></div>
              <div class="empty-state-title">No groups yet</div>
              <div class="empty-state-desc">
                Create a group to start group conversations. Add members by their Node ID.
              </div>
            </div>
          </Show>
        }
      >
        {(room) => (
          <div class="card animate-fade-in mb-8 p-0 overflow-hidden">
            <div class="room-header-row">
              <button
                onClick={() => toggleExpand(room.id)}
                class="flex-1 text-left"
                aria-label={`Toggle details for ${room.name}`}
              >
                <div class="font-medium">{room.name}</div>
                <div class="mono text-xs text-muted mt-2">
                  {room.id}
                </div>
              </button>
              <div class="icon-text">
                <button
                  class="btn btn-primary btn-sm"
                  onClick={() => {
                    setPendingConversation({ key: room.id, isRoom: true });
                    refreshRooms();
                    navigate("/chat");
                  }}
                >
                  Chat
                </button>
                <span class="text-xs text-muted">
                  {room.created_at}
                </span>
              </div>
            </div>

            <Show when={expandedRoom() === room.id}>
              <div class="animate-fade-in room-card-body">
                <div class="text-sm font-medium text-secondary mb-8">
                  Members ({members().length})
                </div>
                <For each={members()}>
                  {(member) => (
                    <div class="room-member-row">
                      <span class="mono text-sm">{member}</span>
                      <button
                        class="btn btn-danger btn-sm"
                        onClick={() => handleRemoveMember(room.id, member)}
                        aria-label={`Remove member ${member.slice(0, 8)}`}
                      >
                        Remove
                      </button>
                    </div>
                  )}
                </For>
                <div class="room-add-row">
                  <input
                    type="text"
                    value={addMemberId()}
                    onInput={(e) => setAddMemberId(e.currentTarget.value)}
                    placeholder="Node ID to add..."
                    class="mono flex-1"
                    style={{ "font-size": "12px" }}
                  />
                  <button
                    class="btn btn-secondary btn-sm"
                    onClick={() => handleAddMember(room.id)}
                    disabled={!addMemberId().trim()}
                  >
                    Add
                  </button>
                </div>
                {/* Delete group */}
                <div class="mt-12 pt-12" style={{ "border-top": "1px solid var(--glass-border)" }}>
                  <Show when={confirmDelete() === room.id} fallback={
                    <button
                      class="btn btn-danger btn-sm icon-text"
                      onClick={() => setConfirmDelete(room.id)}
                    >
                      <IconTrash size={12} /> Delete Group
                    </button>
                  }>
                    <div class="flex items-center gap-8">
                      <span class="text-xs text-error">Delete this group permanently?</span>
                      <button
                        class="btn btn-danger btn-sm"
                        onClick={() => handleDeleteRoom(room.id)}
                      >
                        Confirm
                      </button>
                      <button
                        class="btn btn-ghost btn-sm"
                        onClick={() => setConfirmDelete(null)}
                      >
                        Cancel
                      </button>
                    </div>
                  </Show>
                </div>
              </div>
            </Show>
          </div>
        )}
      </For>
    </div>
  );
}
