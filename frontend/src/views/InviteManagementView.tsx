import { createSignal, createResource, For, Show } from "solid-js";
import { api } from "../stores/auth";
import { toast } from "../stores/toast";
import {
  IconPlus,
  IconCopy,
  IconCheck,
  IconX,
  IconClock,
  IconMail,
} from "../components/Icons";
import InviteModal from "../components/InviteModal";
import { formatDate, truncateId } from "../utils/formatting";

/**
 * InviteManagementView — operator-side panel to issue and revoke invites.
 * Lists all invites issued by this node with status and shareable links.
 */
export default function InviteManagementView() {
  const [invites, { refetch }] = createResource(() => api.listIssuedInvites());
  const [showModal, setShowModal] = createSignal(false);
  const [copyingId, setCopyingId] = createSignal<string | null>(null);

  const handleRevoke = async (id: string) => {
    if (!confirm("Are you sure you want to revoke this invite? It will no longer be usable.")) {
      return;
    }
    try {
      await api.revokeIssuedInvite(id);
      toast.success("Invite revoked");
      refetch();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to revoke invite");
    }
  };

  const handleCopyLink = (token: string, id: string) => {
    const link = `bitsov://invite/${token}`;
    navigator.clipboard.writeText(link).then(() => {
      setCopyingId(id);
      setTimeout(() => setCopyingId(null), 2000);
    }).catch(() => {
      toast.error("Failed to copy to clipboard");
    });
  };

  const statusBadgeClass = (state: string) => {
    switch (state) {
      case "pending": return "badge-warning";
      case "accepted": return "badge-success";
      case "opening": return "badge-info";
      case "revoked": return "badge-error";
      case "expired": return "badge-info";
      default: return "badge-info";
    }
  };

  return (
    <div class="page content-max">
      <div class="page-header flex justify-between items-center">
        <h2 class="page-title">Invites</h2>
        <button class="btn btn-primary" onClick={() => setShowModal(true)}>
          <IconPlus size={16} class="mr-6" />
          New Invite
        </button>
      </div>

      <div class="card">
        <div class="card-header">
          <IconMail size={16} class="mr-8" />
          Issued Invites
        </div>
        
        <Show when={!invites.loading} fallback={<div class="skeleton" style={{ height: "200px" }} />}>
          <div class="invite-list">
            <For each={invites()} fallback={
              <div class="empty-state">
                <div class="empty-state-icon"><IconMail size={48} /></div>
                <p>No invites issued yet.</p>
                <button class="btn btn-secondary mt-12" onClick={() => setShowModal(true)}>
                  Create your first invite
                </button>
              </div>
            }>
              {(invite) => (
                <div class="invite-row flex items-center gap-12 p-12 border-b border-subtle last:border-0">
                  <div class="flex-1 min-w-0">
                    <div class="flex items-center gap-8 mb-4">
                      <span class={`badge ${statusBadgeClass(invite.state)}`}>
                        {invite.state}
                      </span>
                      <span class="mono text-sm truncate" title={invite.invitee_pubkey}>
                        {truncateId(invite.invitee_pubkey, 12, 12)}
                      </span>
                    </div>
                    <div class="flex gap-12 text-xs text-muted">
                      <span class="flex items-center gap-4">
                        <IconClock size={12} />
                        Issued {formatDate(invite.created_at)}
                      </span>
                      <span class="flex items-center gap-4">
                        <IconClock size={12} />
                        Expires {formatDate(invite.expiry_unix)}
                      </span>
                    </div>
                  </div>
                  
                  <div class="flex gap-8">
                    <button
                      class="btn btn-ghost btn-sm"
                      onClick={() => handleCopyLink(invite.invite_token_b64, invite.id)}
                      title="Copy invite link"
                    >
                      {copyingId() === invite.id ? <IconCheck size={14} class="text-success" /> : <IconCopy size={14} />}
                      <span class="ml-4">{copyingId() === invite.id ? "Copied" : "Link"}</span>
                    </button>
                    
                    <Show when={invite.state === "pending"}>
                      <button
                        class="btn btn-ghost btn-sm"
                        onClick={() => handleRevoke(invite.id)}
                        title="Revoke invite"
                        style={{ color: "var(--color-error)" }}
                      >
                        <IconX size={14} />
                        <span class="ml-4">Revoke</span>
                      </button>
                    </Show>
                  </div>
                </div>
              )}
            </For>
          </div>
        </Show>
      </div>

      <InviteModal
        show={showModal()}
        onClose={() => setShowModal(false)}
        onSuccess={() => {
          refetch();
        }}
      />
    </div>
  );
}
