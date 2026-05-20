/**
 * DisplayName — inline span that renders the best name for a node ID with
 * contextual tooltip hints for alias vs self-claimed vs blocked.
 */

import { contacts } from "../../stores/contacts";
import { displayName } from "../../utils/formatting";

interface DisplayNameProps {
  nodeId: string;
  class?: string;
}

/**
 * Build a tooltip that explains where the displayed name comes from.
 *
 * - If local alias is shown and a claimed name also exists:
 *   "aka <claimed_name> (self-claimed)"
 * - If only claimed name is shown: "(self-claimed)"
 * - If blocked: shown by the name itself; no extra tooltip needed.
 */
function nameTooltip(nodeId: string): string | undefined {
  const contact = contacts.find((c) => c.node_id === nodeId);
  if (!contact) return undefined;
  if (contact.blocked) return "This contact is blocked";
  if (contact.local_alias && contact.claimed_name) {
    return `aka ${contact.claimed_name} (self-claimed)`;
  }
  if (!contact.local_alias && contact.claimed_name) {
    return "Self-claimed name";
  }
  return undefined;
}

export default function DisplayName(props: DisplayNameProps) {
  const name = () => displayName(props.nodeId);
  const tooltip = () => nameTooltip(props.nodeId);
  const isBlocked = () =>
    !!contacts.find((c) => c.node_id === props.nodeId)?.blocked;

  return (
    <span
      class={`display-name${isBlocked() ? " display-name-blocked" : ""}${props.class ? ` ${props.class}` : ""}`}
      title={tooltip()}
    >
      {name()}
    </span>
  );
}
