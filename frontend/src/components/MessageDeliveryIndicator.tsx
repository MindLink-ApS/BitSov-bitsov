/**
 * MessageDeliveryIndicator — delivery status for a sent message bubble.
 *
 * Shows a rejection icon (red ×) when the message was rejected by the
 * recipient's payment gate, or delegates to MessageDeliveryState for all
 * other stages.
 */

import { Show } from "solid-js";
import { getDeliveryStatus, getRejectionReason } from "../stores/messages";
import MessageDeliveryState from "./MessageDeliveryState";
import type { DeliveryStage } from "./MessageDeliveryState";
import type { MessageResponse } from "../api/types";

interface MessageDeliveryIndicatorProps {
  msg: MessageResponse;
  stage: DeliveryStage;
}

export default function MessageDeliveryIndicator(props: MessageDeliveryIndicatorProps) {
  return (
    <Show
      when={getDeliveryStatus(props.msg.id) === "rejected"}
      fallback={<MessageDeliveryState stage={props.stage} />}
    >
      <span
        class="delivery-rejected"
        role="status"
        title={`Rejected: ${getRejectionReason(props.msg.id) ?? "unknown"}`}
        aria-label={`Message rejected: ${getRejectionReason(props.msg.id) ?? "unknown"}`}
      >
        <svg
          viewBox="0 0 12 12"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          aria-hidden="true"
          style="width:12px;height:12px"
        >
          <path
            d="M3 3L9 9M9 3L3 9"
            stroke="var(--color-error, #ef4444)"
            stroke-width="1.5"
            stroke-linecap="round"
          />
        </svg>
      </span>
    </Show>
  );
}
