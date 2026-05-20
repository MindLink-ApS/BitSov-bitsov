/**
 * MessageDeliveryState — 5-stage delivery indicator for sent messages.
 *
 * Stages: Encrypting -> Paying -> Sent -> Delivered -> Read
 *
 * Each stage has a distinct icon and color to show message progress
 * through the sovereign pipeline: E2EE encryption, Lightning payment,
 * network delivery, and read receipt.
 */

export type DeliveryStage = "encrypting" | "paying" | "sent" | "delivered" | "read";

interface MessageDeliveryStateProps {
  stage: DeliveryStage;
}

function EncryptingIcon() {
  return (
    <svg viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <circle cx="6" cy="6" r="4.5" stroke="currentColor" stroke-width="1.2" stroke-dasharray="4 3" />
    </svg>
  );
}

function PayingIcon() {
  return (
    <svg viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <path d="M7 2L4.5 6.5H6.5L5.5 10L8.5 5.5H6.8L7 2Z" fill="currentColor" />
    </svg>
  );
}

function SentIcon() {
  return (
    <svg viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <path d="M2.5 6.5L5 9L9.5 3.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round" />
    </svg>
  );
}

function DeliveredIcon() {
  return (
    <svg viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <path d="M1.5 6.5L4 9L8.5 3.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round" />
      <path d="M4.5 6.5L7 9L11.5 3.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round" />
    </svg>
  );
}

function ReadIcon() {
  return (
    <svg viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <path d="M1.5 6.5L4 9L8.5 3.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round" />
      <path d="M4.5 6.5L7 9L11.5 3.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round" />
    </svg>
  );
}

import type { JSX } from "solid-js";

const STAGE_CONFIG: Record<DeliveryStage, { icon: () => JSX.Element; label: string }> = {
  encrypting: { icon: () => <EncryptingIcon />, label: "Encrypting" },
  paying: { icon: () => <PayingIcon />, label: "Paying" },
  sent: { icon: () => <SentIcon />, label: "Sent" },
  delivered: { icon: () => <DeliveredIcon />, label: "Delivered" },
  read: { icon: () => <ReadIcon />, label: "Read" },
};

export default function MessageDeliveryState(props: MessageDeliveryStateProps) {
  const cfg = () => STAGE_CONFIG[props.stage];

  return (
    <span class={`delivery-state ${props.stage}`} title={cfg().label} aria-label={cfg().label}>
      {cfg().icon()}
    </span>
  );
}
