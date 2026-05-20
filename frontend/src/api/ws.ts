/** WebSocket client for real-time message delivery. */

import type { WsEnvelope, WsDeliveryStatus, WsHostingEvent } from "./types";

export type WsStatus = "connecting" | "connected" | "disconnected" | "error";
export type WsMessageHandler = (envelope: WsEnvelope) => void;
export type WsDeliveryHandler = (status: WsDeliveryStatus) => void;
export type WsHostingHandler = (event: WsHostingEvent) => void;
export type WsStatusHandler = (status: WsStatus) => void;

export class WsClient {
  private ws: WebSocket | null = null;
  private url: string;
  private messageHandlers: WsMessageHandler[] = [];
  private deliveryHandlers: WsDeliveryHandler[] = [];
  private hostingHandlers: WsHostingHandler[] = [];
  private statusHandlers: WsStatusHandler[] = [];
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private pingTimer: ReturnType<typeof setInterval> | null = null;
  private lastPong = 0;
  private reconnectDelay = 1000;
  private maxReconnectDelay = 30000;
  private shouldReconnect = true;
  /** Ping interval in milliseconds. */
  private readonly pingInterval = 30000;
  /** Maximum time to wait for a pong before considering the connection dead. */
  private readonly pongTimeout = 10000;

  constructor(url: string) {
    this.url = url;
  }

  /** Update the WebSocket URL (e.g., after token refresh). */
  setUrl(url: string): void {
    this.url = url;
  }

  /** Register a handler for incoming messages. */
  onMessage(handler: WsMessageHandler): () => void {
    this.messageHandlers.push(handler);
    return () => {
      this.messageHandlers = this.messageHandlers.filter((h) => h !== handler);
    };
  }

  /** Register a handler for delivery status updates (ack/reject). */
  onDelivery(handler: WsDeliveryHandler): () => void {
    this.deliveryHandlers.push(handler);
    return () => {
      this.deliveryHandlers = this.deliveryHandlers.filter((h) => h !== handler);
    };
  }

  /** Register a handler for operator hosting payment events. */
  onHosting(handler: WsHostingHandler): () => void {
    this.hostingHandlers.push(handler);
    return () => {
      this.hostingHandlers = this.hostingHandlers.filter((h) => h !== handler);
    };
  }

  /** Register a handler for connection status changes. */
  onStatus(handler: WsStatusHandler): () => void {
    this.statusHandlers.push(handler);
    return () => {
      this.statusHandlers = this.statusHandlers.filter((h) => h !== handler);
    };
  }

  /** Connect to the WebSocket endpoint. */
  connect(): void {
    if (this.ws) {
      this.ws.close();
    }

    this.shouldReconnect = true;
    this.notify("connecting");

    try {
      this.ws = new WebSocket(this.url);
    } catch {
      this.notify("error");
      this.scheduleReconnect();
      return;
    }

    this.ws.onopen = () => {
      this.reconnectDelay = 1000;
      this.lastPong = Date.now();
      this.notify("connected");
      this.startPing();
    };

    this.ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data as string);
        // Keepalive pong response
        if (data.type === "pong") {
          this.lastPong = Date.now();
          return;
        }
        // Delivery status events have a "type" field
        if (data.type === "delivery_status" || data.type === "onboarding_progress") {
          const status = data as WsDeliveryStatus;
          for (const handler of this.deliveryHandlers) {
            handler(status);
          }
        } else if (data.type === "operator_hosting_overdue") {
          const event = data as WsHostingEvent;
          for (const handler of this.hostingHandlers) {
            handler(event);
          }
        } else {
          // Regular message envelope
          const envelope = data as WsEnvelope;
          for (const handler of this.messageHandlers) {
            handler(envelope);
          }
        }
      } catch {
        // Ignore unparseable messages
      }
    };

    this.ws.onclose = () => {
      this.ws = null;
      this.stopPing();
      this.notify("disconnected");
      if (this.shouldReconnect) {
        this.scheduleReconnect();
      }
    };

    this.ws.onerror = () => {
      this.notify("error");
    };
  }

  /** Disconnect and stop reconnecting. */
  disconnect(): void {
    this.shouldReconnect = false;
    this.stopPing();
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.notify("disconnected");
  }

  private notify(status: WsStatus): void {
    for (const handler of this.statusHandlers) {
      handler(status);
    }
  }

  private startPing(): void {
    this.stopPing();
    this.pingTimer = setInterval(() => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
      // Check if we received a pong recently
      if (Date.now() - this.lastPong > this.pingInterval + this.pongTimeout) {
        // Connection is stale — force reconnect
        this.ws.close();
        return;
      }
      try {
        this.ws.send(JSON.stringify({ type: "ping" }));
      } catch {
        // Send failed — connection will close via onerror/onclose
      }
    }, this.pingInterval);
  }

  private stopPing(): void {
    if (this.pingTimer) {
      clearInterval(this.pingTimer);
      this.pingTimer = null;
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) return;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, this.reconnectDelay);
    // Exponential backoff with cap
    this.reconnectDelay = Math.min(
      this.reconnectDelay * 2,
      this.maxReconnectDelay,
    );
  }
}
