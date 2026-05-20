/**
 * AI — Local AI conversation interface.
 * Shows a chat UI with provider connection placeholder.
 * Marked as "Preview" until backend AI integration exists.
 */

import { createSignal, Show, For, onMount, createEffect } from "solid-js";
import type { JSX } from "solid-js";
import {
  IconAI,
  IconSend,
  IconSettings,
  IconUser,
  IconChevronDown,
  IconLightbulb,
  IconPreview,
  IconMessages,
  IconLightning,
  IconShield,
} from "./Icons";
import { loadJSON, saveJSON, loadString, saveString, removeItem } from "../utils/storage";
import VoiceInput from "./VoiceInput";

// ── Types ──────────────────────────────────────────────────────────────

interface ChatMessage {
  id: string;
  role: "user" | "assistant" | "system";
  content: string;
  timestamp: number;
}

interface SuggestedPrompt {
  label: string;
  prompt: string;
  icon: (props?: { size?: number }) => JSX.Element;
}

const SUGGESTED_PROMPTS: SuggestedPrompt[] = [
  {
    label: "Summarize recent messages",
    prompt: "Summarize my recent messages across all peers. Highlight anything that needs my attention.",
    icon: IconMessages,
  },
  {
    label: "Draft a reply",
    prompt: "Help me draft a professional reply to the last message I received.",
    icon: IconSend,
  },
  {
    label: "Explain a payment",
    prompt: "Explain my recent Lightning payment activity. How much have I spent and received?",
    icon: IconLightning,
  },
  {
    label: "Security check",
    prompt: "Review my node's security posture. Are all E2EE sessions healthy? Any concerns?",
    icon: IconShield,
  },
];

// ── Helpers ────────────────────────────────────────────────────────────

function formatTime(ts: number): string {
  return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

// ── Persistence ──────────────────────────────────────────────────────

const AI_MESSAGES_KEY = "konsensus_ai_messages";
const AI_SYSTEM_PROMPT_KEY = "konsensus_ai_system_prompt";
const DEFAULT_SYSTEM_PROMPT =
  "You are a helpful AI assistant for the BitSov sovereign mesh network. You help users manage their node, draft messages, understand payments, and navigate their sovereign workspace.";

function loadMessages(): ChatMessage[] {
  return loadJSON<ChatMessage[]>(AI_MESSAGES_KEY, []);
}

function saveMessages(msgs: ChatMessage[]) {
  saveJSON(AI_MESSAGES_KEY, msgs.slice(-200));
}

function loadSystemPrompt(): string {
  return loadString(AI_SYSTEM_PROMPT_KEY) ?? DEFAULT_SYSTEM_PROMPT;
}

// ── Component ──────────────────────────────────────────────────────────

export default function AIView() {
  const [messages, setMessages] = createSignal<ChatMessage[]>(loadMessages());
  const [input, setInput] = createSignal("");
  const [systemPrompt, setSystemPrompt] = createSignal(loadSystemPrompt());
  const [showSystemPrompt, setShowSystemPrompt] = createSignal(false);
  const [connected, setConnected] = createSignal(false);
  // Voice state — mirrors [ai.voice] config loaded from the node.
  const [allowCloudStt] = createSignal(false);   // default: false (sovereign)
  const [localModelReady] = createSignal(false);  // true once backend confirms Whisper loaded
  const [isResponding, setIsResponding] = createSignal(false);
  let chatEndRef: HTMLDivElement | undefined;

  const scrollToBottom = () => {
    chatEndRef?.scrollIntoView({ behavior: "smooth" });
  };

  // Persist messages and scroll on change
  createEffect(() => {
    const msgs = messages();
    saveMessages(msgs);
    scrollToBottom();
  });

  const handleSend = () => {
    const text = input().trim();
    if (!text) return;

    // Add user message
    const userMsg: ChatMessage = {
      id: crypto.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`,
      role: "user",
      content: text,
      timestamp: Date.now(),
    };

    setMessages(prev => [...prev, userMsg]);
    setInput("");
    setIsResponding(true);

    // Since no provider is connected, show a placeholder response
    if (!connected()) {
      setTimeout(() => {
        const aiMsg: ChatMessage = {
          id: crypto.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`,
          role: "assistant",
          content: "Connect an AI provider in Settings to enable intelligent responses. This preview shows the conversation interface that will be available once a provider (Claude, Grok, or a local model) is configured.",
          timestamp: Date.now(),
        };
        setMessages(prev => [...prev, aiMsg]);
        setIsResponding(false);
      }, 500);
    }
  };

  // Receives transcript from VoiceInput and inserts it into the compose field.
  const handleTranscript = (text: string) => {
    setInput(prev => (prev.trim() ? `${prev} ${text}` : text));
  };

  const handleSuggested = (prompt: string) => {
    setInput(prompt);
  };

  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div class="page ai-page">
      {/* Header */}
      <div class="page-header">
        <h2 class="page-title flex items-center gap-8">
          <IconAI size={20} /> AI Assistant
          <span class="preview-badge">Preview</span>
        </h2>
        <div class="flex items-center gap-8">
          <Show when={messages().length > 0}>
            <button
              class="btn btn-ghost btn-sm"
              onClick={() => {
                setMessages([]);
                removeItem(AI_MESSAGES_KEY);
              }}
              title="Clear conversation"
              aria-label="Clear conversation"
            >
              Clear
            </button>
          </Show>
          <button
            class="btn btn-ghost btn-sm"
            onClick={() => setShowSystemPrompt(!showSystemPrompt())}
            title="System prompt"
            aria-label="Toggle system prompt"
          >
            <IconSettings size={14} />
          </button>
        </div>
      </div>

      {/* System Prompt (collapsible) */}
      <Show when={showSystemPrompt()}>
        <div class="card ai-system-prompt mb-12">
          <div class="card-header flex items-center gap-8">
            <IconSettings size={14} /> System Prompt
          </div>
          <textarea
            class="ai-system-textarea"
            value={systemPrompt()}
            onInput={(e) => {
              setSystemPrompt(e.currentTarget.value);
              saveString(AI_SYSTEM_PROMPT_KEY, e.currentTarget.value);
            }}
            rows={3}
            placeholder="Customize the AI's personality and role..."
          />
        </div>
      </Show>

      {/* Chat area */}
      <div class="ai-chat-container">
        <Show when={messages().length > 0} fallback={
          <div class="ai-empty-state">
            <div class="ai-empty-icon">
              <IconAI size={48} />
            </div>
            <h3 class="text-lg font-semibold mb-8">
              Sovereign AI Interface
            </h3>
            <p class="text-sm text-secondary text-center leading-loose mb-24" style={{ "max-width": "400px" }}>
              Connect an AI provider to get intelligent assistance within your sovereign workspace. All conversations stay local to your node.
            </p>

            {/* Provider status */}
            <div class="ai-provider-card">
              <div class="ai-provider-status">
                <span class="status-dot status-dot-offline" />
                <span class="text-sm">No provider connected</span>
              </div>
              <div class="text-xs text-muted mt-4">
                Configure in Settings: Claude, Grok, Codex, or local model
              </div>
            </div>

            {/* Suggested prompts */}
            <div class="ai-suggestions">
              <div class="text-xs text-muted mb-8">
                <IconLightbulb size={12} style={{ "vertical-align": "middle", "margin-right": "4px" }} />
                Try a suggestion
              </div>
              <div class="ai-suggestion-grid">
                <For each={SUGGESTED_PROMPTS}>
                  {(prompt) => (
                    <button
                      class="ai-suggestion-btn"
                      onClick={() => handleSuggested(prompt.prompt)}
                      aria-label={prompt.label}
                    >
                      <span class="ai-suggestion-icon">{prompt.icon({ size: 14 })}</span>
                      <span class="text-xs">{prompt.label}</span>
                    </button>
                  )}
                </For>
              </div>
            </div>
          </div>
        }>
          {/* Messages */}
          <div class="ai-messages">
            <For each={messages()}>
              {(msg) => (
                <div class={`ai-message ai-message-${msg.role}`}>
                  <div class="ai-message-avatar">
                    {msg.role === "user"
                      ? <IconUser size={16} />
                      : <IconAI size={16} />
                    }
                  </div>
                  <div class="ai-message-content">
                    <div class="ai-message-header">
                      <span class="text-xs font-semibold">
                        {msg.role === "user" ? "You" : "AI"}
                      </span>
                      <span class="text-xs text-muted">{formatTime(msg.timestamp)}</span>
                    </div>
                    <div class="ai-message-text text-sm whitespace-pre-wrap">
                      {msg.content}
                    </div>
                  </div>
                </div>
              )}
            </For>
            <div ref={chatEndRef} />
          </div>
        </Show>
      </div>

      {/* Compose */}
      <div class="ai-compose">
        {/* Voice input row */}
        <VoiceInput
          onTranscript={handleTranscript}
          allowCloudStt={allowCloudStt()}
          localModelReady={localModelReady()}
          disabled={isResponding()}
        />

        <div class="ai-compose-inner">
          <textarea
            class="ai-compose-input"
            value={input()}
            onInput={(e) => setInput(e.currentTarget.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask your AI assistant..."
            rows={1}
          />
          <button
            class="ai-compose-send"
            onClick={handleSend}
            disabled={!input().trim()}
            title="Send message"
            aria-label="Send message"
          >
            <IconSend size={16} />
          </button>
        </div>
        <div class="text-xs text-muted text-center mt-4">
          All conversations are local to your node. No data leaves your sovereign workspace.
        </div>
      </div>
    </div>
  );
}
