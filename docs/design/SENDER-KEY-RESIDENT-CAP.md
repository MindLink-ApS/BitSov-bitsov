# Sender-key resident sub-cap

Status: design proposal; no runtime change. Follow-up to [#473](https://github.com/MindLink-ApS/BitSov-bitsov/pull/473).

## Current behavior

In [`sender_keys.rs`](../../crates/konsensus-crypto/src/sender_keys.rs),
`MAX_TOTAL_SKIPPED_KEYS = 2000` bounds retained skipped message keys across
all receiver-side senders in one `GroupSession`. `MAX_SKIP = 256` bounds the
gap accepted by a single decrypt; repeated advances can retain more than
256 keys for one sender. There is no separate per-sender resident limit.

After signature verification and successful AEAD authentication, a chain
advance commits its staged keys with monotonically increasing session-wide
insertion sequence numbers. `evict_excess_skipped_keys` then removes the
oldest inserted keys across all senders until the total is at most 2,000.
The bound describes retained state after the operation, not peak allocation
during staging or insertion. Victims are selected by insertion age, not
message number or map iteration order, and wiped in place before removal.
Successful delayed decryption consumes its skipped key; failed
authentication does not commit state or trigger eviction. A distribution
update clears that sender's skipped keys; member removal wipes its
receiver entry before removal. Neither rewinds
the session-wide insertion sequence. Group sessions are in memory only.

The shared budget creates an availability tradeoff: one noisy sender can
displace other senders' in-flight skipped keys. A delayed message whose key
has been evicted returns the existing `DecryptionFailed` error; future
in-order messages can still decrypt. Retained-key capacity is not a
delivery guarantee.

## Option A: accept the shared pool as designed

Keep the existing limits and global FIFO eviction. This bounds retained
key count with a simple policy and lets an active sender use otherwise
idle capacity. It also preserves the present tolerance for multiple
reordered windows from one sender. The rationale is reasonable if the
group accepts shared eviction as a best-effort delivery policy and does
not require isolation between senders. The cost is that one sender may
occupy all 2,000 slots and displace every other sender's retained keys.

## Option B: add a per-sender resident sub-cap

Propose `MAX_SENDER_SKIPPED_KEYS = 256` for each sender identity in a
`GroupSession`, independent of the existing `MAX_SKIP = 256`. Keep both
`MAX_SKIP` and `MAX_TOTAL_SKIPPED_KEYS = 2000` unchanged. This retains one
maximum-sized skipped window per sender. Seven full 256-key windows fit
within the shared budget (1,792 keys); an eighth full window requires 48
shared evictions. No capacity is reserved or preallocated per member.

For each authenticated chain advance, apply these steps in order:

1. Commit the staged chain and skipped keys with the existing session-wide
   insertion sequence. Preserve authentication-before-mutation behavior.
2. If that sender exceeds 256 resident keys, evict its own oldest inserted
   keys until it holds 256. Use `remove_skipped` to wipe before removal.
3. Recount the session. If it exceeds 2,000 keys, run the existing global
   oldest-inserted eviction across the remaining keys.

Local trimming must precede shared trimming: a sender already holding
256 keys replaces its own older keys without causing shared eviction.
Keep consumption, distribution reset and member removal semantics, and
keep the global sequence monotonic across resets. Retained state after
each operation must satisfy both limits. No wire or persistence format
change is needed; peers need not negotiate this local retention policy.

This reduces a single sender's residency to 12.8% of the shared budget,
but does not provide complete isolation. A sender below its sub-cap can
still cause shared eviction when the session is full, and aggregate
pressure from several senders still evicts globally. A quieter group also
loses the ability to lend unused slots beyond 256 to one sender, reducing
that sender's delayed-message tolerance. The key-count limits do not bound
map allocation bytes or the number of group members.

## Recommendation and implementation test plan

Recommend **Option B**, in a separate implementation change. A complete
maximum-gap window remains available to a sender, while additional windows
first consume that sender's own retention budget. Prefer this predictable
tradeoff to allowing one sender to occupy the whole pool. The value 256 is
an initial policy choice, not a measured traffic optimum; validate it
against expected reordering before deployment. This note adopts no new
runtime behavior and changes no existing tests or assertions.

The implementation should add or strengthen tests for:

- **Local boundary and victim order:** retain exactly 256 keys for one
  sender; on overflow, pin the last evicted and first retained insertion
  sequences. Confirm retained messages decrypt once and evicted messages
  fail.
- **Isolation and eviction order:** with another sender's skipped keys
  retained, refill a sender already at 256. Assert the other sender's keys
  still decrypt. Repeat with the shared pool exactly full so running
  shared eviction before local trimming is detected.
- **Shared boundary:** use at least eight senders so each is within 256
  while the total reaches and exceeds 2,000. Assert both limits after
  every operation and pin both sides of the global FIFO cutoff. Use a
  multi-sender fixture that distinguishes insertion age from message number.
- **Lifecycle and authentication:** consume retained keys; reset and
  remove a sender; refill after reset and verify sequence ordering across
  senders. Failed signatures, failed AEAD and gaps above `MAX_SKIP` must
  leave keys, counters and other senders' decryptability unchanged. Verify
  that the local eviction path wipes stored keys before removal.

The new sub-cap tests must fail against the current implementation and
pass after implementation. Run the full crypto crate tests and clippy
with warnings denied. Revert-mutation checks should independently remove
the local trim, reverse local/shared trim order, alter the cutoff, and
bypass the wipe; each must fail a targeted test. Preserve existing
assertions; any base test whose shared-only policy conflicts with the new
policy needs a separately explained decision before implementation.
