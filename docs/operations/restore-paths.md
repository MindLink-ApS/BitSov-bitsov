# Restore paths

Three owner-console commands move or recover a node. They are not substitutes.
Static channel backup import (`konsensus scb restore`) always refuses, including
preview. A refusal names `konsensus recover` on the owner console for a lost
disk, and `konsensus move-home` on the owner console when the current live store
is healthy. Coordinating with channel peers is not the recovery route.

The guards below are the checks each command actually runs:

| Command | `ensure_no_move_home` | `ensure_no_recovery` | `ensure_fresh_root` |
| --- | --- | --- | --- |
| `konsensus move-home` | No | Yes | No |
| `konsensus recover` | No | No | Yes, until verification designates a store |
| `konsensus rebind-instance` | Yes | Yes | No |

`ensure_no_move_home` is `konsensus_lightning::ldk::ensure_no_move_home`. It
refuses while `ldk/move-home.json` exists.

`ensure_no_recovery` is the private wrapper in
`crates/konsensus-node/src/restore_fence.rs`. It calls
`konsensus_lightning::recover::ensure_normal_start` and refuses an open,
malformed, or incomplete `ldk/recover.json`.

`ensure_fresh_root` is `konsensus_lightning::recover::ensure_fresh_root`. It
allows only a missing directory or one that holds the recovery journal, host
binding, and recovery session files. A snapshot or live LDK store fails it.

## Healthy live store: move-home

Use `konsensus move-home` when the original node still has its current live disk.
Run it on that store, from the owner console, after the normal service is
stopped. It closes from current channel state and sweeps to an address you
confirm. It does not import a backup and it does not repair a lost disk.

It passes `ensure_no_recovery` through `ensure_bound`. An open recovery journal
refuses the command. It does not pass `ensure_no_move_home`: this command owns
`ldk/move-home.json`, and normal startup keeps refusing while that journal
exists. It does not pass `ensure_fresh_root`. It requires
`ldk/ldk_node_data.sqlite` on the original live store.

## Lost or wiped disk: recover

Use `konsensus recover` when the old node cannot run. Keep that node disabled.
Restore the seed into an empty directory with `konsensus restore`, then preview
and confirm on the owner console. An encrypted SCB is optional and is only a
metadata index. No historical channel manager, monitor, or commitment is loaded.

It passes `ensure_fresh_root` through `ensure_recovery_root` until the journal
designates a verification store; after that, only that marked store is accepted.
It does not pass `ensure_no_move_home` or `ensure_no_recovery`.
`ensure_no_move_home` refuses a move-home journal. `ensure_no_recovery` refuses
an open recovery journal. Recover requires the journal that `konsensus restore`
wrote. Full steps are in [recover](recover.md) and
[the recovery runbook](../v2/RECOVERY.md).

## Latest live store, new machine: rebind-instance

Use `konsensus rebind-instance` only for the latest cleanly stopped live store
after a machine or filesystem move that startup reports as
`host_binding_mismatch`. Confirmation is read from `/dev/tty`. The command does
not construct or start LDK.

It passes `ensure_no_move_home` and `ensure_no_recovery`. An open move-home or
recovery journal refuses the rebind. It does not pass `ensure_fresh_root`.

**rebind-instance does NOT prove freshness.** The typed challenge rewrites the
host binding. It does not show that the directory is the newest channel state.
A backup, snapshot, rsync copy, or disk image can carry the same files, including
`STATE_GENERATION`. Same-host copies are not detected by the binding. Never
rebind a backup or snapshot: a stale commitment can lose the channel balance.
The console warning says this before the challenge.

If the old node is still alive, `rebind-instance` takes the state-generation
lease (`STATE_GENERATION.lock`) and refuses with `state_generation_busy` before
any prompt. Stop the old process and keep it from restarting. The lease is not
a freshness proof either; it only detects another user of this directory.

## Normal startup

`konsensus start` passes `ensure_no_move_home` and `ensure_no_recovery`, and it
checks the host binding. It does not pass `ensure_fresh_root`. A copied
directory on another host or volume is refused before LDK starts. That refusal
points at `konsensus recover` on the owner console in a fresh directory. Do not
delete a journal or `INSTANCE` to get past a guard.
