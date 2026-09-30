# Legacy introduction & unbound invite — migration note

**Date:** 2026-09-30  
**Related:** ADR-029, PROTOCOL-VS-APP-AUDIT.md items (a) and (b), FrontDoorCard.

## Invites — unbound `InviteToken` removed

| Removed | Use instead |
|---|---|
| `POST /api/v1/invite` | `POST /api/v1/invites` (issue a **BitSovInvite** bound to `invitee_pubkey`) |
| `POST /api/v1/invite/redeem` | `POST /api/v1/invites/accept` |

The removed URLs answer **410 Gone** with `Deprecation: true`, a `Link` to the successor, and JSON `code: legacy_invite_removed`. The wire type `InviteToken` (`konsensus://invite/…` base58) remains in `konsensus-core` for offline parsing of old tokens; the node no longer issues or redeems them.

Canonical invites are invitee-bound (`BitSovInvite`, `bitsov://invite/…`).

## Profile cards — FrontDoorCard is canonical

| Prefer | Still present (deprecated as a *profile* surface) |
|---|---|
| `GET/POST /api/v1/front-door` (+ `/verify`, `/open`, publish) | `GET/POST /api/v1/introduction` (+ `/verify`, `/open`) |

`FrontDoorCard` is the single user-facing profile card. Introduction routes stay live because:

1. The **sponsor / starter-bitcoin** kit still signs offers onto `bitsov://introduce` cards (`/api/v1/sponsor/*`).
2. **bitsov-app** still hosts `introduction_mine` / `introduction_read` / `introduction_open` for that kit (not for Browse/profile UX).

Successful introduction responses include `Deprecation: true` and `Link: </api/v1/front-door>; rel="successor-version"`. New profile UX should call front-door only; do not remove introduction until the app sponsor path no longer depends on it.
