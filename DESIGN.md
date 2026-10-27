# DESIGN.md — The Short Write-Up

## The permission model, in my own words

A document is reachable if and only if the server, **on this specific
request**, can prove the caller is allowed. That proof is a live row in
`grants` — owner, admin, or a grant that has not been revoked and whose holder
has not been deactivated. The check happens in Postgres RLS policies, which
evaluate on every single request, and again inside the `serve-doc` edge
function before a single byte is streamed. There is no application server
holding permission state, no cache, and no signed URL whose lifetime could
outlive a revocation.

Everything follows from one decision: the check lives in the database, at
the edge of the data. When the SPA asks "what documents exist for me?", the
answer is filtered by the same policies that guard the rows themselves. When
a download request arrives, the edge function re-derives the right to see
that document at that moment. When a grant is revoked, the next request
finds no live grant and gets the same 404 as if the document never existed.

Proving who reached something is the mirror image: every meaningful event —
grants, revocations, uploads, downloads, refused downloads, logins, admin
actions, suggestion views — appends one row to `audit_log`, and each row's
hash covers the previous row's hash. Nobody below the DBA can edit a row
without breaking the chain, and the chain is verifiable by one admin
endpoint from the UI.

## What was built

- Per-document grants with two permission levels (read / edit), immutable
  after revocation.
- A private storage bucket with no client policies; bytes flow only through
  the `serve-doc` edge function.
- An append-only, hash-chained audit log with admin-visible viewer and
  chain verification.
- Upload validation: content-type allowlist, magic-byte sniffing, 25 MB cap,
  server-generated storage paths.
- User administration (create, deactivate, reset password) via a single
  admin-gated edge function; deactivation immediately revokes every grant.
- An owner-facing, display-only "suggested access" feature (AI never widens
  access on its own).
- A 31-test integration suite covering every cross-user denial route, audit
  tampering, escalation, upload validation and revocation immediacy, plus a
  UI smoke test.
- Documentation: README, THREATS, PROMPTS, API map, this file.

## What was not built (and why)

- **Folder/group inheritance** — per-document grants are the smallest model
  that can be proven; inheritance multiplies the states an auditor must
  reason about.
- **Public share links** — the largest leak source in real products; needs
  expiring links and leak-token semantics of its own.
- **Client-side encryption** — keys held by users would make server-side
  auditing meaningless.
- **Server-side document previews** — parsing untrusted office files on the
  server is a classic RCE surface; the app is download-only.

## How AI was used

Extensively, and with the mistakes documented in PROMPTS.md. The pattern that
worked: the AI produced drafts fast; my job was to *not trust them* — the
`vault` schema collision, the `digest()` resolution failure, the GoTrue
NULL-token seed bug, and the "remove the inconvenient security control"
suggestion in the admin path were all caught by testing and review, not by
the AI. The two most valuable AI contributions were the initial architecture
(proposal of RLS-as-engine + streaming function + hash chain) and the attack
enumeration pass. The most dangerous was its instinct to remove a security
trigger when it conflicted with a feature — a reminder that an AI optimizing
for "make the error go away" will happily delete the control causing it.

## Unfinished / known gaps

- **Timing:** the challenge window was Oct 19–25, 2026, and the brief asked
  for a deploy early in the week. This build was done in a single session on
  October 27, 2026 — the window and the "deploy early" requirement are
  honestly unmet, and the git history (one day of commits) shows it.
- **Mutation testing, demonstrated:** the challenge says "take one
  authorisation check out of your code and run your tests — if they still
  pass, they were not testing anything." We did exactly that against the live
  deployment: the grant check was removed from the `documents_select` policy,
  the suite was run (3 cross-user tests failed: viewer listing, IDOR, revoke
  immediacy), the policy was restored, and the suite went back to 31/31. The
  unedited transcript is `tests/mutation-demo.txt`.
- Timing side channels between granted and refused downloads are not
  normalized (accepted, THREATS.md #7).
- Refusal auditing covers `serve-doc` download attempts only; RLS-filtered
  metadata reads and direct storage denials are blocked but not appended to
  our hash chain (accepted, THREATS.md #7).
- Failed logins are not in our hash chain (Supabase Auth rejects the
  transaction when a client trigger raises; discovered during the build,
  PROMPTS.md Entry 5 follow-up).
- No server-side antivirus scanning of uploads (accepted, THREATS.md #8).
- Rate limiting is delegated to the platform rather than implemented in-app.
