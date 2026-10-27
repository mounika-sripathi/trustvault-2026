# PROMPTS.md — How I Used AI, Honestly

AI assistance was used throughout this build. This log records what the AI
assistant actually did, the prompts that produced it, and — most importantly —
the mistakes it made that I caught, and how they were fixed.

Each entry notes: what I asked, what the AI did, and what I had to correct
myself.

## A note on the timeline

This project was built in a single intensive working session (October 27,
2026), with heavy AI assistance throughout — which is exactly what this log
documents. The git history therefore shows one day of structured commits
rather than a week of gradual ones; the entries below are in the order things
actually happened during that session. Nothing here is backdated.

## Entries

### Entry 1 — Designing the permission model

**What I asked:** "Design the permission model for a document platform. Rules:
a document is reachable only through a grant the owner gave; every route — API,
UI, direct storage access — must enforce this server-side; access must be
provable including refused attempts; revocation must take effect immediately."

**What the AI did:** proposed the core design — one private storage bucket,
RLS policies as the authorization engine evaluated per request, an append-only
audit table with a hash chain, and streaming downloads through an edge
function that re-checks grants (instead of signed URLs). It also suggested
`db internal` helper schema, and warned about the `search_path` hijack risk on
`SECURITY DEFINER` functions.

**What I had to correct:** the AI first proposed storing files encrypted with
per-document keys in the database. I rejected that — it would have made
auditing downloads meaningless and complicated revocation. I pushed it toward
"RLS + private bucket + streaming function", which is what got built.


### Entry 2 — Initial schema and RLS policies

**What I asked:** "Write the migrations: documents, grants, profiles,
audit_log with hash chaining, plus RLS policies for owners, admins, and grant
holders."

**What the AI did:** produced migration `0001_schema.sql` (tables, indexes),
`0002_vault_functions.sql` (audit writer + chain verification), and the first
RLS policies. Solid work on the policy logic.

**What I had to correct:** the AI initially put the internal helper functions in
a schema named `vault` — that collides with Supabase's built-in `vault`
schema, and on first apply Postgres reported `permission denied for schema
vault`. It also granted broad privileges that were unnecessary. I renamed the
schema to `tv_internal`, revoked the accidental grants, and pinned
`search_path` on every `SECURITY DEFINER` function myself. The AI did not
notice the collision on its own.


### Entry 3 — Edge functions and the upload pipeline

**What I asked:** "Write the upload-doc edge function: auth check, owner or
edit grant check, content-type allowlist, magic-byte sniffing, 25MB cap, safe
storage path. And serve-doc: re-check the grant per request and stream bytes."

**What the AI did:** both functions, with the type sniffing table and the
server-generated storage path (`docs/<uuid>/<version>/<name>`).

**What I had to correct:** its first draft of `serve-doc` checked the grant
and then constructed a storage URL from user-supplied input for the *version*
parameter — a path injection risk. I rewrote it so every path segment comes
from a server query, never from the request. I also had it add the "missing
and refused return the same 404" rule — the AI's first draft leaked which
documents exist.


### Entry 4 — AI bug caught: `digest()` not resolving in SECURITY DEFINER context

**Prompt:** "Fix this error: SQLSTATE 42883 function digest(text, unknown) does
not exist — it only happens inside the audit writer."

**What happened:** the AI's hash-chain writer used pgcrypto's `digest()` and
it failed at runtime even though pgcrypto was installed and in the
`search_path`. The AI first suggested recreating pgcrypto — which would have
broken Supabase's managed extension state. I stopped it and found the real
cause myself: inside a `SECURITY DEFINER` function, `digest(text, unknown)`
was being resolved with an ambiguous argument type.

**Fix (mine, verified):** replaced it with Postgres 11+'s native
`pg_catalog.sha256()` — no extension dependency at all. This is a genuine AI
error I caught; the original approach was the AI's suggestion.


### Entry 5 — Seed users and GoTrue

**What I asked:** "Seed the demo accounts — one owner, two more, an admin —
with real bcrypt password hashes. Roles must live in profiles, not in the JWT."

**What the AI did:** wrote `0006_seed_users.sql` inserting directly into
`auth.users` and `public.profiles`.

**What I had to correct (second AI bug caught):** logins returned
"Database error querying schema" with a 500. The AI's first instinct was to
blame the email confirmation flow and suggested disabling confirmations — wrong
direction for a security challenge. I pulled Supabase's auth logs and found the
actual error: a scan failure on `auth.users` because the seed rows had NULL in
the token columns that GoTrue's query expects to coalesce. Fixed by writing
empty strings for `confirmation_token`, `recovery_token` and the
`*_sent_at` columns — the values GoTrue itself writes for confirmed accounts.
The AI would have shipped a broken login.


### Entry 6 — The UI, and a state leak

**What I asked:** "Build the single-page app: login, document list with
filters, upload form, grants management, audit log viewer for admins, and an
AI-suggested-access box for owners."

**What the AI did:** the whole SPA in `app/`.

**What I had to correct:** the first draft had a module-level filter state
that leaked between user sessions (Alice logged out, Carol logged in, and
Carol saw Alice's filter chip still applied). Found by my own UI smoke test,
not by the AI. Fixed by resetting the filter state on login. I also had the
AI re-check its output escaping helper — the initial version had entity
strings mangled by the generation process, which would have broken text
rendering.


### Entry 7 — The suggestion trap, and defense-in-depth backfiring

**Prompt:** "Add suggest_access for owners: based on prior activity, suggest
who might need access. The AI must never be able to widen access on its own —
no auto-grant."

**What the AI did:** the RPC (owner-only, suggestions audited, never applied).

**What I had to correct (third AI-related incident):** my defense-in-depth
trigger on `profiles` — which re-checks that role changes are admin-made —
blocked the *admin edge function itself* when deactivating a user, because the
service-role connection has no `auth.uid()`. The AI flagged the error but
proposed removing the trigger entirely. Instead I exempted the service role
from the trigger check, because the edge function already re-verifies the
caller is an admin before using the service key. The trigger stays for every
other path. This is exactly the kind of shortcut an unattended AI takes —
remove the security control that's inconvenient — and it's why the
`vault-admin` function exists as the only service-key user, with per-action
authorization before the key is used.


### Entry 8 — Test hardening (the "take one check out" test)

**What I asked:** "Write integration tests covering: grant → access →
revoke → immediate refusal; every cross-user denial route (list, fetch, versions,
grants, download, storage direct); audit tampering; privilege escalation;
upload validation; deactivation."

**What the AI did:** the 31-test suite.

**What I had to correct:** the first draft asserted *200-with-zero-rows* as a
failure for RLS denial cases — wrong: PostgREST returns 200 with an empty
array when RLS silently filters rows. An "access denied" test that only
checks status codes proves nothing. I rewrote those to assert the returned
array is empty *and* that a follow-up direct fetch proves the row exists but
is filtered. I also caught an AI bug in the revoke endpoint call — PostgREST
needed `select=seq` so the response returns data; the AI had it returning
only headers, making the assertion meaningless. The tampering tests
additionally attempt updates through every role and assert they fail with
RLS errors. These tests are the ones that would catch a removed
authorization check.

### Entry 9 — The last-mile audit review

**Prompt:** "Review the whole codebase for authorization holes: any route that
checks a grant, any place a client role can reach storage, any way to widen
access."

**What the AI did:** found one real issue — the `suggest_access` RPC
referenced a table in a way that required a broad policy — and confirmed the
rest of the surfaces were closed. I also had it re-verify that the storage
bucket exposes no client policies at all.

### Entry 10 — Deployment and demo

**What I asked:** deploy the app (single static page + edge functions), write
THREATS.md / API.md / DESIGN.md, and record the demo.

**What I did:** the live URL, the docs, and this file.

## Reusable prompts

The prompts that produced real security value, for reuse:

- "Design the permission model so that every route — API, UI, direct storage
  access — enforces the same server-side check. Where does that check live?"
- "For each route, show me the exact code that decides. If it's in the
  frontend, it's not a decision."
- "Now attack it: enumerate every way a user without a grant could reach a
  document. Include the storage API and any admin paths."
- "What does your design leak when a document exists but the caller has no
  grant? Same error as missing? Same timing?"
- "Take any one authorization check out and tell me which test fails."

## What I did not let the AI do

- Give the AI the ability to widen access on its own (the suggestion feature
  is display-only; nothing is applied without an owner).
- Let it store authorization state in the browser.
- Let it "fix" a security control by removing it (see Entry 7).
- Accept an untested migration.
