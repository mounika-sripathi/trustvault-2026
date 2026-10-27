# PROMPTS.md — How I Used AI, Honestly

AI assistance was used throughout this build. This log records what the AI
assistant actually did, the prompts that produced it, and — most importantly —
the mistakes it made, how they were caught, and how they were fixed.

Each entry notes: what was asked of the AI, what the AI did, and what had to
be corrected. Most corrections below were caught by reviewing and testing the
AI's output (running the migrations, the login flow, the smoke tests) rather
than by the AI on its own initiative — that review loop is the point of this
file.

## A note on the timeline

This project was built in a single intensive working session (October 27,
2026), with heavy AI assistance throughout — which is exactly what this log
documents. The git history therefore shows one day of structured commits
rather than a week of gradual ones; the entries below are in the order things
actually happened during that session. Nothing here is backdated.

## Entries

### Entry 1 — October 27, 2026 — Designing the permission model

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

**What had to be corrected:** the first proposal stored files encrypted with
per-document keys in the database — that would have made auditing downloads
meaningless and complicated revocation. The design was pushed toward
"RLS + private bucket + streaming function", which is what got built.


### Entry 2 — October 27, 2026 — Initial schema and RLS policies

**What I asked:** "Write the migrations: documents, grants, profiles,
audit_log with hash chaining, plus RLS policies for owners, admins, and grant
holders."

**What the AI did:** produced migration `0001_schema.sql` (tables, indexes),
`0002_vault_functions.sql` (audit writer + chain verification), and the first
RLS policies. Solid work on the policy logic.

**What had to be corrected:** the first draft put the internal helper functions
in a schema named `vault` — that collides with Supabase's built-in `vault`
schema, and on first apply Postgres reported `permission denied for schema
vault`. It also granted broad privileges that were unnecessary. The fix: rename
the schema to `tv_internal`, revoke the accidental grants, and pin
`search_path` on every `SECURITY DEFINER` function. The AI did not notice the
collision on its own — it surfaced when the migration was actually applied.


### Entry 3 — October 27, 2026 — Edge functions and the upload pipeline

**What I asked:** "Write the upload-doc edge function: auth check, owner or
edit grant check, content-type allowlist, magic-byte sniffing, 25MB cap, safe
storage path. And serve-doc: re-check the grant per request and stream bytes."

**What the AI did:** both functions, with the type sniffing table and the
server-generated storage path (`docs/<uuid>/<version>/<name>`).

**What had to be corrected:** the first draft of `serve-doc` checked the grant
and then constructed a storage URL from user-supplied input for the *version*
parameter — a path injection risk. It was rewritten so every path segment comes
from a server query, never from the request. The "missing and refused return
the same 404" rule was also added — the first draft leaked which documents
exist.


### Entry 4 — October 27, 2026 — AI bug caught: `digest()` not resolving in SECURITY DEFINER context

**Prompt:** "Fix this error: SQLSTATE 42883 function digest(text, unknown) does
not exist — it only happens inside the audit writer."

**What happened:** the hash-chain writer used pgcrypto's `digest()` and it
failed at runtime even though pgcrypto was installed and in the `search_path`.
The first proposed fix was to recreate pgcrypto — which would have broken
Supabase's managed extension state. The real cause: inside a `SECURITY
DEFINER` function, `digest(text, unknown)` was being resolved with an
ambiguous argument type.

**Fix (verified):** replaced it with Postgres 11+'s native
`pg_catalog.sha256()` — no extension dependency at all. This is a genuine AI
error, caught by running the code rather than by the AI itself; the original
approach was the AI's suggestion.


### Entry 5 — October 27, 2026 — Seed users and GoTrue

**What I asked:** "Seed the demo accounts — one owner, two more, an admin —
with real bcrypt password hashes. Roles must live in profiles, not in the JWT."

**What the AI did:** wrote `0006_seed_users.sql` inserting directly into
`auth.users` and `public.profiles`.

**What had to be corrected (second AI bug caught):** logins returned
"Database error querying schema" with a 500. The first diagnosis blamed the
email confirmation flow and suggested disabling confirmations — the wrong
direction for a security challenge. Supabase's auth logs showed the actual
error: a scan failure on `auth.users` because the seed rows had NULL in the
token columns that GoTrue's query expects to coalesce. Fixed by writing empty
strings for `confirmation_token`, `recovery_token` and the `*_sent_at`
columns — the values GoTrue itself writes for confirmed accounts. Left as
first drafted, the AI would have shipped a broken login.


### Entry 6 — October 27, 2026 — The UI, and a state leak

**What I asked:** "Build the single-page app: login, document list with
filters, upload form, grants management, audit log viewer for admins, and an
AI-suggested-access box for owners."

**What the AI did:** the whole SPA in `app/`.

**What had to be corrected:** the first draft had a module-level filter state
that leaked between user sessions (Alice logged out, Carol logged in, and
Carol saw Alice's filter chip still applied). Found by a UI smoke test, not by
the AI and not by any unit assertion. Fixed by resetting the filter state on
login. The output escaping helper was also re-checked — the initial version
had entity strings mangled by the generation process, which would have broken
text rendering.


### Entry 7 — October 27, 2026 — The suggestion trap, and defense-in-depth backfiring

**Prompt:** "Add suggest_access for owners: based on prior activity, suggest
who might need access. The AI must never be able to widen access on its own —
no auto-grant."

**What the AI did:** the RPC (owner-only, suggestions audited, never applied).

**What had to be corrected (third AI-related incident):** the defense-in-depth
trigger on `profiles` — which re-checks that role changes are admin-made —
blocked the *admin edge function itself* when deactivating a user, because the
service-role connection has no `auth.uid()`. The AI flagged the error but
proposed removing the trigger entirely. Instead the fix was to exempt the
no-session (service-key) path from the trigger check, which is safe because
RLS already requires an active session for every client path to `profiles`,
so only the service key — used solely by the `vault-admin` edge function,
which re-verifies the caller is an admin before using it — can reach the
trigger with no session. The trigger stays for every other path. This is
exactly the kind of shortcut an unattended AI takes — remove the security
control that's inconvenient — and it's why the `vault-admin` function exists
as the only service-key user, with per-action authorization before the key
is used.


### Entry 8 — October 27, 2026 — Test hardening (the "take one check out" test)

**What I asked:** "Write integration tests covering: grant → access →
revoke → immediate refusal; every cross-user denial route (list, fetch, versions,
grants, download, storage direct); audit tampering; privilege escalation;
upload validation; deactivation."

**What the AI did:** the 31-test suite.

**What had to be corrected:** the first draft asserted *200-with-zero-rows* as
a failure for RLS denial cases — wrong: PostgREST returns 200 with an empty
array when RLS silently filters rows. An "access denied" test that only
checks status codes proves nothing. Those tests were rewritten to assert the
returned array is empty *and* that a follow-up direct fetch proves the row
exists but is filtered. A bug in the revoke endpoint call was also caught —
PostgREST needed `select=seq` so the response returns data; the first draft
returned only headers, making the assertion meaningless. The tampering tests
additionally attempt updates through every role and assert they fail with
RLS errors. These tests are the ones that would catch a removed
authorization check.

### Entry 9 — October 27, 2026 — The last-mile audit review

**Prompt:** "Review the whole codebase for authorization holes: any route that
checks a grant, any place a client role can reach storage, any way to widen
access."

**What the AI did:** found one real issue — the `suggest_access` RPC
referenced a table in a way that required a broad policy — and confirmed the
rest of the surfaces were closed. I also had it re-verify that the storage
bucket exposes no client policies at all.

### Entry 10 — October 27, 2026 — Deployment and demo

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
