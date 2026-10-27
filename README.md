# TrustVault

**Secure document sharing with a real audit trail.**

Documents are only reachable by the people they were granted to — enforced by the
database on every request, not by the frontend. Every access, including every
*refused* access, is written to an append-only, hash-chained audit log. Revoking
access takes effect on the person's very next request.

## Live demo

The deployed instance (with seed data):

**https://trustvault.mounika-sripathi.workers.dev** — see the URL in the
"Deployment" section of this README for the current address, and use the
credentials below.

Demo accounts (one per role):

| Email | Password | Role |
|---|---|---|
| `admin@trustvault.demo` | `TrustVault!Admin2026` | administrator |
| `alice@trustvault.demo` | `TrustVault!Alice2026` | document owner |
| `bob@trustvault.demo` | `TrustVault!Bob2026` | document owner |
| `carol@trustvault.demo` | `TrustVault!Carol2026` | viewer |
| `dave@trustvault.demo` | `TrustVault!Dave2026` | viewer |

Seed data: six documents owned by Alice and Bob, with a mix of live grants
(Carol and Dave), one deliberately private document per owner, an edit-grant
example (Carol can edit Bob's price list), and a version history on the floor
plan.

## What it does

- **Authentication** with three roles: administrator, document owner, viewer.
  Viewers can read what they were granted; owners can additionally upload and
  manage their documents and grants; admins can additionally manage users and
  read the audit log.
- **Upload, organise, search** documents (by name, owner, category, date range).
- **Per-document grants** — `read` or `edit` — given to named people, by the
  document's owner or an admin.
- **Owners grant and revoke** access; revocation is immediate (see below).
- **Nobody else can read, download, change or delete** a document — through any
  route: the REST API, the storage API, the edge functions, or direct table
  access. The database decides, every time.
- **Audit trail** of uploads, downloads, changes, deletions, permission changes,
  logins and refused attempts — append-only and hash-chained, with an admin
  "verify chain" function.
- **Upload validation**: content-type allowlist, magic-byte sniffing, size cap,
  server-generated storage paths.
- **Administrative views** of document activity, permission changes and users.
- **Automated tests** proving one user cannot reach another's documents — and
  that removing any authorisation check breaks the tests.

## Architecture

```
Browser (static SPA)
   │  (anon key is public by design; a session JWT identifies the user)
   ├─ PostgREST  ──►  Postgres: documents, grants, versions, audit_log
   │                    └─ Row Level Security decides every read/write
   ├─ Edge functions ─► serve-doc   (file bytes; re-checks grants per request)
   │                    upload-doc (validation + storage)
   │                    vault-admin (user management, hard delete)
   └─ Supabase Auth     (sessions; a DB trigger audits logins)
```

Key decisions (full reasoning in `DESIGN.md`, threats in `THREATS.md`):

- **Postgres RLS is the authorisation engine.** Every table has RLS enabled and
  every policy is evaluated per request. There is no application server holding
  cached permissions that could drift.
- **File bytes never get public URLs or long-lived signed URLs.** The only route
  out is the `serve-doc` edge function, which verifies the session, re-reads the
  grants table, and streams the bytes. A revocation therefore stops downloads
  immediately — there is nothing outstanding to expire.
- **The audit log is append-only by trigger** — `UPDATE`/`DELETE` raise an
  exception for *every* role — and each row's hash covers the previous row's
  hash, so deletions and edits are detectable by the admin "verify chain"
  function.
- **The "AI suggestion" surface only suggests.** It lists people who already see
  the owner's other documents in the same category; widening access always
  requires the owner's explicit grant, and both the suggestion and the decision
  are audited.

## Repository layout

```
app/                        the SPA (no build step, vendored supabase-js)
supabase/migrations/        SQL migrations (schema, RLS, triggers, seed users)
supabase/functions/         edge functions (serve-doc, upload-doc, vault-admin)
tests/integration.test.mjs  security + functionality tests (run against live)
tests/ui-smoke.mjs          browser smoke test (Playwright)
scripts/make-samples.mjs    generates the demo documents
scripts/seed.mjs            seeds documents + grants through the public API
THREATS.md                  threat model: found, fixed, accepted
PROMPTS.md                  AI usage log, written as the week went on
API.md                      endpoint-by-endpoint authorisation table
DESIGN.md                   the write-up: choices, trade-offs, gaps
```

## Running the tests

The integration tests run against the deployed instance (they exercise the
real attack surface, which is the point):

```bash
SUPA_URL=https://<project>.supabase.co \
SUPA_ANON_KEY=<anon-key> \
node --test tests/integration.test.mjs
```

The UI smoke test serves `app/` locally and drives a real browser:

```bash
npm install
node tests/ui-smoke.mjs
```

**Mutation check.** The challenge says: take one authorisation check out and
run the tests. Every check is covered — for example, removing
`tv_internal.has_any_grant` from the `documents_select` policy fails
"viewer cannot list documents…"; removing the `revoked_at is null` predicate
fails "revocation is immediate"; removing the grant check inside `serve-doc`
fails "viewer cannot download…"; removing the audit-lock trigger fails
"audit rows cannot be updated or deleted".

## Deploying from a clean clone

The stack is a Supabase project plus a static frontend.

1. **Create a Supabase project** (free tier is fine) and note its URL and
   anon key.
2. **Apply the migrations** in order — via the dashboard SQL editor, the
   Supabase CLI (`supabase db push`), or the MCP `apply_migration` tool:
   `supabase/migrations/0001_schema.sql` … `0010_profiles_trigger_service_path.sql`.
3. **Deploy the edge functions**:
   ```bash
   supabase functions deploy serve-doc --no-verify-jwt=false
   supabase functions deploy upload-doc
   supabase functions deploy vault-admin
   ```
   (Or paste each `supabase/functions/*/index.ts` into the dashboard.)
4. **Configure the frontend**: put the project URL and anon key in
   `app/config.js`.
5. **Host `app/` anywhere static** (GitHub Pages, Netlify, any object storage).
6. **Seed demo data** (optional): `node scripts/make-samples.mjs && node scripts/seed.mjs`
   with `SUPA_URL`/`SUPA_ANON_KEY` pointing at your project. It creates the
   five users (already created by migration `0006`), uploads the sample
   documents through the public API, and creates the sample grants.

### Deployment of this instance

- Supabase project: `dymcermbpcbthimiokba` (region `us-east-1`, free tier).
- Frontend: published static site (URL at the top of this README).
- Free-tier note: Supabase pauses projects after ~1 week of inactivity; opening
  the dashboard (or the URL) restores it. If the API answers with a cold-start
  error, retry once.

## Demo video

`demo/trustvault-demo.mp4` in this repository walks through sign-in, grants,
revocation, denied-access auditing and chain verification (5 minutes).

## Honest gaps

Documented in full in `DESIGN.md` (§ "What is unfinished") and `THREATS.md`
(§ "Accepted risks"). The short version: no folder/group model (deliberate),
no public share links (deliberate), failed login attempts are rate-limited by
Supabase Auth but not recorded in our audit chain, and single-tenant only.
