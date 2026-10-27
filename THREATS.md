# THREATS.md

How TrustVault could be broken, what was done about each one, and which risks
were knowingly accepted. Written to be read alongside the code; every claim
here has a test in `tests/integration.test.mjs` unless marked otherwise.

Format: **Threat → what stops it → residual risk.**

## 1. Direct object access (IDOR)

**Threat:** a user who was never granted a document tries to reach it by id —
listing, fetching by id, fetching its versions, its grants, its bytes.

**What stops it:** Postgres RLS on `documents`, `document_versions`,
`grants`, `audit_log`. The policies only allow: the owner, an active admin, or
the holder of a *live* grant. Every request re-evaluates them; there is no
application layer with a cache to bypass. The only byte route, the `serve-doc`
edge function, independently re-checks the grant before streaming.

**Tests:** "viewer cannot list…", "…fetch by id (IDOR)", "…download via
serve-doc", "…see document versions", "…read the grants".

**Residual:** none known.

## 2. Hidden UI ≠ security

**Threat:** the SPA hides buttons from viewers, and someone calls the API
directly.

**What stops it:** the frontend is treated as untrusted entirely. The anon key
in `app/config.js` is public by design — it identifies the project, not a user.
All authorisation is in RLS policies, triggers and the edge functions, all of
which run server-side per request.

## 3. Storage bucket direct access

**Threat:** the SPA only *talks* to `serve-doc`, but the underlying storage
bucket has its own API. A judge might try `GET /storage/v1/object/documents/…`
with the anon key, or with a valid session, or try to upload straight into the
bucket to smuggle a file into the app.

**What stops it:** the bucket is private and has **no storage policies for
client roles at all** (default deny). Only the service role — used exclusively
inside the edge functions, never shipped to the browser — can read/write it.

**Tests:** "storage objects are not directly downloadable".

**Residual:** none known.

## 4. Signed-URL leakage (why there are no signed URLs)

**Threat:** most file-serving designs hand the browser a pre-signed URL that
lives for minutes or hours; a revocation then doesn't stop a holder mid-flight.

**What stops it:** TrustVault never issues signed URLs. `serve-doc` streams the
bytes itself and re-checks the grant *per request*. The cost: bytes flow
through the function (latency, function memory) — accepted, because
"revocation is immediate" is a hard requirement and a cached URL is a grace
period.

**Test:** "grant → access works; revoke → the very next request is refused".

## 5. Privilege escalation

**Threats:**

- A viewer PATCHes their own `profiles` row to `role = 'admin'`.
- An edit-grant holder grants themselves (or others) more access.
- A user grants themselves access to any document by inserting a grant row.
- An edit-grant holder takes over a document (changes owner, storage path,
  status, or sha256).

**What stops it:**

- `profiles` UPDATE is admin-only by RLS, plus a trigger re-checks role /
  `is_active` changes.
- `grants` INSERT is allowed only for the document's owner or an admin (RLS),
  and a validation trigger rejects grants to the owner or to inactive users.
- `documents` UPDATE for edit-holders is limited by trigger to title, category,
  description — attempts to change owner, path, status, hash or size raise an
  exception. RLS separately limits who can update at all.
- The `grants` UPDATE policy only permits revocation, the validation trigger
  makes revoked rows immutable, and `revoked_by` must equal the calling user.

**Tests:** "viewer cannot escalate their role", "viewer cannot grant
themselves access", "edit-grant holder cannot grant access to others",
"edit-grant holder can change title but not owner, status or storage path",
"revoked grants cannot be re-activated".

## 6. Audit trail tampering

**Threat:** an attacker (or a curious admin) edits the audit trail to hide a
read: `UPDATE audit_log SET actor_email=…` or `DELETE FROM audit_log`.

**What stops it, in layers:**

1. `audit_log` has RLS: SELECT for admins only; no INSERT/UPDATE/DELETE
   policies for client roles at all.
2. `UPDATE`/`DELETE` privileges are revoked from `authenticated`/`anon`.
3. A `BEFORE UPDATE OR DELETE` trigger raises an exception for **every** role —
   including the table owner and the service role.
4. The writer function `tv_internal.audit_write` is not exposed via PostgREST
   (private schema; the public wrapper has `EXECUTE` revoked from client roles,
   granted only to `service_role`).
5. Each row's hash covers the previous row's hash; the admin "verify chain"
   function recomputes the whole chain. Editing one row breaks every later
   hash, and deleting a middle row breaks the link. Deleting the **last**
   row (tail truncation) is *not* detectable from the chain alone — there is
   no external checkpoint of the head hash in this build; noted below as a
   residual risk.
6. Concurrency is serialised with an advisory lock so two simultaneous events
   cannot fork the chain.

**Tests:** "viewer cannot forge an audit entry", "viewer cannot read the audit
log", "audit rows cannot be updated or deleted by any client role", "the hash
chain verifies".

**Residual (accepted):** an attacker with the database owner's credentials
could rewrite the chain and recompute hashes — the chain is tamper-*evident*
against anyone below the DBA, not tamper-*proof* against the DBA. A HMAC with
a key outside the database would raise the bar; noted as future work. Tail
truncation (deleting the newest entries) is also undetectable without a
trusted external record of the head hash — a production build would
checkpoint it (e.g. daily digest published out-of-band). Also:
`seq` values come from a sequence, so gaps appear when transactions roll back —
gaps are normal and the verifier tolerates them (it checks linkage, not
contiguity).

## 7. Existence oracle / information leakage

**Threat:** "does document X exist" is itself sensitive (e.g. a salary letter).
Error responses that distinguish "no such document" from "you may not see it"
leak existence; so do timing differences.

**What stops it:** `serve-doc` returns the same `404` for missing documents,
deleted documents and refused accesses. RLS makes hidden rows simply absent
from query results (empty set, not an error). Document titles of *other
people's* audit entries are visible only to admins (audit SELECT is
admin-only).

**Residual (accepted):** timing side channels remain in principle (a granted
download streams bytes; a refused one returns instantly) — accepted as out of
scope for this build. Also, the *grants you can see* leak the directory (see
#10). One further honest limitation: **only download attempts through
`serve-doc` are appended to the audit chain when refused** (`doc.download_denied`).
RLS-filtered metadata reads and direct storage-API denials are blocked, but
Postgres does not give us a hook to append them to the chain — they are
visible in Supabase's own logs, not ours. Accepted for this build.

## 8. Upload attacks

**Threats:**

- Upload an executable/script disguised as an allowed type.
- Path traversal via filename or crafted `storage_path`.
- Huge files (DoS) or zip bombs.
- Type confusion: new version changes a PDF into something else.

**What stops it:** content-type allowlist (PDF, PNG, JPEG, DOCX, XLSX, PPTX,
TXT, CSV, MD); magic-byte sniffing for binary types (text types are checked for
NUL bytes / non-printable ratios); extension must match the declared type; 25 MB
cap; filenames sanitised and storage paths generated server-side from UUIDs
(a validation trigger rejects any `documents` row whose path does not match
`docs/<uuid>/<version>/<safe-name>`); new versions must keep the original
content type.

**Tests:** "uploads with disallowed content types are rejected", "uploads
whose magic bytes contradict the declared type are rejected", "uploads over
25 MB are rejected", "storage paths are server-generated and validated".

**Residual (accepted):** a DOCX/XLSX is a ZIP — we verify the ZIP magic but do
not deep-inspect its contents (e.g. embedded macros). Stored files are served
with `Content-Disposition: attachment` and their true content type, and the
bucket is not public, so browser-rendered malicious content requires the user
to download and open it — accepted for this build; real deployment would add
antivirus scanning.

## 9. Session and token attacks

**Threat:** JWT forgery, token theft, CSRF.

**What stops it:** JWTs are issued and verified by Supabase Auth (HS/RS-signed;
the anon key cannot mint them). API calls carry the token in the
`Authorization` header — not cookies — so CSRF does not apply. Edge functions
call `getUser()` against the auth server rather than trusting header claims.

**Residual (accepted):** access tokens live ~1 hour and refresh tokens are
rotating browser-side. A stolen *live* token cannot be revoked before expiry —
but this does not violate the challenge rules: revoking a **grant** is
immediate for every route (the token only authenticates *who you are*, not
*what you may see*). Deactivating a user additionally cuts off all their
document access immediately even with a live token (tested).

## 10. User-directory enumeration

**Threat:** any signed-in user can list `profiles` (needed so owners can pick
grantees), revealing emails and roles.

**Decision:** accepted — this is a single-tenant company tool; a staff
directory is a feature (like Slack's). If the product went multi-tenant this
policy would change to per-tenant directories.

## 11. Login attacks

**Threat:** brute-force password guessing, credential stuffing.

**What stops it:** Supabase Auth rate-limits per IP and per account, and
handles lockouts. Successful logins are audited via a trigger on
`auth.users`.

**Residual (accepted):** *failed* logins are visible in Supabase's own logs
but cannot be appended to our hash chain (the auth service rejects the
transaction when a client trigger raises — we discovered this the hard way;
see PROMPTS.md). Accepted and documented rather than papered over.

## 12. SECURITY DEFINER / search-path hijack

**Threat:** Supabase-era classic — a `SECURITY DEFINER` function with an open
`search_path` can be hijacked by creating shadow objects in a writable schema.

**What stops it:** every internal function is `SECURITY DEFINER` with a locked
`search_path` (`tv_internal, public, extensions`) and schema-qualified table
references; the `tv_internal` schema is not writable or exposed to client
roles. Client-callable RPCs (`verify_audit_chain`, `suggest_access`)
re-check the caller's role inside the function body.

## 13. Deactivation races

**Threat:** an employee leaves; their links "still work".

**What stops it:** deactivation is not just a flag: it bulk-revokes every live
grant (each revocation audited), all RLS policies additionally require the
caller's profile to be active, and `serve-doc` refuses inactive users. Their
existing session token stops working for document access immediately.

**Test:** "deactivating a user revokes all their grants immediately".

## 14. Denial of service

**Threat:** flood uploads, huge listings, audit flooding.

**Residual (accepted):** rate limiting is left to the platform (edge function
concurrency, Supabase quotas). Not a 7-day priority; noted honestly.

## 15. Things we thought about and decided NOT to build

- **Folder / group inheritance.** Per-document grants are the simplest model
  that can be *proven*; inheritance multiplies the states an auditor must
  reason about. Deliberate scope cut — the challenge's own words: a smaller
  system whose permission model holds.
- **Public share links** (share-with-anyone-outside URLs). The single largest
  source of leaks in real products; requires expiring links, leak tokens,
  revocation semantics — a product of its own. Not built.
- **Client-side encryption** (keys held by users). Would make auditing
  meaningless (the server can't see who read what it can't decrypt) and breaks
  the audit requirement. Not built.
- **Document previews rendered server-side.** Would require parsing untrusted
  PDFs/office files on the server — a classic RCE surface. The SPA offers
  download-only. Not built.
