# API.md — TrustVault API & Authorization Map

Base URL: `https://<project>.supabase.co`
SPA: the deployed live URL.

Authentication: Supabase Auth. Every request carries `Authorization: Bearer
<access_token>`. Roles live in `public.profiles` (checked server-side per
request), NOT in the JWT — so a role change takes effect immediately.

## Authorization model in one paragraph

All authorization is enforced by **Postgres RLS policies evaluated on every
request**, plus triggers and two edge functions. There is no application
server holding permission state, so there is nothing to bypass or get out of
sync. The storage bucket has **no client policies** — the only way to bytes is
the `serve-doc` edge function, which re-checks the grant per request. Refused
accesses return the same `404` as missing documents (no existence oracle).

## Endpoints

### 1. `POST /auth/v1/token` — login
`password` grant with `email` + `password`.
**Authorization:** public (invalid credentials rejected by Supabase Auth;
rate-limited). Successful logins are audited via a trigger on `auth.users`.

### 2. `GET /rest/v1/documents?select=…` — list documents
**Authorization:** RLS — returns only documents the caller owns, has a live
grant on, or (admins) all documents. No grant → the row simply does not appear
(no error, no existence leak).
**Test:** viewer's list excludes ungranted documents.

### 3. `POST /rest/v1/documents` — create document record
**Authorization:** RLS — any authenticated active user (they become the
owner). Storage-path and size columns are validated by trigger
(server-generated pattern `docs/<uuid>/<version>/<name>`).

### 4. `GET /rest/v1/documents?id=eq.<uuid>` — fetch one document
**Authorization:** RLS — owner, active admin, or live-grant holder only.
Ungranted caller gets **200 with an empty array** (row filtered), not a 403 —
this is intentional (no oracle); the test proves the row exists but is
filtered.
**Test:** viewer cannot fetch an ungranted document by id (IDOR).

### 5. `PATCH /rest/v1/documents?id=eq.<uuid>` — update metadata
**Authorization:** RLS — owner, admin, or **edit**-grant holder.
**Extra rule (trigger):** edit-grant holders may change only `title`,
`category`, `description`. Attempts to change `owner_id`, `storage_path`,
`status`, `content_type`, `size_bytes` or `sha256` raise an exception.
**Test:** edit-holder can change title, cannot change owner/status/path.

### 6. `GET /rest/v1/document_versions?document_id=eq.<uuid>` — list versions
**Authorization:** RLS — same as documents (owner/admin/live grant).
**Test:** viewer cannot see versions of an ungranted document.

### 7. `GET /rest/v1/grants?document_id=eq.<uuid>` — list grants on a document
**Authorization:** RLS — owner, admin, or holder of a live grant on that
document. A viewer with a read grant can see the grant list (transparency) but
cannot modify it.
**Test:** viewer cannot read grants of an ungranted document.

### 8. `POST /rest/v1/grants` — grant access
**Authorization:** RLS — only the document's owner or an admin can insert.
Trigger validates: grantee is not the owner; grantee is active; document_id
exists. Grants are audited.
**Test:** viewer cannot grant themselves access; edit-holder cannot grant
others.

### 9. `PATCH /rest/v1/grants?id=eq.<uuid>&revoked_at=is.null` — revoke
**Authorization:** RLS — only the revoking user may update, and only their own
revocations; trigger enforces the row is currently live and sets
`revoked_by` to the caller. Revoked grants are immutable afterwards.
Revocation is **immediate** — the very next request is refused.
**Tests:** revoke → next request refused; revoked grant cannot be re-activated.

### 10. `POST /functions/v1/upload-doc` — upload document bytes (new or new version)
**Authorization (in order, all enforced before the service key is used):**
1. valid user session (verified against auth server);
2. user active;
3. for a new version: caller is owner, active admin, or holds an **edit**
   grant on that document; new versions must keep the original content type;
4. content checks: allowlist (pdf/png/jpg/docx/xlsx/pptx/txt/csv/md), magic
   bytes sniffed for binary types, 25 MB cap, filename sanitised.
Only then is the service role used to write to the private bucket. The
`storage_path` is **server-generated** (never from the client).
**Tests:** wrong content type rejected; mismatched magic bytes rejected;
oversized rejected; ungranted caller rejected; paths validated.

### 11. `POST /functions/v1/serve-doc` — download / stream bytes
Body: `{ document_id, version }`.
**Authorization:** verified session → user active → re-check live grant (or
owner/admin) **on this request** → stream bytes from the private bucket
through the function. No signed URLs are ever issued, so there is nothing to
leak or outlive a revocation.
**Response:** granted → bytes with `Content-Disposition: attachment`;
missing, deleted, ungranted or inactive → **identical 404**.
Every attempt — granted or refused — is audited (`doc.download` /
`doc.download_denied`).
**Tests:** viewer download via serve-doc refused; grant→works; revoke→next
request refused.

### 12. `GET /storage/v1/object/documents/…` — storage direct (documented to be refused)
**Authorization:** the private bucket has **no client policies** — default
deny for the anon key and authenticated sessions. Bytes are reachable only
through `serve-doc`.
**Test:** direct storage GET returns 400/403.

### 13. `POST /rest/v1/rpc/verify_audit_chain` — verify the audit hash chain
**Authorization:** RLS — admin only (checked inside the function against
`auth.uid()`).
Returns `{ ok, head_seq, head_hash, entries }`.

### 14. `GET /rest/v1/audit_log?select=…` — read the audit log
**Authorization:** RLS — admins only. Non-admins get an empty array.
**Tests:** viewer cannot read audit log; viewer cannot forge an entry.

### 15. `POST /rest/v1/rpc/suggest_access` — AI-suggested grants (owners)
**Authorization:** RLS — document owner only (checked inside the function).
Suggestions are **display-only**: nothing is applied, no grant is created, no
policy widened. Viewing suggestions is itself audited. The "machine must never
widen access on its own" rule holds by construction.

### 16. `POST /functions/v1/vault-admin` — user administration
Actions: `create_user`, `deactivate_user`, `activate_user`, `reset_password`,
`purge_document`.
**Authorization:** the caller's session is verified as an active **admin
before the service role key is used** (per-action check). All three edge
functions hold the service key server-side and never ship it to the browser;
this is the only one that performs user-administration actions, and each
action re-verifies the admin first. `deactivate_user` bulk-revokes all the user's live grants immediately (each
audited).
**Test:** deactivation revokes all grants immediately (access cut off even
with a live token).

### 17. `GET /rest/v1/profiles` — staff directory
**Authorization:** RLS — any authenticated active user (owners need it to pick
grantees). UPDATE is admin-only (plus trigger re-check). See THREATS.md #10 for
the accepted enumeration tradeoff.
**Test:** viewer cannot escalate their own role.
