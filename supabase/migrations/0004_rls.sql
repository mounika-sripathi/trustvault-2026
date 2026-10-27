-- TrustVault: row level security
--
-- The server decides, every time. Every table below has RLS enabled and
-- every policy is evaluated on every request — there is no cached
-- permission anywhere in the stack. Revoking a grant changes what the
-- very next query returns, which is what "immediate" means here.

alter table public.profiles         enable row level security;
alter table public.documents        enable row level security;
alter table public.document_versions enable row level security;
alter table public.grants           enable row level security;
alter table public.audit_log        enable row level security;

-- ============================================================
-- profiles: readable directory for signed-in users (a single-tenant
-- company directory — you cannot share a document with someone you
-- cannot see). Only admins can modify.
-- ============================================================
create policy profiles_select on public.profiles
  for select to authenticated
  using (true);

create policy profiles_update_admin on public.profiles
  for update to authenticated
  using (tv_internal.is_admin())
  with check (tv_internal.is_admin());

-- ============================================================
-- documents
-- ============================================================

-- Who can see a document row: admins, the owner (including their
-- soft-deleted documents, so they can restore), and holders of a live
-- grant — but only while the document is active.
create policy documents_select on public.documents
  for select to authenticated
  using (
    tv_internal.is_admin()
    or owner_id = auth.uid()
    or (status = 'active' and tv_internal.has_any_grant(id, auth.uid()))
  );

-- Only active admins/owners can create document rows.
create policy documents_insert on public.documents
  for insert to authenticated
  with check (tv_internal.can_manage_docs());

-- Updates: admin, owner, or a live *edit* grant on an active document.
-- The tg_documents_protect trigger further limits what edit-grant
-- holders may change.
create policy documents_update on public.documents
  for update to authenticated
  using (
    tv_internal.is_admin()
    or owner_id = auth.uid()
    or (status = 'active' and tv_internal.has_grant(id, auth.uid(), 'edit'))
  )
  with check (
    tv_internal.is_admin()
    or owner_id = auth.uid()
    or (status = 'active' and tv_internal.has_grant(id, auth.uid(), 'edit'))
  );

-- No client DELETE policy at all: hard deletion (with byte removal)
-- is only possible through the tv_internal-admin edge function, which
-- verifies, removes storage objects and versions, and audits.
-- Soft delete is an UPDATE (status='deleted') and is audited by trigger.

-- ============================================================
-- document_versions: same read visibility as the parent document
-- ============================================================
create policy document_versions_select on public.document_versions
  for select to authenticated
  using (
    tv_internal.is_admin()
    or exists (
      select 1 from public.documents d
      where d.id = document_id
        and (d.owner_id = auth.uid()
             or (d.status = 'active' and tv_internal.has_any_grant(d.id, auth.uid())))
    )
  );
-- no client insert/update/delete policies: rows are created only by
-- the upload-doc edge function (service role)

-- ============================================================
-- grants
-- ============================================================

-- Who can see a grant: admins, the grantee (their own access), and
-- the document's owner.
create policy grants_select on public.grants
  for select to authenticated
  using (
    tv_internal.is_admin()
    or user_id = auth.uid()
    or exists (
      select 1 from public.documents d
      where d.id = document_id and d.owner_id = auth.uid()
    )
  );

-- Who can grant: the document's owner or an admin.
create policy grants_insert on public.grants
  for insert to authenticated
  with check (
    tv_internal.is_admin()
    or exists (
      select 1 from public.documents d
      where d.id = document_id and d.owner_id = auth.uid()
    )
  );

-- Who can revoke: the document's owner or an admin. The tg_grants_validate
-- trigger guarantees the only permitted change is setting revoked_at/revoked_by.
create policy grants_revoke on public.grants
  for update to authenticated
  using (
    revoked_at is null
    and (
      tv_internal.is_admin()
      or exists (
        select 1 from public.documents d
        where d.id = document_id and d.owner_id = auth.uid()
      )
    )
  )
  with check (
    revoked_at is not null
    and revoked_by = auth.uid()
    and (
      tv_internal.is_admin()
      or exists (
        select 1 from public.documents d
        where d.id = document_id and d.owner_id = auth.uid()
      )
    )
  );

-- ============================================================
-- audit_log: admins read; nobody writes through this table at all
-- (the tv_internal.audit_write function is the single writer, and it is
-- append-only by trigger)
-- ============================================================
create policy audit_log_select_admin on public.audit_log
  for select to authenticated
  using (tv_internal.is_admin());
