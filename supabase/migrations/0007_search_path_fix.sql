-- combined re-application to fix search_path (extensions schema)
-- TrustVault: tv_internal schema helpers + audit chain + owner-facing RPCs
--
-- All helpers are SECURITY DEFINER with a locked search_path. This is the
-- standard Supabase pattern to avoid RLS recursion between policies
-- (documents policies reference grants, grants policies reference documents).
-- SECURITY DEFINER functions run as the migration owner (postgres) and
-- therefore see every row; the *policies* decide who may call the statements
-- that reach them.

-- ---------- role helpers ----------

create or replace function tv_internal.is_admin()
returns boolean
language sql stable security definer set search_path = 'tv_internal, public, extensions'
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and p.role = 'admin' and p.is_active
  )
$$;

-- Can create/upload documents: active admin or owner.
create or replace function tv_internal.can_manage_docs()
returns boolean
language sql stable security definer set search_path = 'tv_internal, public, extensions'
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and p.is_active and p.role in ('admin', 'owner')
  )
$$;

-- Does p_user hold a live grant on p_document?
-- p_permission = 'read' matches read or edit grants; 'edit' matches only edit.
create or replace function tv_internal.has_grant(p_document uuid, p_user uuid, p_permission text)
returns boolean
language sql stable security definer set search_path = 'tv_internal, public, extensions'
as $$
  select exists (
    select 1 from public.grants g
    where g.document_id = p_document
      and g.user_id = p_user
      and g.revoked_at is null
      and (p_permission = 'read' or g.permission = 'edit')
  )
$$;

create or replace function tv_internal.has_any_grant(p_document uuid, p_user uuid)
returns boolean
language sql stable security definer set search_path = 'tv_internal, public, extensions'
as $$
  select exists (
    select 1 from public.grants g
    where g.document_id = p_document and g.user_id = p_user and g.revoked_at is null
  )
$$;

create or replace function tv_internal.is_doc_owner(p_document uuid, p_user uuid)
returns boolean
language sql stable security definer set search_path = 'tv_internal, public, extensions'
as $$
  select exists (
    select 1 from public.documents d
    where d.id = p_document and d.owner_id = p_user
  )
$$;

-- ---------- audit chain ----------

-- Append one entry to the hash chain and return its seq.
-- Concurrency: an advisory lock serialises writers so two concurrent
-- entries can never fork the chain (both would otherwise read the same
-- prev_hash).
create or replace function tv_internal.audit_write(
  p_actor uuid,
  p_actor_email text,
  p_action text,
  p_document uuid,
  p_document_title text,
  p_target uuid,
  p_target_email text,
  p_detail jsonb,
  p_ip text,
  p_user_agent text
)
returns bigint
language plpgsql security definer set search_path = 'tv_internal, public, extensions'
as $$
declare
  v_seq bigint;
  v_prev_hash text;
  v_ts timestamptz := clock_timestamp();
  v_hash text;
  v_payload text;
begin
  perform pg_advisory_xact_lock(918273645);

  select a.hash into v_prev_hash from public.audit_log a order by a.seq desc limit 1;
  if v_prev_hash is null then
    v_prev_hash := 'GENESIS';
  end if;

  v_seq := nextval('public.audit_seq');

  v_payload :=
    v_seq::text || '|' ||
    to_char(v_ts, 'YYYY-MM-DD"T"HH24:MI:SS.US') || '|' ||
    coalesce(p_actor::text, '') || '|' ||
    coalesce(p_actor_email, '') || '|' ||
    coalesce(p_action, '') || '|' ||
    coalesce(p_document::text, '') || '|' ||
    coalesce(p_document_title, '') || '|' ||
    coalesce(p_target::text, '') || '|' ||
    coalesce(p_target_email, '') || '|' ||
    coalesce(p_detail::jsonb::text, '{}') || '|' ||
    coalesce(p_ip, '') || '|' ||
    coalesce(p_user_agent, '');

  v_hash := encode(sha256(convert_to(v_prev_hash || '|' || v_payload, 'UTF8')), 'hex');

  insert into public.audit_log (
    seq, ts, actor_id, actor_email, action,
    document_id, document_title, target_user_id, target_email,
    detail, ip, user_agent, prev_hash, hash
  ) values (
    v_seq, v_ts, p_actor, coalesce(p_actor_email, ''), p_action,
    p_document, coalesce(p_document_title, ''), p_target, coalesce(p_target_email, ''),
    coalesce(p_detail, '{}'::jsonb), coalesce(p_ip, ''), coalesce(p_user_agent, ''),
    v_prev_hash, v_hash
  );

  return v_seq;
end;
$$;

-- Walk the whole chain and recompute every hash. Returns ok/checked/first_bad_seq.
create or replace function tv_internal.verify_audit_chain()
returns jsonb
language plpgsql security definer set search_path = 'tv_internal, public, extensions'
as $$
declare
  r record;
  v_prev text := 'GENESIS';
  v_count bigint := 0;
  v_bad bigint := null;
  v_payload text;
  v_hash text;
begin
  for r in select * from public.audit_log order by seq loop
    v_count := v_count + 1;

    v_payload :=
      r.seq::text || '|' ||
      to_char(r.ts, 'YYYY-MM-DD"T"HH24:MI:SS.US') || '|' ||
      coalesce(r.actor_id::text, '') || '|' ||
      coalesce(r.actor_email, '') || '|' ||
      coalesce(r.action, '') || '|' ||
      coalesce(r.document_id::text, '') || '|' ||
      coalesce(r.document_title, '') || '|' ||
      coalesce(r.target_user_id::text, '') || '|' ||
      coalesce(r.target_email, '') || '|' ||
      coalesce(r.detail::jsonb::text, '{}') || '|' ||
      coalesce(r.ip, '') || '|' ||
      coalesce(r.user_agent, '');

    v_hash := encode(sha256(convert_to(v_prev || '|' || v_payload, 'UTF8')), 'hex');

    if r.prev_hash is distinct from v_prev or r.hash is distinct from v_hash then
      v_bad := r.seq;
      exit;
    end if;
    v_prev := r.hash;
  end loop;

  return jsonb_build_object(
    'ok', v_bad is null,
    'checked', v_count,
    'first_bad_seq', v_bad
  );
end;
$$;

-- ---------- public wrappers (callable through PostgREST) ----------

-- Admin-only chain verification, exposed to the SPA.
create or replace function public.verify_audit_chain()
returns jsonb
language plpgsql security definer set search_path = 'tv_internal, public, extensions'
as $$
begin
  if not tv_internal.is_admin() then
    raise exception 'only administrators can verify the audit chain'
      using errcode = '42501';
  end if;
  return tv_internal.verify_audit_chain();
end;
$$;

-- Service-role-only audit writer for the edge functions.
-- EXECUTE is revoked from every client role below; PostgREST enforces
-- EXECUTE privileges, so anonymous/authenticated callers are refused.
create or replace function public.audit_write(
  p_actor uuid,
  p_actor_email text,
  p_action text,
  p_document uuid,
  p_document_title text,
  p_target uuid,
  p_target_email text,
  p_detail jsonb,
  p_ip text,
  p_user_agent text
)
returns bigint
language plpgsql security definer set search_path = 'tv_internal, public, extensions'
as $$
begin
  return tv_internal.audit_write(
    p_actor, p_actor_email, p_action, p_document, p_document_title,
    p_target, p_target_email, p_detail, p_ip, p_user_agent
  );
end;
$$;

revoke execute on function public.audit_write(uuid, text, text, uuid, text, uuid, text, jsonb, text, text) from public, authenticated, anon;
grant  execute on function public.audit_write(uuid, text, text, uuid, text, uuid, text, jsonb, text, text) to service_role;

revoke execute on function tv_internal.audit_write(uuid, text, text, uuid, text, uuid, text, jsonb, text, text) from public, authenticated, anon;
revoke execute on function tv_internal.verify_audit_chain() from public, authenticated, anon;

-- ---------- access suggestions (the "AI assist" surface) ----------
--
-- Suggests people the owner might want to grant access to, based on who
-- already has access to this owner's other documents in the same category.
-- It only *suggests*: widening access always requires the owner to insert
-- a grant row explicitly, and both the suggestion and the decision are
-- written to the audit log.
create or replace function public.suggest_access(p_document uuid)
returns table (user_id uuid, email text, full_name text, reason text)
language plpgsql security definer set search_path = 'tv_internal, public, extensions'
as $$
declare
  v_caller uuid := auth.uid();
  v_doc public.documents%rowtype;
  v_count bigint;
begin
  if v_caller is null then
    raise exception 'authentication required' using errcode = '42501';
  end if;

  select * into v_doc from public.documents d
  where d.id = p_document and d.status = 'active';

  if not found then
    raise exception 'document not found' using errcode = '42503';
  end if;

  if not (tv_internal.is_admin() or v_doc.owner_id = v_caller) then
    raise exception 'only the document owner or an administrator can request suggestions'
      using errcode = '42501';
  end if;

  select count(*) into v_count
  from (
    select p.id
    from public.grants g
    join public.documents d on d.id = g.document_id
    join public.profiles p on p.id = g.user_id
    where d.owner_id = v_doc.owner_id
      and d.category = v_doc.category
      and d.id <> p_document
      and d.status = 'active'
      and g.revoked_at is null
      and p.is_active
      and not exists (
        select 1 from public.grants g2
        where g2.document_id = p_document and g2.user_id = p.id and g2.revoked_at is null
      )
      and not exists (
        select 1 from public.documents d3
        where d3.id = p_document and d3.owner_id = p.id
      )
    group by p.id
  ) c;

  perform tv_internal.audit_write(
    v_caller, '', 'access.suggestion_viewed', p_document, v_doc.title,
    null, '',
    jsonb_build_object('candidate_count', v_count),
    '', ''
  );

  return query
  select p.id, p.email, p.full_name,
         format(
           'Already has access to %s other document(s) of this owner in category ''%s''',
           count(distinct g.document_id), v_doc.category
         )
  from public.grants g
  join public.documents d on d.id = g.document_id
  join public.profiles p on p.id = g.user_id
  where d.owner_id = v_doc.owner_id
    and d.category = v_doc.category
    and d.id <> p_document
    and d.status = 'active'
    and g.revoked_at is null
    and p.is_active
    and not exists (
      select 1 from public.grants g2
      where g2.document_id = p_document and g2.user_id = p.id and g2.revoked_at is null
    )
    and not exists (
      select 1 from public.documents d3
      where d3.id = p_document and d3.owner_id = p.id
    )
  group by p.id, p.email, p.full_name
  limit 5;
end;
$$;
-- TrustVault: refinements after first review
-- 1) every client-facing policy additionally requires an *active* caller,
--    so deactivating a user cuts off document access immediately even for
--    documents they own;
-- 2) new file versions are audited as doc.version_added (the documents
--    trigger detects the version bump instead of logging an empty
--    "doc.updated");
-- 3) audit entries written through PostgREST capture the caller's IP and
--    user agent from PostgREST's request.headers GUC when available.

create or replace function tv_internal.caller_active()
returns boolean
language sql stable security definer set search_path = 'tv_internal, public, extensions'
as $$
  select auth.uid() is not null
     and exists (select 1 from public.profiles p where p.id = auth.uid() and p.is_active)
$$;

-- ---------- policies rebuilt with the active-caller requirement ----------

drop policy documents_select on public.documents;
create policy documents_select on public.documents
  for select to authenticated
  using (
    tv_internal.caller_active()
    and (
      tv_internal.is_admin()
      or owner_id = auth.uid()
      or (status = 'active' and tv_internal.has_any_grant(id, auth.uid()))
    )
  );

drop policy documents_update on public.documents;
create policy documents_update on public.documents
  for update to authenticated
  using (
    tv_internal.caller_active()
    and (
      tv_internal.is_admin()
      or owner_id = auth.uid()
      or (status = 'active' and tv_internal.has_grant(id, auth.uid(), 'edit'))
    )
  )
  with check (
    tv_internal.caller_active()
    and (
      tv_internal.is_admin()
      or owner_id = auth.uid()
      or (status = 'active' and tv_internal.has_grant(id, auth.uid(), 'edit'))
    )
  );

drop policy document_versions_select on public.document_versions;
create policy document_versions_select on public.document_versions
  for select to authenticated
  using (
    tv_internal.caller_active()
    and (
      tv_internal.is_admin()
      or exists (
        select 1 from public.documents d
        where d.id = document_id
          and (d.owner_id = auth.uid()
               or (d.status = 'active' and tv_internal.has_any_grant(d.id, auth.uid())))
      )
    )
  );

drop policy grants_select on public.grants;
create policy grants_select on public.grants
  for select to authenticated
  using (
    tv_internal.caller_active()
    and (
      tv_internal.is_admin()
      or user_id = auth.uid()
      or exists (
        select 1 from public.documents d
        where d.id = document_id and d.owner_id = auth.uid()
      )
    )
  );

drop policy grants_insert on public.grants;
create policy grants_insert on public.grants
  for insert to authenticated
  with check (
    tv_internal.caller_active()
    and (
      tv_internal.is_admin()
      or exists (
        select 1 from public.documents d
        where d.id = document_id and d.owner_id = auth.uid()
      )
    )
  );

drop policy grants_revoke on public.grants;
create policy grants_revoke on public.grants
  for update to authenticated
  using (
    tv_internal.caller_active()
    and revoked_at is null
    and (
      tv_internal.is_admin()
      or exists (
        select 1 from public.documents d
        where d.id = document_id and d.owner_id = auth.uid()
      )
    )
  )
  with check (
    tv_internal.caller_active()
    and revoked_at is not null
    and revoked_by = auth.uid()
    and (
      tv_internal.is_admin()
      or exists (
        select 1 from public.documents d
        where d.id = document_id and d.owner_id = auth.uid()
      )
    )
  );

-- ---------- version uploads get their own audit action ----------

create or replace function tv_internal.tg_documents_audit()
returns trigger language plpgsql security definer set search_path = 'tv_internal, public, extensions'
as $$
declare
  v_actor uuid := auth.uid();
  v_email text := '';
  v_action text;
  v_detail jsonb := '{}'::jsonb;
begin
  if v_actor is not null then
    select p.email into v_email from public.profiles p where p.id = v_actor;
  end if;

  if tg_op = 'INSERT' then
    v_action := 'doc.uploaded';
    v_detail := jsonb_build_object('filename', new.filename, 'category', new.category,
                                   'size_bytes', new.size_bytes, 'sha256', new.sha256,
                                   'version', new.current_version);
  elsif old.status = 'active' and new.status = 'deleted' then
    v_action := 'doc.soft_deleted';
  elsif old.status = 'deleted' and new.status = 'active' then
    v_action := 'doc.restored';
  elsif old.current_version is distinct from new.current_version then
    v_action := 'doc.version_added';
    v_detail := jsonb_build_object('version', new.current_version,
                                   'filename', new.filename,
                                   'size_bytes', new.size_bytes,
                                   'sha256', new.sha256);
  else
    v_action := 'doc.updated';
    v_detail := jsonb_build_object('changes',
      (select coalesce(jsonb_object_agg(key, value), '{}'::jsonb)
       from jsonb_each(to_jsonb(new)) n(key, value)
       where n.key in ('title', 'category', 'description')
         and to_jsonb(old) -> n.key is distinct from n.value));
  end if;

  perform tv_internal.audit_write(v_actor, v_email, v_action, new.id, new.title,
                                  null, '', v_detail, '', '');
  return new;
end;
$$;

-- ---------- audit_write: capture request headers when the caller
-- went through PostgREST (edge functions pass ip/ua explicitly) ----------

create or replace function tv_internal.audit_write(
  p_actor uuid,
  p_actor_email text,
  p_action text,
  p_document uuid,
  p_document_title text,
  p_target uuid,
  p_target_email text,
  p_detail jsonb,
  p_ip text,
  p_user_agent text
)
returns bigint
language plpgsql security definer set search_path = 'tv_internal, public, extensions'
as $$
declare
  v_seq bigint;
  v_prev_hash text;
  v_ts timestamptz := clock_timestamp();
  v_hash text;
  v_payload text;
  v_headers jsonb := null;
begin
  perform pg_advisory_xact_lock(918273645);

  begin
    v_headers := nullif(current_setting('request.headers', true), '')::jsonb;
  exception when others then
    v_headers := null;
  end;

  if (p_ip is null or p_ip = '') and v_headers is not null then
    p_ip := coalesce(v_headers->>'x-forwarded-for', '');
  end if;
  if (p_user_agent is null or p_user_agent = '') and v_headers is not null then
    p_user_agent := coalesce(v_headers->>'user-agent', '');
  end if;

  select a.hash into v_prev_hash from public.audit_log a order by a.seq desc limit 1;
  if v_prev_hash is null then
    v_prev_hash := 'GENESIS';
  end if;

  v_seq := nextval('public.audit_seq');

  v_payload :=
    v_seq::text || '|' ||
    to_char(v_ts, 'YYYY-MM-DD"T"HH24:MI:SS.US') || '|' ||
    coalesce(p_actor::text, '') || '|' ||
    coalesce(p_actor_email, '') || '|' ||
    coalesce(p_action, '') || '|' ||
    coalesce(p_document::text, '') || '|' ||
    coalesce(p_document_title, '') || '|' ||
    coalesce(p_target::text, '') || '|' ||
    coalesce(p_target_email, '') || '|' ||
    coalesce(p_detail::jsonb::text, '{}') || '|' ||
    coalesce(p_ip, '') || '|' ||
    coalesce(p_user_agent, '');

  v_hash := encode(sha256(convert_to(v_prev_hash || '|' || v_payload, 'UTF8')), 'hex');

  insert into public.audit_log (
    seq, ts, actor_id, actor_email, action,
    document_id, document_title, target_user_id, target_email,
    detail, ip, user_agent, prev_hash, hash
  ) values (
    v_seq, v_ts, p_actor, coalesce(p_actor_email, ''), p_action,
    p_document, coalesce(p_document_title, ''), p_target, coalesce(p_target_email, ''),
    coalesce(p_detail, '{}'::jsonb), coalesce(p_ip, ''), coalesce(p_user_agent, ''),
    v_prev_hash, v_hash
  );

  return v_seq;
end;
$$;
