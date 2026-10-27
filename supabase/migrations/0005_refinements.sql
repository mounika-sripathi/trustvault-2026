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
