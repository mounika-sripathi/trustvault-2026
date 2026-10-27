-- TrustVault: triggers — validation, audit, and tamper protection
--
-- Audit strategy in one line each:
--   * everything reachable through PostgREST (grants, document metadata,
--     soft delete/restore, profile changes) is audited by DB triggers,
--     so there is NO code path that mutates these tables without an audit row;
--   * downloads/uploads of bytes and admin operations go through the edge
--     functions, which call the same audit writer with request metadata.

-- keep documents.updated_at fresh
create or replace function tv_internal.tg_touch_updated_at()
returns trigger language plpgsql security definer set search_path = 'tv_internal, public'
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

create trigger documents_touch_updated_at
  before update on public.documents
  for each row execute function tv_internal.tg_touch_updated_at();

-- ---------------------------------------------------------------
-- documents: path validation on insert
-- ---------------------------------------------------------------
create or replace function tv_internal.tg_documents_validate()
returns trigger language plpgsql security definer set search_path = 'tv_internal, public'
as $$
begin
  -- storage paths are generated server-side; anything else is rejected
  if new.storage_path !~ '^docs/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[1-9][0-9]*/[A-Za-z0-9._-]+$'
     or new.storage_path like '%..%' then
    raise exception 'invalid storage_path' using errcode = '23514';
  end if;
  return new;
end;
$$;

create trigger documents_validate_path
  before insert on public.documents
  for each row execute function tv_internal.tg_documents_validate();

-- ---------------------------------------------------------------
-- documents: grant-holders with edit may only touch presentation fields
-- (the RLS UPDATE policy decides who can update at all; this trigger
-- decides WHAT they may change)
-- ---------------------------------------------------------------
create or replace function tv_internal.tg_documents_protect()
returns trigger language plpgsql security definer set search_path = 'tv_internal, public'
as $$
begin
  -- auth.uid() is null only for the service role (edge functions), which
  -- never runs with user input for these columns.
  if auth.uid() is not null
     and not (tv_internal.is_admin() or tv_internal.is_doc_owner(old.id, auth.uid())) then
    if new.owner_id      is distinct from old.owner_id
       or new.storage_path   is distinct from old.storage_path
       or new.sha256         is distinct from old.sha256
       or new.size_bytes     is distinct from old.size_bytes
       or new.mime_type      is distinct from old.mime_type
       or new.filename      is distinct from old.filename
       or new.current_version is distinct from old.current_version
       or new.status         is distinct from old.status
       or new.deleted_at     is distinct from old.deleted_at then
      raise exception 'edit permission covers title, category and description only'
        using errcode = '42501';
    end if;
  end if;
  return new;
end;
$$;

create trigger documents_protect_fields
  before update on public.documents
  for each row execute function tv_internal.tg_documents_protect();

-- ---------------------------------------------------------------
-- documents: audit metadata changes, soft delete and restore
-- ---------------------------------------------------------------
create or replace function tv_internal.tg_documents_audit()
returns trigger language plpgsql security definer set search_path = 'tv_internal, public'
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

create trigger documents_audit
  after insert or update on public.documents
  for each row execute function tv_internal.tg_documents_audit();

-- ---------------------------------------------------------------
-- grants: validation before write
-- ---------------------------------------------------------------
create or replace function tv_internal.tg_grants_validate()
returns trigger language plpgsql security definer set search_path = 'tv_internal, public'
as $$
declare
  v_grantee public.profiles%rowtype;
  v_doc public.documents%rowtype;
begin
  if tg_op = 'INSERT' then
    select * into v_grantee from public.profiles p where p.id = new.user_id;
    if not found or not v_grantee.is_active then
      raise exception 'grantee must be an active user' using errcode = '23503';
    end if;
    select * into v_doc from public.documents d where d.id = new.document_id;
    if not found then
      raise exception 'document not found' using errcode = '23503';
    end if;
    if v_doc.owner_id = new.user_id then
      raise exception 'the owner already has full access' using errcode = '23514';
    end if;
  else
    -- UPDATE: the only permitted change is revoking a live grant
    if old.revoked_at is not null then
      raise exception 'a revoked grant is immutable; grant access again instead'
        using errcode = '23514';
    end if;
    if new.revoked_at is null then
      raise exception 'the only permitted update is revocation' using errcode = '23514';
    end if;
    if new.permission is distinct from old.permission
       or new.user_id is distinct from old.user_id
       or new.document_id is distinct from old.document_id
       or new.granted_by is distinct from old.granted_by
       or new.granted_at is distinct from old.granted_at then
      raise exception 'only revoked_at / revoked_by may change' using errcode = '23514';
    end if;
    if auth.uid() is not null and new.revoked_by is distinct from auth.uid() then
      raise exception 'revoked_by must be the revoking user' using errcode = '42501';
    end if;
  end if;
  return new;
end;
$$;

create trigger grants_validate
  before insert or update on public.grants
  for each row execute function tv_internal.tg_grants_validate();

-- ---------------------------------------------------------------
-- grants: audit every permission change
-- ---------------------------------------------------------------
create or replace function tv_internal.tg_grants_audit()
returns trigger language plpgsql security definer set search_path = 'tv_internal, public'
as $$
declare
  v_actor uuid;
  v_actor_email text := '';
  v_target_email text := '';
  v_title text := '';
begin
  select p.email into v_target_email from public.profiles p where p.id = new.user_id;
  select d.title into v_title from public.documents d where d.id = new.document_id;

  if tg_op = 'INSERT' then
    v_actor := new.granted_by;
    select p.email into v_actor_email from public.profiles p where p.id = new.granted_by;
    perform tv_internal.audit_write(v_actor, v_actor_email, 'grant.added',
      new.document_id, v_title, new.user_id, v_target_email,
      jsonb_build_object('permission', new.permission), '', '');
  else
    v_actor := new.revoked_by;
    if v_actor is not null then
      select p.email into v_actor_email from public.profiles p where p.id = new.revoked_by;
    end if;
    perform tv_internal.audit_write(v_actor, v_actor_email, 'grant.revoked',
      new.document_id, v_title, new.user_id, v_target_email,
      jsonb_build_object('permission', new.permission), '', '');
  end if;
  return new;
end;
$$;

create trigger grants_audit
  after insert or update on public.grants
  for each row execute function tv_internal.tg_grants_audit();

-- ---------------------------------------------------------------
-- profiles: only admins may change role / active status (RLS already
-- restricts UPDATE to admins; this is defence in depth)
-- ---------------------------------------------------------------
create or replace function tv_internal.tg_profiles_protect()
returns trigger language plpgsql security definer set search_path = 'tv_internal, public'
as $$
begin
  if (new.role is distinct from old.role or new.is_active is distinct from old.is_active)
     and auth.uid() is not null
     and not tv_internal.is_admin() then
    raise exception 'only administrators may change role or active status'
      using errcode = '42501';
  end if;
  return new;
end;
$$;

create trigger profiles_protect
  before update on public.profiles
  for each row execute function tv_internal.tg_profiles_protect();

-- ---------------------------------------------------------------
-- audit_log: append-only, for everyone. No role — including table
-- owner or service role — can quietly rewrite history. Legitimate
-- retention purging requires manually disabling this trigger, which
-- is a deliberate, logged operations decision.
-- ---------------------------------------------------------------
create or replace function tv_internal.tg_audit_lock()
returns trigger language plpgsql
as $$
begin
  raise exception 'audit_log is append-only (% on seq %)', tg_op, old.seq
    using errcode = '42501';
  return null;
end;
$$;

create trigger audit_lock
  before update or delete on public.audit_log
  for each row execute function tv_internal.tg_audit_lock();

-- belt and braces: no client role retains write privileges at all
revoke insert, update, delete on public.audit_log from authenticated, anon;

-- ---------------------------------------------------------------
-- auth.users: record successful sign-ins
-- ---------------------------------------------------------------
create or replace function tv_internal.tg_auth_login()
returns trigger language plpgsql security definer set search_path = 'tv_internal, public'
as $$
begin
  if new.last_sign_in_at is distinct from old.last_sign_in_at
     and new.last_sign_in_at is not null then
    perform tv_internal.audit_write(new.id, new.email, 'auth.login',
                              null, '', null, '', '{}'::jsonb, '', '');
  end if;
  return new;
end;
$$;

create trigger auth_users_login_audit
  after update on auth.users
  for each row execute function tv_internal.tg_auth_login();
