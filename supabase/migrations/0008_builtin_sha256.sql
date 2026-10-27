-- TrustVault: replace pgcrypto digest() with the built-in sha256().
-- pgcrypto lives in Supabase's extensions schema, which is awkward to
-- guarantee inside SECURITY DEFINER search paths; sha256()/convert_to()
-- live in pg_catalog and are always visible.

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

