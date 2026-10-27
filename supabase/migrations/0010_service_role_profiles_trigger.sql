-- 0010: tg_profiles_protect — keep role/is_active changes admin-only.
--
-- Note on the exemption: the trigger exempts any request with no user
-- session (auth.uid() is null). This is safe only because RLS separately
-- requires an active session for every client path to profiles, so the
-- only session-less writer that can reach profile writes at all is the
-- service role — used only by the admin-gated vault-admin edge function,
-- which re-verifies the caller is an active admin before the key is used.
-- Every client role still passes through this trigger: viewers cannot
-- update profiles at all, and role / is_active changes remain admin-only.

create or replace function tv_internal.tg_profiles_protect()
returns trigger
language plpgsql
security definer
set search_path = 'tv_internal, public'
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
