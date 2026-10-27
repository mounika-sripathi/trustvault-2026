-- 0010: tg_profiles_protect — keep role/is_active changes admin-only.
--
-- The service-role connection (used only by the admin-gated vault-admin
-- edge function, which re-verifies the caller is an active admin before
-- the key is used) has no auth.uid(), so it is exempt from this check.
-- Every client role still passes through it: viewers cannot update
-- profiles at all, and role / is_active changes remain admin-only.

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
