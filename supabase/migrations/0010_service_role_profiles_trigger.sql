-- 0010: tg_profiles_protect — exempt the service-role path from the re-check.
-- The vault-admin edge function pre-verifies the caller is an active admin
-- before using the service key; the trigger stays in force for every other
-- path (client roles cannot update profiles at all except self, and role /
-- is_active changes remain admin-only).

create or replace function tv_internal.tg_profiles_protect()
returns trigger
language plpgsql
security definer
set search_path = tv_internal, public, extensions
as $$
begin
  if new.role is distinct from old.role or new.is_active is distinct from old.is_active then
    -- Admins may change roles/active state; service role path is used only by
    -- the admin-gated edge function; everyone else is refused.
    if not (is_admin() or (auth.uid() is null and not tv_internal.is_admin() and current_user = 'service_role')) then
      raise exception 'PROFILE_PROTECTED: role and is_active changes require an administrator';
    end if;
  end if;
  return new;
end;
$$;
