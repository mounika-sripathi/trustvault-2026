-- TrustVault: re-create the login audit trigger.
-- (It was dropped on the live instance while diagnosing a seed issue;
-- this migration keeps the repository and the deployed database in step.)

create trigger auth_users_login_audit
  after update on auth.users
  for each row execute function tv_internal.tg_auth_login();
