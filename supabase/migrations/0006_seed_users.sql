-- TrustVault: seed users and profiles (demo credentials — see README)
--
-- These are the accounts published in the README for judges: one admin,
-- two document owners, two viewers. Passwords are demo-only.

insert into auth.users (
  instance_id, id, aud, role, email, encrypted_password,
  email_confirmed_at, created_at, updated_at,
  raw_app_meta_data, raw_user_meta_data,
  confirmation_token, recovery_token, email_change_token_new,
  email_change, phone_change, phone_change_token,
  email_change_token_current, reauthentication_token
)
values
  ('00000000-0000-0000-0000-000000000000', gen_random_uuid(), 'authenticated', 'authenticated',
   'admin@trustvault.demo', crypt('TrustVault!Admin2026', gen_salt('bf')),
   now(), now(), now(),
   '{"provider":"email","providers":["email"]}'::jsonb,
   '{"full_name":"Monica Admin"}'::jsonb,
   '', '', '', '', '', '', '', ''),

  ('00000000-0000-0000-0000-000000000000', gen_random_uuid(), 'authenticated', 'authenticated',
   'alice@trustvault.demo', crypt('TrustVault!Alice2026', gen_salt('bf')),
   now(), now(), now(),
   '{"provider":"email","providers":["email"]}'::jsonb,
   '{"full_name":"Alice Andrews"}'::jsonb,
   '', '', '', '', '', '', '', ''),

  ('00000000-0000-0000-0000-000000000000', gen_random_uuid(), 'authenticated', 'authenticated',
   'bob@trustvault.demo', crypt('TrustVault!Bob2026', gen_salt('bf')),
   now(), now(), now(),
   '{"provider":"email","providers":["email"]}'::jsonb,
   '{"full_name":"Bob Baker"}'::jsonb,
   '', '', '', '', '', '', '', ''),

  ('00000000-0000-0000-0000-000000000000', gen_random_uuid(), 'authenticated', 'authenticated',
   'carol@trustvault.demo', crypt('TrustVault!Carol2026', gen_salt('bf')),
   now(), now(), now(),
   '{"provider":"email","providers":["email"]}'::jsonb,
   '{"full_name":"Carol Chen"}'::jsonb,
   '', '', '', '', '', '', '', ''),

  ('00000000-0000-0000-0000-000000000000', gen_random_uuid(), 'authenticated', 'authenticated',
   'dave@trustvault.demo', crypt('TrustVault!Dave2026', gen_salt('bf')),
   now(), now(), now(),
   '{"provider":"email","providers":["email"]}'::jsonb,
   '{"full_name":"Dave Davis"}'::jsonb,
   '', '', '', '', '', '', '', '');

insert into public.profiles (id, email, full_name, role)
select u.id, u.email,
       coalesce(u.raw_user_meta_data->>'full_name', u.email),
       case u.email
         when 'admin@trustvault.demo'  then 'admin'
         when 'alice@trustvault.demo'  then 'owner'
         when 'bob@trustvault.demo'    then 'owner'
         else 'viewer'
       end
from auth.users u
where u.email like '%@trustvault.demo';
