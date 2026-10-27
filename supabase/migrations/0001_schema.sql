-- TrustVault: initial schema
-- Everything the platform stores lives in these five tables plus Supabase Auth.

create extension if not exists pgcrypto;

-- Private schema for internal helpers. Not exposed through PostgREST.
-- USAGE is granted to client roles because RLS policies call these helpers,
-- but the audit writer has EXECUTE revoked from client roles (see 0004).
create schema if not exists tv_internal;
grant usage on schema tv_internal to authenticated, anon, service_role;

-- ============================================================
-- profiles: one row per auth user; holds the platform role
-- ============================================================
create table public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  email       text not null unique,
  full_name   text not null default '',
  role        text not null default 'viewer'
              check (role in ('admin', 'owner', 'viewer')),
  is_active   boolean not null default true,
  created_at  timestamptz not null default now()
);

-- ============================================================
-- documents: metadata; bytes live in the private storage bucket
-- ============================================================
create table public.documents (
  id              uuid primary key default gen_random_uuid(),
  owner_id        uuid not null references public.profiles(id),
  title           text not null check (char_length(title) between 1 and 200),
  category        text not null default 'general' check (char_length(category) between 1 and 60),
  description     text not null default '' check (char_length(description) <= 2000),
  filename        text not null,
  mime_type       text not null,
  size_bytes      bigint not null check (size_bytes > 0),
  sha256          text not null,
  storage_path    text not null unique,
  current_version int not null default 1 check (current_version >= 1),
  status          text not null default 'active' check (status in ('active', 'deleted')),
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  deleted_at      timestamptz
);

create index documents_owner_idx    on public.documents(owner_id);
create index documents_category_idx on public.documents(category);
create index documents_status_idx   on public.documents(status);

-- ============================================================
-- document_versions: immutable history of file contents
-- ============================================================
create table public.document_versions (
  id           uuid primary key default gen_random_uuid(),
  document_id  uuid not null references public.documents(id) on delete cascade,
  version_no   int  not null check (version_no >= 1),
  filename     text not null,
  mime_type    text not null,
  size_bytes   bigint not null,
  sha256       text not null,
  storage_path text not null,
  uploaded_by  uuid not null references public.profiles(id),
  note         text not null default '' check (char_length(note) <= 500),
  created_at   timestamptz not null default now(),
  unique (document_id, version_no)
);

-- ============================================================
-- grants: per-document, per-user access. Revocation = setting
-- revoked_at; every read path checks revoked_at is null, so a
-- revoke takes effect on the very next request.
-- ============================================================
create table public.grants (
  id          uuid primary key default gen_random_uuid(),
  document_id uuid not null references public.documents(id) on delete cascade,
  user_id     uuid not null references public.profiles(id),
  permission  text not null check (permission in ('read', 'edit')),
  granted_by  uuid not null references public.profiles(id),
  granted_at  timestamptz not null default now(),
  revoked_at  timestamptz,
  revoked_by  uuid references public.profiles(id)
);

-- at most one live grant per (document, user)
create unique index grants_active_unique
  on public.grants(document_id, user_id) where revoked_at is null;
create index grants_user_live_idx on public.grants(user_id) where revoked_at is null;

-- ============================================================
-- audit_log: append-only, hash-chained. seq is allocated from a
-- dedicated sequence inside tv_internal.audit_write so the row is
-- written complete (hash included) in a single INSERT; UPDATE
-- and DELETE are rejected by trigger for every role.
-- ============================================================
create sequence public.audit_seq;

create table public.audit_log (
  seq            bigint not null default nextval('public.audit_seq') primary key,
  ts             timestamptz not null default now(),
  actor_id       uuid,
  actor_email    text not null default '',
  action         text not null,
  document_id    uuid,
  document_title text not null default '',
  target_user_id uuid,
  target_email   text not null default '',
  detail         jsonb not null default '{}'::jsonb,
  ip             text not null default '',
  user_agent     text not null default '',
  prev_hash     text not null,
  hash           text not null
);

create index audit_action_idx on public.audit_log(action);
create index audit_doc_idx    on public.audit_log(document_id);
create index audit_actor_idx  on public.audit_log(actor_id);

-- Private storage bucket for document bytes. No storage policies are
-- created for client roles: default deny. All byte access goes through
-- the serve-doc edge function, which re-checks grants on every request.
insert into storage.buckets (id, name, public)
values ('documents', 'documents', false)
on conflict (id) do nothing;
