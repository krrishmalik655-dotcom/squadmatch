-- Squadmatch schema for Supabase. Run in the SQL editor after creating a project.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '',
  college text not null default '',
  bio text not null default '',
  interests text[] not null default '{}',
  experience text not null default '',
  github_url text check (github_url is null or github_url ~* '^https?://(www[.])?github[.]com/[^/]+/?$'),
  avatar_url text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.profiles add column if not exists interests text[] not null default '{}';
alter table public.profiles add column if not exists github_url text;
create table if not exists public.skills (
  id bigint generated always as identity primary key,
  name text not null unique
);
create table if not exists public.profile_skills (
  profile_id uuid not null references public.profiles(id) on delete cascade,
  skill_id bigint not null references public.skills(id) on delete cascade,
  verified boolean not null default false,
  verified_at timestamptz,
  primary key(profile_id, skill_id)
);
create table if not exists public.availability (
  profile_id uuid not null references public.profiles(id) on delete cascade,
  slot text not null,
  primary key(profile_id, slot)
);
create table if not exists public.project_preferences (
  profile_id uuid primary key references public.profiles(id) on delete cascade,
  idea text not null default '',
  experience_notes text not null default '',
  updated_at timestamptz not null default now()
);
create table if not exists public.needed_skills (
  profile_id uuid not null references public.profiles(id) on delete cascade,
  skill_id bigint not null references public.skills(id) on delete cascade,
  primary key(profile_id, skill_id)
);
create table if not exists public.project_screenshots (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references public.profiles(id) on delete cascade,
  storage_path text not null unique,
  caption text not null default '',
  created_at timestamptz not null default now()
);
create table if not exists public.saved_squad_members (
  owner_id uuid not null references public.profiles(id) on delete cascade,
  member_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key(owner_id, member_id),
  check (owner_id <> member_id)
);
create table if not exists public.conversations (
  id uuid primary key default gen_random_uuid(),
  created_by uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  last_message_at timestamptz not null default now()
);
create table if not exists public.conversation_participants (
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  joined_at timestamptz not null default now(),
  primary key(conversation_id,user_id)
);
create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  sender_id uuid not null references public.profiles(id) on delete cascade,
  body text not null check (length(body) between 1 and 10000),
  created_at timestamptz not null default now()
);
create table if not exists public.hackathons (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  starts_at timestamptz,
  registration_deadline timestamptz,
  location text not null default 'Online',
  source_url text not null,
  source_name text not null default '',
  last_verified_at date,
  is_published boolean not null default false,
  created_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now()
);

-- Create a usable profile row immediately when auth creates a user.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles(id, full_name)
  values (new.id, coalesce(new.raw_user_meta_data ->> 'full_name', ''))
  on conflict (id) do nothing;
  return new;
end;
$$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute procedure public.handle_new_user();

create or replace function public.is_conversation_member(cid uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists(select 1 from public.conversation_participants cp
    where cp.conversation_id = cid and cp.user_id = auth.uid());
$$;
revoke all on function public.is_conversation_member(uuid) from public;
grant execute on function public.is_conversation_member(uuid) to authenticated;

-- Create the conversation and its memberships atomically. This avoids an
-- RLS gap where the creator cannot yet select the conversation to add members.
create or replace function public.create_conversation(participant_ids uuid[])
returns uuid language plpgsql security definer set search_path = '' as $$
declare new_conversation_id uuid;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  insert into public.conversations(created_by) values (auth.uid()) returning id into new_conversation_id;
  insert into public.conversation_participants(conversation_id,user_id)
    values (new_conversation_id,auth.uid());
  insert into public.conversation_participants(conversation_id,user_id)
    select new_conversation_id, u.member_id
    from unnest(coalesce(participant_ids, array[]::uuid[])) as u(member_id)
    where u.member_id <> auth.uid()
    on conflict do nothing;
  return new_conversation_id;
end;
$$;
grant execute on function public.create_conversation(uuid[]) to authenticated;
revoke all on function public.create_conversation(uuid[]) from public;

alter table public.profiles enable row level security;
alter table public.skills enable row level security;
alter table public.profile_skills enable row level security;
alter table public.availability enable row level security;
alter table public.project_preferences enable row level security;
alter table public.needed_skills enable row level security;
alter table public.project_screenshots enable row level security;
alter table public.saved_squad_members enable row level security;
alter table public.conversations enable row level security;
alter table public.conversation_participants enable row level security;
alter table public.messages enable row level security;
alter table public.hackathons enable row level security;

drop policy if exists "profiles visible to signed-in students" on public.profiles;
create policy "profiles visible to signed-in students" on public.profiles for select to authenticated using (true);
drop policy if exists "users create own profile" on public.profiles;
create policy "users create own profile" on public.profiles for insert to authenticated with check (id = auth.uid());
drop policy if exists "users update own profile" on public.profiles;
create policy "users update own profile" on public.profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid());
drop policy if exists "skills visible to signed-in students" on public.skills;
create policy "skills visible to signed-in students" on public.skills for select to authenticated using (true);
drop policy if exists "signed-in students add skill names" on public.skills;
create policy "signed-in students add skill names" on public.skills for insert to authenticated with check (length(name) between 1 and 80);
drop policy if exists "profile skills visible to signed-in students" on public.profile_skills;
create policy "profile skills visible to signed-in students" on public.profile_skills for select to authenticated using (true);
drop policy if exists "users manage own profile skills" on public.profile_skills;
create policy "users manage own profile skills" on public.profile_skills for all to authenticated using (profile_id = auth.uid()) with check (profile_id = auth.uid());
drop policy if exists "availability visible to signed-in students" on public.availability;
create policy "availability visible to signed-in students" on public.availability for select to authenticated using (true);
drop policy if exists "users manage own availability" on public.availability;
create policy "users manage own availability" on public.availability for all to authenticated using (profile_id = auth.uid()) with check (profile_id = auth.uid());
drop policy if exists "project preferences visible to signed-in students" on public.project_preferences;
create policy "project preferences visible to signed-in students" on public.project_preferences for select to authenticated using (true);
drop policy if exists "users manage own project preferences" on public.project_preferences;
create policy "users manage own project preferences" on public.project_preferences for all to authenticated using (profile_id = auth.uid()) with check (profile_id = auth.uid());
drop policy if exists "needed skills visible to signed-in students" on public.needed_skills;
create policy "needed skills visible to signed-in students" on public.needed_skills for select to authenticated using (true);
drop policy if exists "users manage own needed skills" on public.needed_skills;
create policy "users manage own needed skills" on public.needed_skills for all to authenticated using (profile_id = auth.uid()) with check (profile_id = auth.uid());
drop policy if exists "screenshots visible to signed-in students" on public.project_screenshots;
create policy "screenshots visible to signed-in students" on public.project_screenshots for select to authenticated using (true);
drop policy if exists "users manage own screenshot rows" on public.project_screenshots;
create policy "users manage own screenshot rows" on public.project_screenshots for all to authenticated using (profile_id = auth.uid()) with check (profile_id = auth.uid());
drop policy if exists "users see own saved squad" on public.saved_squad_members;
create policy "users see own saved squad" on public.saved_squad_members for select to authenticated using (owner_id = auth.uid());
drop policy if exists "users manage own saved squad" on public.saved_squad_members;
create policy "users manage own saved squad" on public.saved_squad_members for all to authenticated using (owner_id = auth.uid()) with check (owner_id = auth.uid());
drop policy if exists "participants see conversations" on public.conversations;
create policy "participants see conversations" on public.conversations for select to authenticated using (public.is_conversation_member(id));
drop policy if exists "signed-in users create conversations" on public.conversations;
create policy "signed-in users create conversations" on public.conversations for insert to authenticated with check (created_by = auth.uid());
drop policy if exists "participants see participant list" on public.conversation_participants;
create policy "participants see participant list" on public.conversation_participants for select to authenticated using (public.is_conversation_member(conversation_id));
drop policy if exists "participants add themselves or creator adds members" on public.conversation_participants;
drop policy if exists "conversation creator adds participants" on public.conversation_participants;
drop policy if exists "conversation creator adds participants" on public.conversation_participants;
create policy "conversation creator adds participants" on public.conversation_participants for insert to authenticated with check (
  exists(select 1 from public.conversations c where c.id = conversation_id and c.created_by = auth.uid())
);
drop policy if exists "participants leave conversation" on public.conversation_participants;
create policy "participants leave conversation" on public.conversation_participants for delete to authenticated using (user_id = auth.uid());
drop policy if exists "participants read messages" on public.messages;
create policy "participants read messages" on public.messages for select to authenticated using (public.is_conversation_member(conversation_id));
drop policy if exists "participants send own messages" on public.messages;
create policy "participants send own messages" on public.messages for insert to authenticated with check (sender_id = auth.uid() and public.is_conversation_member(conversation_id));
drop policy if exists "published hackathons visible" on public.hackathons;
create policy "published hackathons visible" on public.hackathons for select to authenticated using (is_published);
drop policy if exists "users manage hackathons they created" on public.hackathons;
create policy "users manage hackathons they created" on public.hackathons for all to authenticated using (created_by = auth.uid()) with check (created_by = auth.uid());

-- Enable realtime delivery for chat messages (safe to run more than once).
do $$ begin
  alter publication supabase_realtime add table public.messages;
exception when duplicate_object then null;
end $$;

-- Private project screenshot storage. Each student may upload/delete only in their own folder.
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values ('project-screenshots','project-screenshots',false,10485760,array['image/jpeg','image/png','image/webp'])
on conflict (id) do nothing;
drop policy if exists "signed-in users upload to own folder" on storage.objects;
create policy "signed-in users upload to own folder" on storage.objects for insert to authenticated
with check (bucket_id='project-screenshots' and (storage.foldername(name))[1]=auth.uid()::text);
drop policy if exists "signed-in users read project screenshots" on storage.objects;
create policy "signed-in users read project screenshots" on storage.objects for select to authenticated
using (bucket_id='project-screenshots');
drop policy if exists "users delete own screenshot files" on storage.objects;
create policy "users delete own screenshot files" on storage.objects for delete to authenticated
using (bucket_id='project-screenshots' and (storage.foldername(name))[1]=auth.uid()::text);
