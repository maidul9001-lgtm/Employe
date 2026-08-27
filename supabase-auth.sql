-- Supabase Auth + Profile/Roles setup
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  username text unique,
  role text not null default 'public' check (role in ('public','moderator','admin')),
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

drop policy if exists "profiles_select_own" on public.profiles;
create policy "profiles_select_own" on public.profiles for select to authenticated using (id = auth.uid());

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path=public as $$
begin
  insert into public.profiles(id,full_name,username,role)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name',''),
    nullif(trim(new.raw_user_meta_data->>'username'),''),
    'public'
  )
  on conflict (id) do update set
    full_name=excluded.full_name,
    username=coalesce(excluded.username,public.profiles.username);
  return new;
end; $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

create or replace function public.get_login_email(p_username text)
returns text language sql security definer set search_path=public as $$
  select u.email
  from public.profiles p join auth.users u on u.id=p.id
  where lower(p.username)=lower(trim(p_username))
  limit 1;
$$;
revoke all on function public.get_login_email(text) from public;
grant execute on function public.get_login_email(text) to anon, authenticated;

create or replace function public.admin_list_users()
returns table(id uuid, full_name text, username text, role text, email text, created_at timestamptz)
language sql security definer set search_path=public as $$
  select p.id,p.full_name,p.username,p.role,u.email,p.created_at
  from public.profiles p join auth.users u on u.id=p.id
  where exists (select 1 from public.profiles me where me.id=auth.uid() and me.role='admin')
  order by p.created_at desc;
$$;
revoke all on function public.admin_list_users() from public;
grant execute on function public.admin_list_users() to authenticated;

create or replace function public.admin_set_user_role(p_user_id uuid,p_role text)
returns boolean language plpgsql security definer set search_path=public as $$
begin
  if not exists(select 1 from public.profiles where id=auth.uid() and role='admin') then
    raise exception 'Only an admin can change roles';
  end if;
  if p_role not in ('public','moderator','admin') then raise exception 'Invalid role'; end if;
  if p_user_id=auth.uid() then raise exception 'You cannot change your own role'; end if;
  update public.profiles set role=p_role where id=p_user_id;
  return found;
end; $$;
revoke all on function public.admin_set_user_role(uuid,text) from public;
grant execute on function public.admin_set_user_role(uuid,text) to authenticated;

-- IMPORTANT: after you create/login the Admin Auth user, set its profile to admin.
-- Replace YOUR_PERSONAL_EMAIL with the email you used in Supabase Authentication > Users:
-- update public.profiles p set username='Maidul', full_name='Maidul', role='admin'
-- where p.id=(select id from auth.users where email='YOUR_PERSONAL_EMAIL' limit 1);
