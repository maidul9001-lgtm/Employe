create table if not exists public.profiles (id uuid primary key references auth.users(id) on delete cascade, full_name text, username text unique, role text not null default 'public' check (role in ('public','moderator','admin')), created_at timestamptz default now());

create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$ begin insert into public.profiles(id,full_name,username,role) values(new.id,new.raw_user_meta_data->>'full_name',new.raw_user_meta_data->>'username','public'); return new; end; $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();

create or replace function public.get_login_email(p_username text) returns text language sql security definer set search_path=public as $$ select u.email from public.profiles p join auth.users u on u.id=p.id where lower(p.username)=lower(trim(p_username)) limit 1; $$;
grant execute on function public.get_login_email(text) to anon,authenticated;

create or replace function public.admin_set_user_role(p_user_id uuid,p_role text) returns boolean language plpgsql security definer set search_path=public as $$ begin if not exists(select 1 from public.profiles where id=auth.uid() and role='admin') then raise exception 'Only admin'; end if; if p_role not in ('public','moderator','admin') then raise exception 'Invalid role'; end if; if p_user_id=auth.uid() then raise exception 'Cannot change own role'; end if; update public.profiles set role=p_role where id=p_user_id; return found; end; $$;
grant execute on function public.admin_set_user_role(uuid,text) to authenticated;

create or replace function public.admin_list_users() returns table(id uuid,full_name text,username text,role text,email text,created_at timestamptz) language sql security definer set search_path=public as $$ select p.id,p.full_name,p.username,p.role,u.email,p.created_at from public.profiles p join auth.users u on u.id=p.id where exists(select 1 from public.profiles me where me.id=auth.uid() and me.role='admin') order by p.created_at desc; $$;
grant execute on function public.admin_list_users() to authenticated;

-- After your Admin Auth user exists, replace YOUR_PERSONAL_EMAIL and run once:
-- update public.profiles set full_name='Maidul',username='Maidul',role='admin' where id=(select id from auth.users where email='YOUR_PERSONAL_EMAIL' limit 1);
