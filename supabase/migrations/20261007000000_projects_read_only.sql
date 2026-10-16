begin;

alter table public.projects enable row level security;

grant usage on schema public
    to anon, authenticated;

revoke all privileges on table public.projects
    from public, anon, authenticated;

grant select on table public.projects
    to anon, authenticated;

drop policy if exists "Public can read projects"
    on public.projects;

create policy "Public can read projects"
    on public.projects
    for select
    to anon, authenticated
    using (true);

create schema if not exists private;

revoke all on schema private
    from public, anon, authenticated;

grant usage on schema private
    to service_role;

create table if not exists private.ap_fl_admin_rate_limits (
    ip_hash text primary key,
    window_started_at timestamptz not null,
    attempt_count integer not null check (attempt_count > 0)
);

revoke all privileges on table private.ap_fl_admin_rate_limits
    from public, anon, authenticated;

grant select, insert, update, delete
    on table private.ap_fl_admin_rate_limits
    to service_role;

create index if not exists ap_fl_admin_rate_limits_window_idx
    on private.ap_fl_admin_rate_limits (window_started_at);

create or replace function public.consume_ap_fl_admin_attempt(
    p_ip_hash text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $function$
declare
    current_attempts integer;
begin
    if p_ip_hash is null or length(p_ip_hash) <> 64 then
        raise exception 'Invalid rate limit key';
    end if;

    insert into private.ap_fl_admin_rate_limits as current_limit (
        ip_hash,
        window_started_at,
        attempt_count
    )
    values (
        p_ip_hash,
        now(),
        1
    )
    on conflict (ip_hash) do update
    set
        window_started_at = case
            when current_limit.window_started_at < now() - interval '15 minutes'
                then now()
            else current_limit.window_started_at
        end,
        attempt_count = case
            when current_limit.window_started_at < now() - interval '15 minutes'
                then 1
            else current_limit.attempt_count + 1
        end
    returning attempt_count into current_attempts;

    delete from private.ap_fl_admin_rate_limits
    where window_started_at < now() - interval '1 day';

    return current_attempts <= 20;
end;
$function$;

revoke all on function public.consume_ap_fl_admin_attempt(text)
    from public, anon, authenticated;

grant execute on function public.consume_ap_fl_admin_attempt(text)
    to service_role;

commit;
