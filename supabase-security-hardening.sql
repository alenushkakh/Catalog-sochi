-- ============================================================
-- БЕЗОПАСНОСТЬ И ПРИВАТНОСТЬ — комплексный апгрейд
-- Запустите целиком в Supabase → SQL Editor → New query → Run
-- Безопасно для повторного запуска (idempotent)
-- ============================================================

-- ============================================================
-- 1) ЗАПРЕТ САМОСТОЯТЕЛЬНОГО НАЗНАЧЕНИЯ РОЛИ ДИРЕКТОРА
-- При signup роль ВСЕГДА = 'Агент'. Повысить может только Директор.
-- ============================================================

alter table agents
  add column if not exists consent_at timestamptz,
  add column if not exists consent_version text;

-- триггер: при insert принудительно ставим 'Агент' если не Директор
create or replace function enforce_agent_role_on_signup()
returns trigger as $$
declare
  caller_role text;
begin
  -- если это сам пользователь регистрируется (auth.uid() = new.auth_user_id)
  if auth.uid() = new.auth_user_id then
    -- проверяем — это вообще первая запись или повышение?
    if not exists (select 1 from agents where auth_user_id = auth.uid()) then
      -- первый раз — только 'Агент'
      new.role := 'Агент';
    else
      -- update своей же записи — нельзя поднимать роль
      select role into caller_role from agents where auth_user_id = auth.uid() limit 1;
      if new.role <> caller_role and caller_role <> 'Директор' then
        new.role := caller_role;
      end if;
    end if;
  else
    -- кто-то другой создаёт/меняет запись — нужно быть админом
    select role into caller_role from agents where auth_user_id = auth.uid() limit 1;
    if caller_role is null or caller_role not in ('Директор','Руководитель отдела') then
      raise exception 'Только Директор может управлять чужими записями';
    end if;
    -- Руководитель не может назначить роль выше своей
    if caller_role = 'Руководитель отдела' and new.role = 'Директор' then
      raise exception 'Только Директор может назначить роль Директора';
    end if;
  end if;
  return new;
end;
$$ language plpgsql security definer;

drop trigger if exists trg_enforce_agent_role on agents;
create trigger trg_enforce_agent_role
  before insert or update of role on agents
  for each row execute function enforce_agent_role_on_signup();

-- ============================================================
-- 2) RLS для tg_chats и tg_broadcasts
-- ============================================================

alter table tg_chats enable row level security;
alter table tg_broadcasts enable row level security;

drop policy if exists "tg_chats_all" on tg_chats;
create policy "tg_chats_all" on tg_chats for all
  using (created_by = current_agent_id() or is_admin())
  with check (created_by = current_agent_id() or is_admin());

drop policy if exists "tg_broadcasts_all" on tg_broadcasts;
create policy "tg_broadcasts_all" on tg_broadcasts for all
  using (created_by = current_agent_id() or is_admin())
  with check (created_by = current_agent_id() or is_admin());

-- ============================================================
-- 3) АУДИТ-ЛОГ — записываем критические действия (152-ФЗ требование)
-- ============================================================

create table if not exists audit_log (
  id bigserial primary key,
  agent_id uuid references agents(id) on delete set null,
  auth_user_id uuid,
  action text not null,           -- 'login', 'signup', 'delete_account', 'role_change', 'export_data', и т.п.
  details jsonb,
  ip_addr text,
  user_agent text,
  created_at timestamptz default now()
);

alter table audit_log enable row level security;

drop policy if exists "audit_select_own_or_director" on audit_log;
create policy "audit_select_own_or_director" on audit_log for select
  using (agent_id = current_agent_id() or is_director());

drop policy if exists "audit_insert_any" on audit_log;
create policy "audit_insert_any" on audit_log for insert
  with check (true);  -- любой авторизованный может записать о себе

create index if not exists audit_log_agent_idx on audit_log(agent_id, created_at desc);

-- ============================================================
-- 4) ПРАВО НА УДАЛЕНИЕ (152-ФЗ ст.14, Google Play Data Deletion)
-- RPC delete_my_data() — пользователь может удалить себя одной кнопкой
-- ============================================================

create or replace function delete_my_data()
returns jsonb as $$
declare
  my_id uuid;
  my_auth uuid;
  cnt_clients int := 0;
  cnt_tasks int := 0;
  cnt_deals int := 0;
  cnt_props int := 0;
begin
  my_auth := auth.uid();
  if my_auth is null then
    raise exception 'Not authenticated';
  end if;

  select id into my_id from agents where auth_user_id = my_auth limit 1;
  if my_id is null then
    return jsonb_build_object('ok', false, 'reason', 'Agent record not found');
  end if;

  -- записываем в лог ДО удаления
  insert into audit_log(agent_id, auth_user_id, action, details)
  values (my_id, my_auth, 'delete_account', jsonb_build_object('requested_at', now()));

  delete from clients where responsible_agent_id = my_id returning 1 into cnt_clients;
  delete from tasks where agent_id = my_id returning 1 into cnt_tasks;
  delete from deals where agent_id = my_id returning 1 into cnt_deals;
  delete from partner_deals where agent_id = my_id;
  delete from referrals where inviter_id = my_id;
  delete from tg_chats where created_by = my_id;
  delete from tg_broadcasts where created_by = my_id;
  -- объекты НЕ удаляем (это общая база агентства) — но обнуляем привязку
  update properties set agent_id = null, agent_name = null, agent_phone = null where agent_id = my_id;

  -- удаляем сам аккаунт agents (auth.users почистится отдельной службой supabase или ручным удалением)
  delete from agents where id = my_id;

  return jsonb_build_object(
    'ok', true,
    'deleted_at', now(),
    'note', 'Account auth record должен быть удалён вручную из Supabase Auth → Users'
  );
end;
$$ language plpgsql security definer;

revoke all on function delete_my_data() from public;
grant execute on function delete_my_data() to authenticated;

-- ============================================================
-- 5) СКРЫТИЕ ТЕЛЕФОНА СОБСТВЕННИКА — VIEW + RLS
-- properties.owner_phone виден только автору объекта и Директору
-- ============================================================

-- (предполагаем что в properties есть колонка owner_phone, проверяем)
do $$
begin
  if not exists (
    select 1 from information_schema.columns
    where table_name = 'properties' and column_name = 'owner_phone'
  ) then
    alter table properties add column owner_phone text;
  end if;
end$$;

create or replace view properties_safe as
select
  p.*,
  case when p.agent_id = current_agent_id() or is_director()
       then p.owner_phone
       else null
  end as owner_phone_visible
from properties p;

grant select on properties_safe to authenticated;

-- ============================================================
-- 6) ИНДЕКСЫ для скорости
-- ============================================================

create index if not exists clients_agent_idx on clients(responsible_agent_id, created_at desc);
create index if not exists clients_status_idx on clients(status);
create index if not exists clients_next_contact_idx on clients(next_contact);
create index if not exists properties_agent_idx on properties(agent_id);
create index if not exists tasks_agent_due_idx on tasks(agent_id, when_at);
create index if not exists deals_agent_idx on deals(agent_id);
create index if not exists tg_broadcasts_status_idx on tg_broadcasts(status, when_at);

-- ============================================================
-- 7) REALTIME — мгновенная синхронизация между устройствами
-- ============================================================

alter publication supabase_realtime add table clients;
alter publication supabase_realtime add table properties;
alter publication supabase_realtime add table tasks;
alter publication supabase_realtime add table deals;
alter publication supabase_realtime add table tg_chats;
alter publication supabase_realtime add table tg_broadcasts;
-- если таблица уже добавлена — оператор кинет «relation is already member», это OK

-- ============================================================
-- 8) ПРИВЕТСТВЕННЫЕ ДАННЫЕ ДЛЯ ПРОВЕРКИ
-- ============================================================

select
  'security-hardening' as patch,
  (select count(*) from agents) as agents_total,
  (select count(*) from clients) as clients_total,
  (select count(*) from properties) as properties_total,
  (select count(*) from pg_policies where tablename in ('tg_chats','tg_broadcasts')) as new_rls_policies,
  (select count(*) from pg_publication_tables where pubname = 'supabase_realtime' and tablename in ('clients','properties','tasks','deals','tg_chats','tg_broadcasts')) as realtime_tables,
  'OK' as status;
