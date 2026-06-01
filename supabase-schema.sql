-- ========================================
-- Каталог Сочи · CRM — схема базы данных
-- Запустите в Supabase SQL Editor одним блоком
-- ========================================

-- 1) Таблица агентов (профили пользователей)
create table if not exists agents (
  id uuid primary key default gen_random_uuid(),
  auth_user_id uuid references auth.users(id) on delete cascade,
  name text not null,
  phone text,
  email text,
  role text not null default 'Агент', -- 'Агент' | 'Руководитель отдела' | 'Директор'
  city text default 'Сочи',
  ref_code text,
  subscription_end timestamptz,
  balance numeric default 0,
  created_at timestamptz default now()
);

create index if not exists agents_auth_user_idx on agents(auth_user_id);

-- 2) Клиенты (с привязкой к ответственному агенту)
create table if not exists clients (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  phone text,
  status text default 'new',
  request_comment text,
  type text,
  budget_mln numeric,
  area text,
  next_contact timestamptz,
  next_action text,
  note text,
  responsible_agent_id uuid references agents(id) on delete set null,
  responsible_name text, -- денормализовано для скорости
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

create index if not exists clients_responsible_idx on clients(responsible_agent_id);
create index if not exists clients_status_idx on clients(status);

-- 3) Объекты (общая база, видна всем)
create table if not exists properties (
  id uuid primary key default gen_random_uuid(),
  complex text not null,
  title text,
  kind text default 'new',
  bedrooms int,
  reno text,
  area text,
  price bigint,
  commission text,
  district text,
  developer text,
  note text,
  agent_id uuid references agents(id) on delete set null,
  agent_name text,
  agent_phone text,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

create index if not exists properties_kind_idx on properties(kind);
create index if not exists properties_district_idx on properties(district);
create index if not exists properties_agent_idx on properties(agent_id);

-- 4) Фотографии объектов (в Storage, тут только ссылки)
create table if not exists property_photos (
  id uuid primary key default gen_random_uuid(),
  property_id uuid references properties(id) on delete cascade,
  storage_path text not null, -- путь в Supabase Storage
  position int default 0,
  created_at timestamptz default now()
);

create index if not exists property_photos_property_idx on property_photos(property_id);

-- 5) Задачи
create table if not exists tasks (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  when_at timestamptz,
  done boolean default false,
  client_id uuid references clients(id) on delete set null,
  agent_id uuid references agents(id) on delete cascade,
  created_at timestamptz default now()
);

create index if not exists tasks_agent_idx on tasks(agent_id);
create index if not exists tasks_when_idx on tasks(when_at);

-- 6) Сделки
create table if not exists deals (
  id uuid primary key default gen_random_uuid(),
  object_text text,
  client_name text,
  date date,
  price bigint,
  commission bigint,
  expenses bigint default 0,
  received bigint default 0,
  note text,
  agent_id uuid references agents(id) on delete cascade,
  created_at timestamptz default now()
);

-- 7) Партнерские сделки
create table if not exists partner_deals (
  id uuid primary key default gen_random_uuid(),
  object_text text,
  partner_name text,
  sum_total bigint,
  commission bigint,
  my_share_pct numeric,
  status text default 'pending',
  agent_id uuid references agents(id) on delete cascade,
  created_at timestamptz default now()
);

-- 8) Рефералы / начисления
create table if not exists referrals (
  id uuid primary key default gen_random_uuid(),
  inviter_id uuid references agents(id) on delete cascade,
  invitee_name text,
  amount numeric,
  paid_at timestamptz default now()
);

-- ========================================
-- Row Level Security (RLS) — права доступа
-- ========================================

-- AGENTS: видят сами себя + директор видит всех
alter table agents enable row level security;

create policy "agents read own" on agents for select using (
  auth.uid() = auth_user_id
  or exists (select 1 from agents a where a.auth_user_id = auth.uid() and a.role in ('Директор','Руководитель отдела'))
);

create policy "agents update own" on agents for update using (auth.uid() = auth_user_id);

create policy "anyone signup" on agents for insert with check (auth.uid() = auth_user_id);

-- CLIENTS: агент видит только свои, директор — все
alter table clients enable row level security;

create policy "clients read by agent" on clients for select using (
  responsible_agent_id in (select id from agents where auth_user_id = auth.uid())
  or exists (select 1 from agents where auth_user_id = auth.uid() and role in ('Директор','Руководитель отдела'))
);

create policy "clients write by agent" on clients for insert with check (
  responsible_agent_id in (select id from agents where auth_user_id = auth.uid())
);

create policy "clients update own" on clients for update using (
  responsible_agent_id in (select id from agents where auth_user_id = auth.uid())
  or exists (select 1 from agents where auth_user_id = auth.uid() and role in ('Директор','Руководитель отдела'))
);

create policy "clients delete own" on clients for delete using (
  responsible_agent_id in (select id from agents where auth_user_id = auth.uid())
  or exists (select 1 from agents where auth_user_id = auth.uid() and role = 'Директор')
);

-- PROPERTIES: видят все авторизованные, но изменять/удалять — только автор или директор
alter table properties enable row level security;

create policy "properties read all auth" on properties for select using (auth.role() = 'authenticated');

create policy "properties insert by author" on properties for insert with check (
  agent_id in (select id from agents where auth_user_id = auth.uid())
);

create policy "properties update by author" on properties for update using (
  agent_id in (select id from agents where auth_user_id = auth.uid())
  or exists (select 1 from agents where auth_user_id = auth.uid() and role in ('Директор','Руководитель отдела'))
);

create policy "properties delete by author" on properties for delete using (
  agent_id in (select id from agents where auth_user_id = auth.uid())
  or exists (select 1 from agents where auth_user_id = auth.uid() and role = 'Директор')
);

-- PROPERTY_PHOTOS: те же права что у объекта
alter table property_photos enable row level security;
create policy "photos read all auth" on property_photos for select using (auth.role() = 'authenticated');
create policy "photos write by prop author" on property_photos for insert with check (
  property_id in (select id from properties where agent_id in (select id from agents where auth_user_id = auth.uid()))
);
create policy "photos delete by prop author" on property_photos for delete using (
  property_id in (select id from properties where agent_id in (select id from agents where auth_user_id = auth.uid()))
  or exists (select 1 from agents where auth_user_id = auth.uid() and role in ('Директор','Руководитель отдела'))
);

-- TASKS, DEALS, PARTNER_DEALS, REFERRALS: только свои
alter table tasks enable row level security;
create policy "tasks own" on tasks for all using (
  agent_id in (select id from agents where auth_user_id = auth.uid())
) with check (
  agent_id in (select id from agents where auth_user_id = auth.uid())
);

alter table deals enable row level security;
create policy "deals own or director" on deals for all using (
  agent_id in (select id from agents where auth_user_id = auth.uid())
  or exists (select 1 from agents where auth_user_id = auth.uid() and role in ('Директор','Руководитель отдела'))
) with check (
  agent_id in (select id from agents where auth_user_id = auth.uid())
);

alter table partner_deals enable row level security;
create policy "partner own" on partner_deals for all using (
  agent_id in (select id from agents where auth_user_id = auth.uid())
) with check (
  agent_id in (select id from agents where auth_user_id = auth.uid())
);

alter table referrals enable row level security;
create policy "referrals own" on referrals for select using (
  inviter_id in (select id from agents where auth_user_id = auth.uid())
);

-- ========================================
-- Storage: bucket для фотографий объектов
-- (создаётся через UI Supabase Storage)
-- Bucket name: 'property-photos'  Public: true (для прямых ссылок)
-- ========================================

-- Триггер: автообновление updated_at
create or replace function set_updated_at() returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

create trigger set_clients_updated before update on clients
  for each row execute function set_updated_at();
create trigger set_properties_updated before update on properties
  for each row execute function set_updated_at();

-- ========================================
-- Готово. Создайте первого пользователя через Authentication → Users → Add user,
-- затем в SQL Editor: insert into agents (auth_user_id, name, role) values ('UUID_USER', 'Алёна', 'Директор');
-- ========================================
