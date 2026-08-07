-- Doca <-> Mercado Livre sync — esquema minimo (Postgres / Supabase)
-- Rode este arquivo uma vez no SQL Editor do Supabase (ou via psql) antes do primeiro deploy.

create table if not exists ml_accounts (
  loja text primary key,                 -- 'TorvStore' | 'Dor Block' | 'Orbix Brasil' | 'TorvShop'
  ml_user_id text,
  access_token text not null,
  refresh_token text not null,
  expires_at timestamptz not null,
  atualizado_em timestamptz not null default now()
);

create table if not exists ml_produtos (
  id bigserial primary key,
  loja text not null references ml_accounts(loja) on delete cascade,
  ml_item_id text not null,
  sku text,
  titulo text,
  quantidade_disponivel integer default 0,
  preco numeric(12,2),
  status text,
  atualizado_em timestamptz not null default now(),
  unique (loja, ml_item_id)
);

create index if not exists idx_ml_produtos_loja on ml_produtos(loja);

-- log simples de cada sincronizacao manual (util pra depurar e mostrar "ultima atualizacao" no Doca)
create table if not exists ml_sync_log (
  id bigserial primary key,
  loja text not null,
  iniciado_em timestamptz not null default now(),
  concluido_em timestamptz,
  itens_sincronizados integer,
  erro text
);
