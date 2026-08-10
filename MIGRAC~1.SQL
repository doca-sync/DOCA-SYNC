-- Rodar uma vez no banco (Supabase -> SQL editor)

-- estado atual (1 linha so)
create table if not exists doca_estado (
  id int primary key default 1,
  dados jsonb,
  atualizado_em timestamptz,
  check (id=1)
);

-- historico/backups: uma copia do estado ANTERIOR e' salva aqui antes de cada gravacao
-- (tipo 'rotativo' = ultimas 30 gravacoes; tipo 'diario' = 1 por dia, guardado por 180 dias)
create table if not exists doca_estado_hist (
  id bigserial primary key,
  tipo text not null check (tipo in ('rotativo','diario')),
  dados jsonb not null,
  criado_em timestamptz not null default now()
);
create index if not exists idx_doca_estado_hist_tipo_criado on doca_estado_hist(tipo, criado_em desc);
