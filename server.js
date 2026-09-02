/*
 * Doca <-> Mercado Livre — backend minimo
 * -----------------------------------------
 * Nao faz sincronizacao em tempo real nem recebe webhook. So existe pra fazer 2 coisas:
 *
 *  1) Autorizar cada loja uma vez (OAuth2 do Mercado Livre) e guardar o token com seguranca
 *     — isso NAO pode acontecer no navegador porque exige o client_secret, que e um segredo.
 *  2) Quando alguem aperta "Atualizar" no Doca, buscar o estoque atual na API do ML e salvar
 *     no banco (Postgres/Supabase), pra o Doca ler depois.
 *
 * Endpoints:
 *   GET  /health                    -> healthcheck simples
 *   GET  /oauth/login?loja=X        -> redireciona pro login do Mercado Livre (fazer 1x por loja)
 *   GET  /oauth/callback            -> volta do login do ML, troca o code por access/refresh token
 *   POST /sync?loja=X               -> busca os dados atuais na API do ML e salva no banco
 *   GET  /data?loja=X               -> devolve os ultimos dados salvos daquela loja (pro Doca ler)
 *
 * Variaveis de ambiente necessarias (ver .env.example):
 *   DATABASE_URL, ML_CLIENT_ID, ML_CLIENT_SECRET, ML_REDIRECT_URI, ALLOWED_ORIGIN
 *
 * Multi-loja (v15): cada loja pode ter seu PROPRIO aplicativo do Mercado Livre (Client ID/
 * Secret diferentes), todos usando o MESMO Redirect URI (ML_REDIRECT_URI), ja que e' o mesmo
 * backend/rota /oauth/callback pra todo mundo. As credenciais globais ML_CLIENT_ID/
 * ML_CLIENT_SECRET continuam servindo de "padrao" (hoje sao as da TorvShop) - nao precisou
 * mexer em nada pra ela continuar funcionando. Pra cada loja NOVA com aplicativo proprio,
 * basta criar duas variaveis de ambiente extras no Render:
 *   ML_CLIENT_ID_<LOJA>  e  ML_CLIENT_SECRET_<LOJA>
 * onde <LOJA> e' o nome da loja em maiusculo, com espacos/acentos trocados por "_"
 * (ver normalizarChaveLoja). Ex.: "Dor Block" -> ML_CLIENT_ID_DOR_BLOCK.
 */
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');
const {
  PORT = 3000,
  DATABASE_URL,
  ML_CLIENT_ID,
  ML_CLIENT_SECRET,
  ML_REDIRECT_URI,
  ML_AUTH_DOMAIN = 'https://auth.mercadolivre.com.br',
  ALLOWED_ORIGIN = '*',
  DOCA_USER,
  DOCA_SENHA
} = process.env;
if (!DATABASE_URL) { console.error('Faltou DATABASE_URL no .env'); process.exit(1); }
if (!ML_CLIENT_ID || !ML_CLIENT_SECRET || !ML_REDIRECT_URI) {
  console.error('Faltou ML_CLIENT_ID / ML_CLIENT_SECRET / ML_REDIRECT_URI no .env');
  process.exit(1);
}
const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
/* tabela pra relatorios compartilhaveis (fechamento de todas as lojas etc) - pedido do Felipe
   19/08: gerar um link que a pessoa que ele mandar por WhatsApp consiga abrir sem precisar de
   login do Doca (ver rotas /relatorio no fim do arquivo). Criada sozinha se ainda nao existir -
   nao precisa rodar migracao manual no Supabase pra essa. */
pool.query(`create table if not exists relatorios (
  id text primary key,
  html text not null,
  criado_em timestamptz not null default now()
)`).catch(e => console.error('Falha ao garantir tabela "relatorios":', e.message));
/* anexos de conciliacao da Auditoria - pedido do Felipe 23/08: sobe o Relatorio de Conciliacao
   mensal (xlsx, baixado direto no Mercado Livre em Vendas > Relatorios > Conciliacao - tem 2
   tipos, "por venda" e "por liberacao de dinheiro") na aba Auditoria pra guardar de referencia.
   v2 (23/08): o Doca tentou usar antes um CSV bruto do Mercado Pago (settlement_report/
   reserve-release), mas o Felipe mostrou que o que ele realmente tem em maos e' esse outro
   relatorio (do proprio Mercado Livre, xlsx, com SKU por linha) - o parsing do xlsx e' feito no
   NAVEGADOR (SheetJS, ja carregado no doca.html) porque campos como "Detalhes de tarifas" tem
   ";" e quebra de linha dentro, o que quebraria um parser de CSV simples. O backend so' recebe o
   resumo (jsonb) ja pronto - nao guarda mais o arquivo original (o Felipe sempre pode baixar de
   novo no Mercado Livre com o mesmo periodo, entao nao vale a pena guardar um xlsx inteiro no
   banco so' pra isso). "conteudo" fica de fora por enquanto (coluna continua existindo, sem NOT
   NULL, pra nao quebrar se um dia precisar guardar o arquivo de novo). */
pool.query(`create table if not exists auditoria_anexos (
  id serial primary key,
  loja text not null,
  mes text not null,
  tipo text not null,
  nome_arquivo text,
  conteudo text,
  resumo jsonb,
  criado_em timestamptz not null default now()
)`).catch(e => console.error('Falha ao garantir tabela "auditoria_anexos":', e.message));
pool.query('alter table auditoria_anexos alter column conteudo drop not null')
  .catch(e => console.error('Falha ao tornar "conteudo" opcional em auditoria_anexos:', e.message));
/* resultado da Auditoria Financeira Mensal, salvo por loja+periodo exato (pedido do Felipe 23/08:
   a auditoria demora varios minutos - milhares de pedidos, uma chamada extra ao Mercado Pago por
   pedido - entao rodar de novo toda vez que reabre o Doca era desperdicio). O job em memoria
   (auditoriaJobs, mais abaixo) continua existindo so' pra acompanhar o progresso ENQUANTO roda;
   assim que termina, o resultado cai aqui e fica disponivel pra sempre (ate' rodar de novo o MESMO
   periodo, que sobrescreve). */
pool.query(`create table if not exists auditoria_resultados (
  id serial primary key,
  loja text not null,
  de text not null,
  ate text not null,
  resultado jsonb,
  criado_em timestamptz not null default now(),
  unique (loja, de, ate)
)`).catch(e => console.error('Falha ao garantir tabela "auditoria_resultados":', e.message));
const app = express();
app.use(express.json({ limit: '10mb' })); // o estado inteiro do Doca (produtos, envios, historico) pode passar de 100kb (limite padrao)
const allowedOrigins = ALLOWED_ORIGIN.split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: allowedOrigins.includes('*') ? true : allowedOrigins,
  methods: ['GET', 'POST', 'DELETE']
}));
/* ---- login (usuario/senha) pra proteger o app hospedado e os dados na nuvem (v25) ----
   Usa autenticacao HTTP Basic - o proprio navegador sabe mostrar a tela de login sozinho
   quando abre a pagina (funciona em celular tambem), sem precisar de nenhuma tela de login
   customizada. So protege as rotas /doca (o app em si) e /estado (os dados) - as rotas de
   sincronizacao com Mercado Livre/Mercado Pago continuam sem login (sao so numeros/estoque,
   nao tem como um estranho adivinhar a URL exata + loja e fazer algo com isso, e travar
   ELAS especificamente quebraria a sincronizacao automatica do proprio Doca, que nao manda
   usuario/senha nessas chamadas). */
function exigirLogin(req, res, next) {
  if (!DOCA_USER || !DOCA_SENHA) {
    return res.status(500).send('Login do Doca nao configurado no servidor (falta DOCA_USER e DOCA_SENHA nas variaveis de ambiente).');
  }
  const auth = req.headers.authorization || '';
  const [tipo, credenciais] = auth.split(' ');
  if (tipo === 'Basic' && credenciais) {
    const decodificado = Buffer.from(credenciais, 'base64').toString('utf8');
    const i = decodificado.indexOf(':');
    const usuario = i >= 0 ? decodificado.slice(0, i) : decodificado;
    const senha = i >= 0 ? decodificado.slice(i + 1) : '';
    if (usuario === DOCA_USER && senha === DOCA_SENHA) return next();
  }
  res.set('WWW-Authenticate', 'Basic realm="Doca"');
  res.status(401).send('Login necessario.');
}
const LOJAS_VALIDAS = ['TorvStore', 'Dor Block', 'Orbix Brasil', 'TorvShop'];
/* "Dor Block" -> "DOR_BLOCK", "Orbix Brasil" -> "ORBIX_BRASIL" etc. — usado pra montar o nome
   das variaveis de ambiente especificas de cada loja. */
function normalizarChaveLoja(loja) {
  return String(loja || '')
    .normalize('NFD').replace(/[̀-ͯ]/g, '') // tira acento
    .toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '');
}
/* credenciais do aplicativo do Mercado Livre pra uma loja: se existir ML_CLIENT_ID_<LOJA> /
   ML_CLIENT_SECRET_<LOJA> no ambiente, usa essas (aplicativo proprio da loja); senao cai pro
   ML_CLIENT_ID/ML_CLIENT_SECRET globais (hoje sao os da TorvShop, primeira loja configurada -
   continua funcionando sem precisar duplicar variavel de ambiente pra ela). */
function credenciaisDaLoja(loja) {
  const chave = normalizarChaveLoja(loja);
  const clientId = process.env[`ML_CLIENT_ID_${chave}`] || ML_CLIENT_ID;
  const clientSecret = process.env[`ML_CLIENT_SECRET_${chave}`] || ML_CLIENT_SECRET;
  return { clientId, clientSecret };
}
const loginsPendentes = new Map();
function limparLoginsAntigos() {
  const limite = Date.now() - 10 * 60 * 1000;
  for (const [state, info] of loginsPendentes) {
    if (info.criadoEm < limite) loginsPendentes.delete(state);
  }
}
function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function gerarPkce() {
  const codeVerifier = base64url(crypto.randomBytes(48));
  const codeChallenge = base64url(crypto.createHash('sha256').update(codeVerifier).digest());
  return { codeVerifier, codeChallenge };
}
async function salvarTokens(loja, { access_token, refresh_token, expires_in, user_id }) {
  const expiresAt = new Date(Date.now() + (expires_in - 60) * 1000);
  await pool.query(
    `insert into ml_accounts (loja, ml_user_id, access_token, refresh_token, expires_at, atualizado_em)
     values ($1,$2,$3,$4,$5, now())
     on conflict (loja) do update set
       ml_user_id = excluded.ml_user_id,
       access_token = excluded.access_token,
       refresh_token = excluded.refresh_token,
       expires_at = excluded.expires_at,
       atualizado_em = now()`,
    [loja, String(user_id || ''), access_token, refresh_token, expiresAt]
  );
}
async function pegarConta(loja) {
  const r = await pool.query('select * from ml_accounts where loja = $1', [loja]);
  return r.rows[0] || null;
}
async function tokenValido(loja) {
  const conta = await pegarConta(loja);
  if (!conta) throw new Error(`A loja "${loja}" ainda nao foi autorizada. Rode /oauth/login?loja=${encodeURIComponent(loja)} primeiro.`);
  if (new Date(conta.expires_at).getTime() > Date.now()) {
    return conta.access_token;
  }
  const { clientId, clientSecret } = credenciaisDaLoja(loja);
  const resp = await fetch('https://api.mercadolibre.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: clientId,
      client_secret: clientSecret,
      refresh_token: conta.refresh_token
    })
  });
  const dados = await resp.json();
  if (!resp.ok) throw new Error('Falha ao renovar token do ML: ' + JSON.stringify(dados));
  await salvarTokens(loja, dados);
  return dados.access_token;
}
app.get('/health', (_req, res) => res.json({ ok: true, agora: new Date().toISOString() }));
app.post('/ml/webhook', async (req, res) => {
  res.sendStatus(200); // responde rapido - o ML cancela o webhook se demorar pra responder
  try {
    const { topic, user_id, resource } = req.body || {};
    const topicoLower = String(topic || '').toLowerCase();
    if (topicoLower.includes('claim') && user_id) {
      const r = await pool.query('select loja from ml_accounts where ml_user_id = $1', [String(user_id)]);
      const loja = r.rows[0] && r.rows[0].loja;
      if (loja) {
        processarReclamacoesDaLoja(loja).catch(e => console.error('[webhook claims] falha ao processar', loja, e.message));
      }
    } else if (topicoLower.includes('message') && user_id && resource) {
      /* mensagens pos-venda NAO sao mais buscadas sob demanda (ver comentario grande la' embaixo,
         perto de "Mensagens pos-venda") - o unico jeito que funcionou ate' agora foi via webhook.
         So' processa aqui, fora do sync normal. */
      processarWebhookMensagem(String(user_id), resource).catch(e => console.error('[webhook mensagens] falha ao processar notificacao:', e.message));
    }
  } catch (e) {
    console.error('[webhook] erro ao processar notificacao:', e.message);
  }
});

/* ================= Reclamações e mediações (claims) - resolução automática =================
   Regra definida pelo Felipe (19/08): so' 2 desfechos possiveis, sem meio termo:
     1) Se o FRETE desse pedido foi absorvido pelo vendedor (frete "gratis" pro comprador, saiu
        do bolso da loja) -> resolve por DEVOLUCAO (o comprador devolve o produto, o dinheiro
        volta quando o status do envio de devolucao virar shipped/delivered - fluxo padrao do ML).
     2) Se o frete NAO foi absorvido pelo vendedor (o comprador pagou o frete) -> resolve com
        REEMBOLSO 100% na hora, sem pedir devolucao do produto.
   So' age quando a acao necessaria realmente aparece em available_actions do player "respondent"
   (o vendedor) - se nao aparecer (claim ainda em estagio inicial, em mediacao/dispute, ou tipo de
   reclamacao que nao aceita essas acoes), NAO tenta nada e fica registrado como "nao resolvido
   automaticamente" pra revisao manual - nunca forca uma acao que a API nao ofereceu. So' atua em
   reclamacoes cujo resource==="order" (reclamacao sobre pagamento/envio direto sem pedido
   associado fica de fora - a regra do Felipe foi definida em cima de pedido/frete).
   Prazo (Felipe, 20/08): o ML da' ate' 14h do proximo dia util pra responder - por isso isso roda
   toda vez que o /sync roda (ao abrir o Doca / apertar Atualizar) E via webhook (quase na hora que
   a reclamacao abre, se o Render estiver acordado) - NAO precisa avisar em tempo real, so' fica
   tudo registrado em ml_reclamacoes_log pro Doca mostrar um relatorio do que foi feito. */
/* Analise de Mercado (21/08, pedido do Felipe): comparar vendas proprias x vendas da categoria
   inteira no Mercado Livre, mes a mes, pra ter uma base de sazonalidade e planejar estoque.
   NAO tem API publica pra "Analise de mercado" (tendencias por categoria, concorrencia) - so'
   existe dentro do painel logado do vendedor (vendedores.mercadolivre.com.br/metricas/...).
   Por isso os numeros da categoria sao alimentados A MAO (Felipe manda o print, eu registro aqui)
   - ja o category_id de cada produto e' puxado automaticamente pela API normal (ver campo
   categoria_id em ml_produtos), e as vendas PROPRIAS de cada mes sao calculadas automaticamente
   a partir do historico de pedidos que a gente ja busca (ver /mercado/vendas-proprias). */
/* fluxo de caixa (23/08, pedido do Felipe): a coluna MONEY_RELEASE_DATE ja vinha no relatorio
   "Dinheiro em conta" (COLUNAS_DINHEIRO_EM_CONTA mais abaixo) mas so' o total agregado (a_receber)
   era guardado - a data de cada liberacao pendente era jogada fora. Guarda agora agrupado por
   data, pra dar pra projetar o saldo dia a dia (agenda_liberacoes: [{data,valor}, ...]). */
pool.query('alter table mp_financeiro add column if not exists agenda_liberacoes jsonb').catch(e => console.error('Falha ao adicionar coluna "agenda_liberacoes":', e.message));
/* coluna "Projetado" do Fluxo de Caixa (27/08, pedido do Felipe): prazo de liberacao empirico
   (mediana real de dias entre a venda e o dinheiro cair, calculado do proprio relatorio de
   "dinheiro em conta" - achado real 27/08: e' D+28 na TorvStore e na Dor Block, nao D+8 como o
   Felipe lembrava) e receita liquida diaria media dos ultimos 15 dias (mesma fonte, sem precisar
   cadastrar preco de venda em lugar nenhum). Usados pra projetar receita futura no Fluxo de Caixa. */
pool.query('alter table mp_financeiro add column if not exists prazo_liberacao_dias numeric').catch(e => console.error('Falha ao adicionar coluna "prazo_liberacao_dias":', e.message));
pool.query('alter table mp_financeiro add column if not exists receita_diaria_media numeric').catch(e => console.error('Falha ao adicionar coluna "receita_diaria_media":', e.message));
pool.query('alter table mp_financeiro add column if not exists receita_atualizado_em timestamptz').catch(e => console.error('Falha ao adicionar coluna "receita_atualizado_em":', e.message));
pool.query('alter table ml_produtos add column if not exists categoria_id text')
  .catch(e => console.error('Falha ao adicionar coluna "categoria_id" em ml_produtos:', e.message));
/* "Entrada Pendente 2.0" (28/08, pedido do Felipe): guarda o LOG REAL de recebimento no galpao do
   Full (endpoint /stock/fulfillment/operations/search, type=inbound_reception), pra' o Doca (front)
   conseguir saber com precisao quanto de um envio confirmado ja' foi recebido de verdade pelo ML -
   em vez de inferir por delta de aptas+transferencia (que se confunde com venda/ajuste no meio do
   caminho). So' e' preenchido quando o item esta' na lista "pendentes" que o front manda no /sync
   (ver rota /sync abaixo) - assim nao gasta chamada de API a toa pra item sem nada em processamento. */
pool.query('alter table ml_produtos add column if not exists recebimentos_full jsonb')
  .catch(e => console.error('Falha ao adicionar coluna "recebimentos_full" em ml_produtos:', e.message));
pool.query(`create table if not exists ml_mercado_categoria (
  id serial primary key,
  loja text not null,
  ml_item_id text not null,
  mes text not null,
  vendas_brutas_categoria numeric,
  unidades_categoria numeric,
  preco_medio_categoria numeric,
  criado_em timestamptz not null default now(),
  atualizado_em timestamptz not null default now(),
  unique(loja, ml_item_id, mes)
)`).catch(e => console.error('Falha ao garantir tabela "ml_mercado_categoria":', e.message));
/* 21/08 (2a rodada): Felipe achou o botao "Baixar relatorio" dentro do proprio painel do Mercado
   Livre (relatorio .xlsx "Mais vendidos nas suas categorias" - top 100 produtos da categoria, com
   preco/unidades vendidas/visualizacoes/etc de cada um, pro periodo escolhido). Isso e' bem melhor
   que digitar 4 numeros de um print: da' pra somar os 100 produtos e ter um numero de categoria bem
   mais preciso, e ainda mostrar um ranking de concorrentes dentro do Doca. O parse do .xlsx e' feito
   no PROPRIO NAVEGADOR (lib SheetJS via CDN, doca.html so' manda o resumo ja' calculado pra ca) -
   por isso essas colunas extras sao todas OPCIONAIS (o formulario manual de digitar 4 numeros
   continua funcionando do jeito que estava, sem periodo_de/periodo_ate/etc). */
/* periodo_de/periodo_ate sao TEXT (nao "date") de proposito: guardam so' a data "YYYY-MM-DD" que
   o proprio Mercado Livre usou no relatorio, sem nenhuma conta em cima - assim nao corre risco do
   driver do Postgres devolver um objeto Date pro node (em vez de string) e bagunçar a comparacao
   com o nome do arquivo/rotulo mostrado no Doca. */
pool.query('alter table ml_mercado_categoria add column if not exists periodo_de text').catch(e => console.error('Falha ao adicionar coluna "periodo_de":', e.message));
pool.query('alter table ml_mercado_categoria add column if not exists periodo_ate text').catch(e => console.error('Falha ao adicionar coluna "periodo_ate":', e.message));
pool.query('alter table ml_mercado_categoria add column if not exists categoria_nome text').catch(e => console.error('Falha ao adicionar coluna "categoria_nome":', e.message));
pool.query('alter table ml_mercado_categoria add column if not exists produtos_analisados integer').catch(e => console.error('Falha ao adicionar coluna "produtos_analisados":', e.message));
pool.query('alter table ml_mercado_categoria add column if not exists top_produtos jsonb').catch(e => console.error('Falha ao adicionar coluna "top_produtos":', e.message));
pool.query("alter table ml_mercado_categoria add column if not exists fonte text default 'manual'").catch(e => console.error('Falha ao adicionar coluna "fonte":', e.message));

pool.query(`create table if not exists ml_reclamacoes_log (
  id serial primary key,
  loja text not null,
  claim_id text not null,
  order_id text,
  reason_id text,
  frete_vendedor boolean,
  valor_frete_vendedor numeric,
  acao_tomada text,
  sucesso boolean not null default false,
  motivo text,
  tentativas int not null default 1,
  criado_em timestamptz not null default now(),
  atualizado_em timestamptz not null default now(),
  unique(loja, claim_id)
)`).catch(e => console.error('Falha ao garantir tabela "ml_reclamacoes_log":', e.message));

async function buscarClaimsAbertas(loja) {
  const accessToken = await tokenValido(loja);
  const conta = await pegarConta(loja);
  const claims = [];
  let offset = 0;
  const limit = 50;
  while (true) {
    const url = `https://api.mercadolibre.com/post-purchase/v1/claims/search?player_role=respondent&player_user_id=${conta.ml_user_id}&status=opened&limit=${limit}&offset=${offset}`;
    const j = await fetchMLDebug(url, { headers: { Authorization: `Bearer ${accessToken}` } });
    const pagina = j.data || j.results || [];
    claims.push(...pagina);
    const total = (j.paging && j.paging.total) || pagina.length;
    offset += limit;
    if (pagina.length < limit || offset >= total) break;
  }
  return claims;
}

async function pegarLogReclamacao(loja, claimId) {
  const r = await pool.query('select * from ml_reclamacoes_log where loja = $1 and claim_id = $2', [loja, String(claimId)]);
  return r.rows[0] || null;
}
async function salvarLogReclamacao(loja, claimId, patch) {
  const existente = await pegarLogReclamacao(loja, claimId);
  const tentativas = (existente ? existente.tentativas : 0) + 1;
  await pool.query(
    `insert into ml_reclamacoes_log (loja, claim_id, order_id, reason_id, frete_vendedor, valor_frete_vendedor, acao_tomada, sucesso, motivo, tentativas, atualizado_em)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, now())
     on conflict (loja, claim_id) do update set
       order_id = excluded.order_id, reason_id = excluded.reason_id,
       frete_vendedor = excluded.frete_vendedor, valor_frete_vendedor = excluded.valor_frete_vendedor,
       acao_tomada = excluded.acao_tomada, sucesso = excluded.sucesso, motivo = excluded.motivo,
       tentativas = excluded.tentativas, atualizado_em = now()`,
    [loja, String(claimId), patch.orderId || null, patch.reasonId || null, patch.freteVendedor ?? null,
     patch.valorFreteVendedor ?? null, patch.acaoTomada || null, !!patch.sucesso, patch.motivo || null, tentativas]
  );
}

async function processarReclamacaoAutomatico(loja, claim, accessToken) {
  const claimId = claim.id;
  const jaResolvido = await pegarLogReclamacao(loja, claimId);
  if (jaResolvido && jaResolvido.sucesso) return { claimId, pulado: true, motivo: 'ja resolvido antes' };
  if (claim.resource !== 'order') {
    await salvarLogReclamacao(loja, claimId, { sucesso: false, motivo: `reclamacao sobre "${claim.resource}" (nao "order") - fora da regra automatica, precisa revisao manual` });
    return { claimId, pulado: true, motivo: 'resource != order' };
  }
  const orderId = claim.resource_id;
  let valorVenda = null;
  try {
    const pedido = await fetchMLDebug(`https://api.mercadolibre.com/orders/${orderId}`, { headers: { Authorization: `Bearer ${accessToken}` } });
    // preco UNITARIO do produto (nao o total do pedido) - se tiver mais de 1 item no pedido, usa
    // o mais caro deles pra decidir (pedido do Felipe 24/08, corrigido: e' preco do produto, nao
    // total do pedido - um pedido de 3 unidades de R$8 nao deveria cair na regra manual).
    valorVenda = Math.max(0, ...(pedido.order_items || []).map(oi => Number(oi.unit_price) || 0));
  } catch (e) {
    await salvarLogReclamacao(loja, claimId, { orderId, reasonId: claim.reason_id, sucesso: false, motivo: 'falha ao buscar o pedido: ' + e.message });
    return { claimId, erro: e.message };
  }
  /* regra nova do Felipe (24/08): preco unitario do produto acima de R$20 NAO entra na resolucao
     automatica - fica pendente pra revisao manual mesmo (mesmo padrao de "sucesso:false com
     motivo" ja usado nos outros casos que pulam a automacao, pra aparecer certinho como pendente
     na tela). Abaixo de R$20 continua tudo automatico como ja era. */
  if (valorVenda > 20) {
    await salvarLogReclamacao(loja, claimId, { orderId, reasonId: claim.reason_id, sucesso: false, motivo: `Produto de R$${valorVenda.toFixed(2).replace('.', ',')} (acima de R$20) - fora da regra automática, precisa revisão manual` });
    return { claimId, pulado: true, motivo: 'valor da venda acima de R$20 - revisao manual' };
  }
  const respondent = (claim.players || []).find(p => p.role === 'respondent') || {};
  const acoes = (respondent.available_actions || []).map(a => a.action);
  /* CORRIGIDO 26/08 de novo (insight do Felipe, apos o erro real da claim 5565994624/R$9,36): a
     decisao NAO tenta mais PREVER se o frete de devolucao seria gratis (tentativa anterior usava
     base_cost do shipment - ver historico) - previsao de custo se mostrou pouco confiavel (foi
     exatamente essa previsao errada que causou o R$9,36 cobrado numa devolucao que deveria ter
     sido reembolso sem devolucao). O sinal CONFIAVEL e' o proprio Mercado Livre: ele so' oferece a
     acao formal "allow_return"/"allow_return_label" quando a devolucao gratuita/limpa esta
     realmente disponivel pra aquele pedido - e' a mesma caixinha de dialogo/botao que aparece pro
     Felipe manualmente no site quando ele resolve uma reclamacao na mao. Por isso agora:
       1) allow_return/allow_return_label disponivel -> Mercado Livre esta oferecendo devolucao
          formalmente -> aplica a devolucao.
       2) senao, refund disponivel -> reembolso 100% sem devolucao (acao formal).
       3) senao -> fallback por mensagem, mas a mensagem NUNCA promete devolucao (so' "reembolso
          100% sem devolucao") - o Mercado Livre nao confirmou formalmente que a devolucao esta
          disponivel, entao nao faz sentido prometer ela por mensagem. */
  /* fallback (Felipe, 20/08): quando a reclamacao NAO tem o botao formal disponivel - o que ele diz
     ser o caso mais comum na pratica - em vez de so' ficar "pendente de revisao manual" pra sempre,
     manda uma MENSAGEM pro comprador oferecendo "Reembolso de 100% sem devolucao" (mesmo truque que
     ele ja usa manualmente no proprio Mercado Livre). Usa a acao "send_message_to_complainant"
     (quase sempre disponivel, mesmo quando refund/allow_return ainda nao estao) - endpoint
     confirmado na doc oficial: POST /marketplace/v2/claims/{id}/actions/send-message. Isso NAO e'
     um refund automatico de verdade (o comprador ainda precisa aceitar/a ML precisa processar) -
     por isso fica marcado como resolvido (nao fica preso em "pendente"), mas com o motivo deixando
     claro que foi por mensagem, nao pela acao formal. So' usado como fallback - NUNCA no lugar da
     devolucao formal quando ela estiver disponivel (pra nao dar reembolso sem pedir o produto de
     volta quando dava pra fazer a devolucao de verdade). */
  async function tentarFallbackMensagem(motivoAcaoIndisponivel) {
    /* qual papel recebe a mensagem depende do estagio da reclamacao (confirmado com dado real em
       20/08: reclamacao em mediacao - stage "dispute" - so' oferece "send_message_to_mediator",
       NAO "send_message_to_complainant", porque nesse estagio o vendedor fala com o mediador do
       Mercado Livre, nao mais direto com o comprador):
         estagio "claim"   -> send_message_to_complainant, receiver_role "complainant"
         estagio "dispute" -> send_message_to_mediator, receiver_role "mediator"
       Tenta o que fizer sentido pro estagio atual primeiro; se por algum motivo o outro tambem
       estiver disponivel e o preferido falhar, tenta o outro antes de desistir. */
    const candidatos = claim.stage === 'dispute'
      ? [{ acao: 'send_message_to_mediator', role: 'mediator' }, { acao: 'send_message_to_complainant', role: 'complainant' }]
      : [{ acao: 'send_message_to_complainant', role: 'complainant' }, { acao: 'send_message_to_mediator', role: 'mediator' }];
    /* texto da mensagem SEMPRE "sem devolucao" (CORRIGIDO 26/08, 2a vez): so' chega no fallback
       quando nem allow_return/allow_return_label nem refund estao disponiveis - ou seja, o
       Mercado Livre NAO confirmou formalmente que a devolucao esta disponivel pra esse pedido.
       Prometer "com devolucao" por mensagem sem essa confirmacao foi exatamente o que causou o
       erro real de R$9,36 (claim 5565994624) - a mensagem antiga prometia devolucao baseada numa
       previsao de custo, nao numa acao formal do ML. */
    const textoMensagem = 'Reembolso de 100% sem devolução.';
    const disponiveis = candidatos.filter(c => acoes.includes(c.acao));
    if (!disponiveis.length) {
      /* Antes de marcar como "precisa revisao manual": as vezes o vendedor NAO tem mais nenhuma
         acao disponivel (nem botao formal, nem mensagem) porque o Mercado Livre JA habilitou uma
         devolucao/mediacao sozinho e esta so' esperando o comprador agir - nesse caso nao e' um caso
         travado, e' um caso que ja esta andando por conta propria. Confirmado com dado real em 20/08
         e 21/08 (Felipe verificou manualmente no ML: reclamacao ja tinha resposta do vendedor,
         "esperando resposta do comprador", so' que o campo "available_actions" da busca de lista fica
         vazio nesses casos). Sinal disponivel so' no detalhe completo da reclamacao:
         "related_entities" contendo "return" = devolucao ja em andamento. Por isso busca o detalhe
         completo aqui (so' quando cai nesse caso, pra nao gastar chamada a toa nos outros). */
      let jaEmAndamento = false;
      let motivoAndamento = '';
      try {
        const detalhe = await fetchMLDebug(`https://api.mercadolibre.com/post-purchase/v1/claims/${claimId}`, { headers: { Authorization: `Bearer ${accessToken}` } });
        if (Array.isArray(detalhe.related_entities) && detalhe.related_entities.includes('return')) {
          jaEmAndamento = true;
          motivoAndamento = 'o Mercado Livre ja habilitou a devolucao sozinho (related_entities: return)';
        }
      } catch (e) { /* nao conseguiu confirmar por esse lado - ainda tenta o outro sinal abaixo */ }
      if (!jaEmAndamento) {
        /* segundo sinal, achado em 21/08 (Felipe viu no proprio ML: reclamacao com "Mercado Livre:
           Perfeito! Vamos oferecer ao comprador um reembolso total..." e status "esperando resposta
           do comprador", mesmo com related_entities vazio e acoes vazias) - o assistente do proprio
           Mercado Livre as vezes ja manda uma mensagem em nome do vendedor oferecendo solucao, sem
           que isso apareca no related_entities. Unico jeito de pegar isso e' olhando o HISTORICO de
           mensagens da reclamacao: se ja existe QUALQUER mensagem com sender_role "respondent"
           (o proprio vendedor, incluindo as que o assistente do ML manda em nome dele), quer dizer
           que ja foi respondida - so' falta o comprador reagir. */
        try {
          const mensagens = await fetchMLDebug(`https://api.mercadolibre.com/marketplace/v2/claims/${claimId}/messages`, { headers: { Authorization: `Bearer ${accessToken}` } });
          const lista = Array.isArray(mensagens) ? mensagens : (mensagens.results || []);
          if (lista.some(m => m.sender_role === 'respondent')) {
            jaEmAndamento = true;
            motivoAndamento = 'ja existe mensagem do vendedor nessa reclamacao (respondida antes, inclusive pelo proprio assistente do Mercado Livre)';
          }
        } catch (e) { /* nao conseguiu confirmar - segue tratando como pendente mesmo, pra nao esconder um caso real */ }
      }
      if (jaEmAndamento) {
        await salvarLogReclamacao(loja, claimId, { orderId, reasonId: claim.reason_id, acaoTomada: 'ja respondida (pelo Doca ou pelo proprio Mercado Livre) - aguardando o comprador', sucesso: true, motivo: motivoAcaoIndisponivel + ` - mas ${motivoAndamento}, esperando o comprador agir - nada a fazer da nossa parte` });
        return { claimId, ok: true, acao: 'aguardando-comprador' };
      }
      await salvarLogReclamacao(loja, claimId, { orderId, reasonId: claim.reason_id, sucesso: false, motivo: motivoAcaoIndisponivel + ` - e nem mensagem pro comprador/mediador esta disponivel nessa reclamacao (estagio: ${claim.stage || '?'}) - precisa revisao manual` });
      return { claimId, erro: 'acao indisponivel' };
    }
    let ultimoErro = null;
    for (const c of disponiveis) {
      try {
        /* NAO usa fetchMLDebug aqui de proposito - esse endpoint devolve 201 Created com o CORPO
           VAZIO quando da certo (confirmado na doc oficial: "Response: status 201 created", sem
           nenhum JSON junto). fetchMLDebug trata corpo vazio como erro (pensado pra endpoints que
           SEMPRE devolvem JSON) - usar ele aqui fazia a mensagem ser enviada com sucesso de
           verdade mas o Doca registrar como falha, tentar de novo no proximo sync, e mandar a
           MESMA mensagem duplicada toda vez (bug real encontrado em 20/08, corrigido). Confere so'
           r.ok (2xx) direto, sem exigir corpo JSON nenhum. */
        const rMsg = await fetch(`https://api.mercadolibre.com/marketplace/v2/claims/${claimId}/actions/send-message`, {
          method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ receiver_role: c.role, message: textoMensagem, attachments: [] })
        });
        if (!rMsg.ok) {
          const brutoMsg = await rMsg.text().catch(() => '');
          throw new Error(`send-message respondeu status ${rMsg.status}${brutoMsg ? ': ' + brutoMsg.slice(0, 300) : ''}`);
        }
        await salvarLogReclamacao(loja, claimId, { orderId, reasonId: claim.reason_id, acaoTomada: `mensagem pro ${c.role === 'mediator' ? 'mediador' : 'comprador'}: ${textoMensagem} (sem botão de ação formal disponível)`, sucesso: true, motivo: motivoAcaoIndisponivel + ` - mandada mensagem (estagio: ${claim.stage || '?'}): "${textoMensagem}", no lugar da ação formal` });
        return { claimId, ok: true, acao: 'mensagem-reembolso' };
      } catch (e) {
        ultimoErro = e;
      }
    }
    await salvarLogReclamacao(loja, claimId, { orderId, reasonId: claim.reason_id, sucesso: false, motivo: motivoAcaoIndisponivel + ' - falha ao mandar a mensagem de reembolso: ' + (ultimoErro && ultimoErro.message) });
    return { claimId, erro: ultimoErro && ultimoErro.message };
  }
  if (acoes.includes('allow_return') || acoes.includes('allow_return_label')) {
    // regra 1: Mercado Livre esta oferecendo a devolucao formalmente -> aplica a devolucao
    try {
      await fetchMLDebug(`https://api.mercadolibre.com/post-purchase/v1/claims/${claimId}/expected-resolutions/allow-return`, {
        method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' }
      });
      await salvarLogReclamacao(loja, claimId, { orderId, reasonId: claim.reason_id, acaoTomada: 'devolucao (allow-return)', sucesso: true, motivo: 'Mercado Livre ofereceu a acao formal de devolucao (allow_return/allow_return_label) - devolucao aplicada automaticamente' });
      return { claimId, ok: true, acao: 'devolucao' };
    } catch (e) {
      await salvarLogReclamacao(loja, claimId, { orderId, reasonId: claim.reason_id, sucesso: false, motivo: 'falha ao oferecer devolucao: ' + e.message });
      return { claimId, erro: e.message };
    }
  } else if (acoes.includes('refund')) {
    // regra 2: devolucao formal nao disponivel, mas reembolso formal esta -> reembolso 100% sem devolucao
    try {
      await fetchMLDebug(`https://api.mercadolibre.com/post-purchase/v1/claims/${claimId}/expected-resolutions/refund`, {
        method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' }
      });
      await salvarLogReclamacao(loja, claimId, { orderId, reasonId: claim.reason_id, acaoTomada: 'reembolso 100% (refund)', sucesso: true, motivo: 'acao formal de devolucao (allow_return/allow_return_label) nao disponivel - reembolso 100% aplicado automaticamente, sem devolucao' });
      return { claimId, ok: true, acao: 'reembolso' };
    } catch (e) {
      await salvarLogReclamacao(loja, claimId, { orderId, reasonId: claim.reason_id, sucesso: false, motivo: 'falha ao aplicar reembolso: ' + e.message });
      return { claimId, erro: e.message };
    }
  } else {
    // regra 3: nem devolucao nem reembolso formal disponiveis ainda -> fallback por mensagem
    return tentarFallbackMensagem('nem a acao de devolucao (allow_return/allow_return_label) nem a de reembolso (refund) estao disponiveis nessa reclamacao ainda');
  }
}

async function processarReclamacoesDaLoja(loja) {
  const accessToken = await tokenValido(loja);
  const claims = await buscarClaimsAbertas(loja);
  const resultados = [];
  for (const claim of claims) {
    const r = await processarReclamacaoAutomatico(loja, claim, accessToken);
    resultados.push(r);
    await sleep(150);
  }
  /* limpeza (21/08, dado real do Felipe): uma reclamacao que ficou marcada como "pendente"
     (sucesso=false) - por exemplo, pelo bug antigo do corpo vazio (201) que fazia o Doca achar que
     a mensagem de fallback tinha falhado quando na verdade foi enviada com sucesso - mas que JA
     FECHOU de verdade no Mercado Livre (comprador aceitou, mediacao encerrada etc) nunca mais
     aparece em buscarClaimsAbertas (so' traz status=opened), entao o loop acima nunca revisita ela
     pra corrigir o log - fica pendente pra sempre no card, mesmo ja resolvida havia dias.
     Aqui, pra cada pendente registrada nos ultimos 30 dias que NAO esta mais entre as abertas de
     agora, confere o status atual dela direto na API - se ja fechou, corrige o log pra "resolvida"
     (some da lista de pendentes do Doca). */
  try {
    const idsAbertas = new Set(claims.map(c => String(c.id)));
    const rPendentes = await pool.query(
      `select claim_id, order_id, reason_id, frete_vendedor, valor_frete_vendedor from ml_reclamacoes_log where loja = $1 and sucesso = false and atualizado_em > now() - interval '30 days'`,
      [loja]
    );
    for (const row of rPendentes.rows) {
      const claimId = row.claim_id;
      if (idsAbertas.has(String(claimId))) continue; // ainda esta aberta, ja foi tratada no loop acima
      try {
        const detalhe = await fetchMLDebug(`https://api.mercadolibre.com/post-purchase/v1/claims/${claimId}`, { headers: { Authorization: `Bearer ${accessToken}` } });
        if (detalhe.status !== 'opened') {
          await salvarLogReclamacao(loja, claimId, {
            orderId: row.order_id, reasonId: row.reason_id, freteVendedor: row.frete_vendedor, valorFreteVendedor: row.valor_frete_vendedor,
            sucesso: true, acaoTomada: 'reclamacao encerrada no Mercado Livre (nao esta mais entre as abertas)',
            motivo: `estava marcada como pendente, mas a reclamacao ja fechou no Mercado Livre (status: ${detalhe.status}) - corrigido automaticamente`
          });
        }
      } catch (e) { /* nao conseguiu confirmar essa agora - tenta de novo no proximo sync, nao bloqueia as outras */ }
      await sleep(150);
    }
  } catch (e) {
    console.error('Falha na limpeza de reclamacoes ja fechadas (' + loja + '):', e.message);
  }
  return { totalAbertas: claims.length, resultados };
}

/* rota de diagnostico (so' LE, nao executa nada) - testa a busca de reclamacoes abertas ANTES de
   ligar a resolucao automatica de verdade, seguindo o mesmo padrao ja usado no resto do arquivo
   (testar via /debug/* com dado real antes de automatizar). Ex.:
   /debug/claims/buscar?loja=TorvStore */
app.get('/debug/claims/buscar', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const claims = await buscarClaimsAbertas(loja);
    res.json({ ok: true, loja, total: claims.length, claims });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo }); }
});
/* rota de diagnostico (so' LE, nao executa nada) - dump CRU (sem nenhum recorte/resumo) do que a
   API do Mercado Livre devolve pro shipment de uma venda, tanto /shipments/{id} (dados gerais:
   logistic_type, tipo de envio, etc.) quanto /shipments/{id}/costs (que hoje o Doca so' olha o
   campo "senders" pra decidir frete do vendedor). Criado 26/08 (Felipe achou um caso real onde a
   automacao ofereceu devolucao achando que seria de graca pro vendedor, baseado no frete da VENDA
   original, mas a devolucao de verdade cobrou R$9,36 dele) - objetivo e' achar, com dado real, se
   existe algum campo que realmente preveja o custo/gratuidade do frete de DEVOLUCAO, em vez de
   usar o frete da venda como proxy (que se mostrou errado nesse caso). Ex.:
   /debug/claims/frete-shipment?shippingId=47619274554 */
app.get('/debug/claims/frete-shipment', async (req, res) => {
  try {
    const shippingId = req.query.shippingId;
    const loja = req.query.loja;
    if (!shippingId) return res.status(400).json({ ok: false, erro: 'Parametro "shippingId" obrigatorio.' });
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const accessToken = await tokenValido(loja);
    const [shipment, costs] = await Promise.all([
      fetchMLDebug(`https://api.mercadolibre.com/shipments/${shippingId}`, { headers: { Authorization: `Bearer ${accessToken}` } }).catch(e => ({ erro: e.message })),
      fetchMLDebug(`https://api.mercadolibre.com/shipments/${shippingId}/costs`, { headers: { Authorization: `Bearer ${accessToken}` } }).catch(e => ({ erro: e.message }))
    ]);
    res.json({ ok: true, shippingId, shipment, costs });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo }); }
});
/* rota de diagnostico (so' LE, nao executa nada) - mostra, pra 1 reclamacao especifica,
   exatamente o que a automacao IRIA decidir (frete do vendedor ou nao, acao disponivel ou nao)
   SEM aplicar nada de verdade - so' simula. Ex.:
   /debug/claims/simular?loja=TorvStore&claimId=5298903643 */
app.get('/debug/claims/simular', async (req, res) => {
  try {
    const loja = req.query.loja;
    const claimId = req.query.claimId;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!claimId) return res.status(400).json({ ok: false, erro: 'Parametro "claimId" obrigatorio.' });
    const accessToken = await tokenValido(loja);
    const claim = await fetchMLDebug(`https://api.mercadolibre.com/post-purchase/v1/claims/${claimId}`, { headers: { Authorization: `Bearer ${accessToken}` } });
    let orderErro = null, valorVenda = null;
    try {
      const pedido = await fetchMLDebug(`https://api.mercadolibre.com/orders/${claim.resource_id}`, { headers: { Authorization: `Bearer ${accessToken}` } });
      valorVenda = Math.max(0, ...(pedido.order_items || []).map(oi => Number(oi.unit_price) || 0));
    } catch (e) { orderErro = e.message; }
    const respondent = (claim.players || []).find(p => p.role === 'respondent') || {};
    const acoes = (respondent.available_actions || []).map(a => a.action);
    let regraAplicavel = null;
    // dado real (20/08): reclamacao em mediacao (stage "dispute") so' oferece send_message_to_mediator,
    // nao send_message_to_complainant (que so' existe no estagio "claim") - simula os dois certinho
    const papelFallback = claim.stage === 'dispute' ? 'mediator' : 'complainant';
    const acaoFallback = claim.stage === 'dispute' ? 'send_message_to_mediator' : 'send_message_to_complainant';
    const temFallbackMensagem = acoes.includes(acaoFallback) || acoes.includes('send_message_to_complainant') || acoes.includes('send_message_to_mediator');
    // texto do fallback (CORRIGIDO 26/08, 2a vez): sempre "sem devolucao" - o fallback so' e' usado
    // quando o Mercado Livre NAO ofereceu formalmente allow_return/allow_return_label, entao nao
    // faz sentido a mensagem prometer devolucao (ver comentario em processarReclamacaoAutomatico)
    const textoFallbackSimulado = 'reembolso 100% sem devolucao';
    // mesmos 2 sinais de "ja em andamento/ja respondida" usados de verdade em tentarFallbackMensagem
    // (21/08) - so' verifica se cair no caso sem acao nenhuma disponivel, pra nao gastar chamada a toa
    let jaEmAndamento = false, motivoAndamento = '', relatedEntities = null, mensagensClaim = null;
    if (!temFallbackMensagem) {
      relatedEntities = claim.related_entities || [];
      if (Array.isArray(relatedEntities) && relatedEntities.includes('return')) {
        jaEmAndamento = true; motivoAndamento = 'devolucao ja habilitada pelo Mercado Livre (related_entities: return)';
      }
      try {
        mensagensClaim = await fetchMLDebug(`https://api.mercadolibre.com/marketplace/v2/claims/${claimId}/messages`, { headers: { Authorization: `Bearer ${accessToken}` } });
        const lista = Array.isArray(mensagensClaim) ? mensagensClaim : (mensagensClaim.results || []);
        if (!jaEmAndamento && lista.some(m => m.sender_role === 'respondent')) {
          jaEmAndamento = true; motivoAndamento = 'ja existe mensagem do vendedor nessa reclamacao (respondida antes, inclusive pelo assistente do proprio Mercado Livre)';
        }
      } catch (e) { /* nao bloqueia a simulacao */ }
    }
    const fallbackTxt = temFallbackMensagem
      ? `cairia no fallback: mensagem pro ${papelFallback === 'mediator' ? 'mediador' : 'comprador'} "${textoFallbackSimulado}" (estagio: ${claim.stage || '?'})`
      : (jaEmAndamento ? `sem acao/mensagem disponivel, MAS ja em andamento (${motivoAndamento}) - contaria como resolvida, aguardando o comprador` : `fallback de mensagem tambem indisponivel (estagio: ${claim.stage || '?'}) - ficaria pendente de verdade`);
    const temAllowReturn = acoes.includes('allow_return') || acoes.includes('allow_return_label');
    if (claim.resource !== 'order') regraAplicavel = 'fora da regra (resource != order)';
    else if (valorVenda != null && valorVenda > 20) regraAplicavel = `fora da regra automática - venda de R$${valorVenda.toFixed(2).replace('.', ',')} acima de R$20, precisa revisão manual`;
    else if (temAllowReturn) regraAplicavel = 'devolucao (Mercado Livre ofereceu allow_return/allow_return_label)';
    else if (acoes.includes('refund')) regraAplicavel = 'reembolso 100% sem devolucao (acao refund disponivel)';
    else regraAplicavel = `nem allow_return nem refund disponiveis - ${fallbackTxt}`;
    res.json({ ok: true, loja, claimId, resource: claim.resource, reasonId: claim.reason_id, orderId: claim.resource_id, valorVenda, stage: claim.stage, orderErro, acoesDisponiveisVendedor: acoes, jaEmAndamento, motivoAndamento, mensagensClaim, regraAplicavel, claim });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo }); }
});
/* processa de verdade (EXECUTA a acao automatica) todas as reclamacoes abertas da loja - roda
   sozinho dentro do /sync (ver bloco 2 das instrucoes), mas tambem pode ser chamado na mao pra
   testar antes de confiar 100%. Ex.: POST /reclamacoes/processar?loja=TorvStore */
app.post('/reclamacoes/processar', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const r = await processarReclamacoesDaLoja(loja);
    res.json({ ok: true, loja, ...r });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo }); }
});
/* relatorio pro Doca mostrar o que foi feito automaticamente (card em Visao Geral) - devolve as
   reclamacoes processadas nos ultimos "dias" (default 14), resolvidas ou pendentes de revisao
   manual. Ex.: /reclamacoes/relatorio?loja=TorvStore&dias=14 */
app.get('/reclamacoes/relatorio', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    /* Felipe (21/08) pediu: pendente de verdade (sucesso=false) continua aparecendo sempre, nao
       importa ha quanto tempo foi registrada - precisa mesmo de revisao manual, some sozinha so'
       quando o processo de limpeza (ver processarReclamacoesDaLoja) confirma que ja fechou no ML.
       Ja' as RESOLVIDAS (sucesso=true) - que so' aparecem no resumo, ja' nem entram na lista
       detalhada (ver comentario no doca.html) - se acumulavam pra sempre no contador "resolvida
       sozinha", ficando com um numero cada vez mais velho/menos util. Agora so' conta as resolvidas
       nas ultimas 24h, pra refletir "o que o Doca resolveu hoje", nao o historico todo. */
    const r = await pool.query(
      `select claim_id, order_id, reason_id, frete_vendedor, valor_frete_vendedor, acao_tomada, sucesso, motivo, tentativas, criado_em, atualizado_em
       from ml_reclamacoes_log where loja = $1 and (sucesso = false or atualizado_em > now() - interval '24 hours')
       order by atualizado_em desc`,
      [loja]
    );
    res.json({ ok: true, loja, total: r.rows.length, pendentes: r.rows.filter(x => !x.sucesso).length, resolvidas: r.rows.filter(x => x.sucesso).length, itens: r.rows });
  } catch (e) { res.status(500).json({ ok: false, erro: e.message }); }
});
/* rota de diagnostico temporaria - devolve a lista CRUA de pedidos que a API do ML retorna
   pro item/periodo pedido, pra comparar pedido por pedido com o que a propria tela de
   "Vendas" do vendedor no ML mostra (em vez de so comparar contagens agregadas). Ex.:
   /debug/pedidos?loja=TorvShop&itemId=MLB7174620602&dias=7
   Tambem aceita de/ate (ISO) direto: /debug/pedidos?loja=TorvShop&de=...&ate=...
   IMPORTANTE: quando "dias" e' usado (sem de/ate explicito), a janela agora e' EXATAMENTE
   a mesma que o /sync usa de verdade (dias civis fechados, terminando na meia-noite de hoje
   fuso America/Sao_Paulo) - antes essa rota usava uma janela corrida "agora - N*24h" diferente
   da que buscarVendasPorItem() calcula, o que fazia a auditoria comparar coisas diferentes
   sem perceber. Agora as duas usam a mesma funcao inicioDoDiaBR(). */
app.get('/debug/pedidos', async (req, res) => {
  try {
    const loja = req.query.loja;
    const itemId = req.query.itemId || null;
    let de, ate;
    if (req.query.de && req.query.ate) {
      de = new Date(req.query.de).toISOString();
      ate = new Date(req.query.ate).toISOString();
    } else {
      const dias = parseInt(req.query.dias || '7', 10);
      const fim = inicioDoDiaBR(Date.now());
      de = new Date(fim - dias * 864e5).toISOString();
      ate = new Date(fim).toISOString();
    }
    if (!LOJAS_VALIDAS.includes(loja)) {
      return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    }
    const accessToken = await tokenValido(loja);
    const conta = await pegarConta(loja);
    const log = { avisos: [] };
    const pedidos = await buscarPedidosNoIntervalo(accessToken, conta.ml_user_id, de, ate, log, 'order.date_closed');
    const filtrados = itemId
      ? pedidos.filter(p => (p.order_items || []).some(oi => oi.item && oi.item.id === itemId))
      : pedidos;
    const resumo = filtrados.map(p => ({
      id: p.id,
      status: p.status,
      status_detail: p.status_detail || null,
      date_created: p.date_created,
      date_closed: p.date_closed,
      date_last_updated: p.date_last_updated || null,
      pack_id: p.pack_id || null,
      tags: p.tags || [],
      itens: (p.order_items || []).map(oi => ({ item_id: oi.item && oi.item.id, qtd: oi.quantity, titulo: oi.item && oi.item.title }))
    })).sort((a, b) => (a.date_closed || '').localeCompare(b.date_closed || ''));
    res.json({
      ok: true, loja, itemId, janela: { de, ate },
      total_pedidos_no_periodo_todos_itens: pedidos.length,
      total_pedidos_filtrados: resumo.length,
      ids: resumo.map(p => p.id),
      avisos: log.avisos,
      pedidos: resumo
    });
  } catch (e) {
    res.status(500).json({ ok: false, erro: e.message });
  }
});
/* rota de diagnostico - acha pedidos PARCELADOS (payments[].installments > 1) num periodo e
   devolve o array de "payments" completo de cada um, sem cortar nada. Objetivo: descobrir em qual
   campo o Mercado Livre expoe a taxa de financiamento/parcelamento que o vendedor absorve - a
   "Tarifa" calculada pelo Doca hoje so' soma sale_fee (comissao de venda) de cada item, e bate
   ~13% abaixo do painel deles numa loja com bastante venda parcelada - a suspeita e' que essa
   taxa de parcelamento fica em outro campo, ligado ao PAGAMENTO, nao ao item. Ex.:
   /debug/parcelamento?loja=TorvStore&de=2026-08-01&ate=2026-08-14&limite=5 */
app.get('/debug/parcelamento', async (req, res) => {
  try {
    const loja = req.query.loja;
    const de = req.query.de, ate = req.query.ate;
    const limite = parseInt(req.query.limite || '5', 10);
    if (!LOJAS_VALIDAS.includes(loja)) {
      return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    }
    if (!de || !ate) return res.status(400).json({ ok: false, erro: 'Parametros "de" e "ate" obrigatorios (AAAA-MM-DD).' });
    const accessToken = await tokenValido(loja);
    const conta = await pegarConta(loja);
    const log = { avisos: [] };
    const deIso = `${de}T00:00:00-03:00`, ateIso = `${ate}T23:59:59-03:00`;
    const pedidos = await buscarPedidosNoIntervalo(accessToken, conta.ml_user_id, deIso, ateIso, log, 'order.date_closed');
    const parcelados = pedidos.filter(p => (p.payments || []).some(pg => (pg.installments || 1) > 1));
    const achados = parcelados.slice(0, limite).map(p => ({
      pedido_id: p.id,
      status: p.status,
      total_amount: p.total_amount,
      payments: p.payments
    }));
    res.json({
      ok: true, loja, periodo: { de, ate },
      total_pedidos_no_periodo: pedidos.length,
      total_pedidos_parcelados: parcelados.length,
      mostrando: achados.length,
      pedidos_parcelados: achados,
      avisos: log.avisos
    });
  } catch (e) {
    res.status(500).json({ ok: false, erro: e.message });
  }
});
/* rota de diagnostico - o /debug/parcelamento (acima) mostrou que o "payments" que vem
   DENTRO do pedido do Mercado Livre e' uma versao resumida (so' tem installments,
   transaction_amount, total_paid_amount etc) - NAO tem o detalhamento de taxas. A taxa de
   financiamento/parcelamento que o vendedor absorve, quando existe, fica no objeto de
   pagamento COMPLETO do Mercado Pago (campo "fee_details", um array com {type, amount} -
   tipos possiveis incluem "mercadopago_fee" e "financing_fee"). Essa rota busca esse objeto
   completo direto na API do Mercado Pago (GET /v1/payments/{id}), usando o mesmo token
   MP_ACCESS_TOKEN_<LOJA> que ja' e' usado pros relatorios financeiros. Ex.:
   /debug/pagamento-mp?loja=TorvStore&id=170621591243 */
app.get('/debug/pagamento-mp', async (req, res) => {
  try {
    const loja = req.query.loja;
    const id = req.query.id;
    if (!LOJAS_VALIDAS.includes(loja)) {
      return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    }
    if (!id) return res.status(400).json({ ok: false, erro: 'Parametro "id" obrigatorio (id do pagamento, campo "id" dentro de payments[] do /debug/parcelamento).' });
    if (!tokenMpDaLoja(loja)) {
      return res.status(400).json({ ok: false, erro: `Faltou a variavel de ambiente MP_ACCESS_TOKEN_${normalizarChaveLoja(loja)} (ou MP_ACCESS_TOKEN) no Render.` });
    }
    const r = await mpFetch(loja, `/v1/payments/${encodeURIComponent(id)}`, { method: 'GET' });
    const j = await r.json();
    res.status(200).json({
      ok: r.ok, http_status: r.status,
      transaction_amount: j.transaction_amount,
      installments: j.installments,
      total_paid_amount: j.transaction_details && j.transaction_details.total_paid_amount,
      fee_details: j.fee_details || null,
      charges_details: j.charges_details || null,
      pagamento_completo: j
    });
  } catch (e) {
    res.status(500).json({ ok: false, erro: e.message });
  }
});
/* rota de diagnostico - suspeita: pra produto enviado por FULL (fulfillment), o custo de
   /shipments/{id}/costs (o que o Doca usa hoje pro Frete ML) pode NAO incluir a taxa de
   separacao/armazenagem do FULL - essa taxa aparece nos charges_details do PAGAMENTO como um
   item separado tipo "shp_fulfillment" (visto num pagamento de teste, R$ 6,55, com metadata
   source:"shipping-account-movements"), debitada direto da conta, fora do fluxo normal de
   frete do pedido. Essa rota pega pedidos de um produto (filtra pelo TITULO, sem precisar do
   item_id de cor) num periodo e mostra, pedido por pedido: o custo de frete pelo metodo atual
   (/shipments/{id}/costs) ao lado de TODAS as cobrancas reais que saíram da conta do vendedor
   nesse pagamento (charges_details onde accounts.from==="collector"), pra achar visualmente se
   sobra alguma cobranca de frete/fulfillment que hoje NAO entra no calculo. Ex.:
   /debug/frete-fulfillment?loja=TorvStore&titulo=substrato&de=2026-07-01&ate=2026-07-31&limite=5 */
app.get('/debug/frete-fulfillment', async (req, res) => {
  try {
    const loja = req.query.loja;
    const titulo = (req.query.titulo || '').toLowerCase();
    const de = req.query.de, ate = req.query.ate;
    const limite = parseInt(req.query.limite || '5', 10);
    if (!LOJAS_VALIDAS.includes(loja)) {
      return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    }
    if (!titulo) return res.status(400).json({ ok: false, erro: 'Parametro "titulo" obrigatorio (trecho do titulo do anuncio, ex: "substrato").' });
    if (!de || !ate) return res.status(400).json({ ok: false, erro: 'Parametros "de" e "ate" obrigatorios (AAAA-MM-DD).' });
    const accessToken = await tokenValido(loja);
    const conta = await pegarConta(loja);
    const log = { avisos: [] };
    const deIso = `${de}T00:00:00-03:00`, ateIso = `${ate}T23:59:59-03:00`;
    const pedidos = await buscarPedidosNoIntervalo(accessToken, conta.ml_user_id, deIso, ateIso, log, 'order.date_closed');
    const combinam = pedidos.filter(p => (p.order_items || []).some(oi => oi.item && (oi.item.title || '').toLowerCase().includes(titulo)));
    const amostra = combinam.slice(0, limite);
    const resultado = [];
    for (const p of amostra) {
      const item = { shipment_costs: null, pagamento: null };
      if (p.shipping && p.shipping.id) {
        try {
          const j = await fetchMLDebug(`https://api.mercadolibre.com/shipments/${p.shipping.id}/costs`, { headers: { Authorization: `Bearer ${accessToken}` } });
          const senders = j.senders || [];
          item.shipment_costs = { shipping_id: p.shipping.id, total_senders: senders.reduce((s, r) => s + (Number(r.cost) || 0), 0), raw: j };
        } catch (e) { item.shipment_costs = { erro: e.message }; }
      }
      const pgAprovado = (p.payments || []).find(pg => pg.status === 'approved') || (p.payments || [])[0];
      if (pgAprovado && pgAprovado.id && tokenMpDaLoja(loja)) {
        try {
          const r = await mpFetch(loja, `/v1/payments/${pgAprovado.id}`, { method: 'GET' });
          const jp = await r.json();
          const cobrancasDoVendedor = (jp.charges_details || []).filter(c => c.accounts && c.accounts.from === 'collector');
          item.pagamento = {
            payment_id: pgAprovado.id,
            total_cobrado_do_vendedor: cobrancasDoVendedor.reduce((s, c) => s + ((c.amounts && Number(c.amounts.original)) || 0), 0),
            cobrancas: cobrancasDoVendedor.map(c => ({ nome: c.name, tipo: c.type, valor: c.amounts && c.amounts.original, destino: c.accounts.to, detalhe: c.metadata && c.metadata.source_detail }))
          };
        } catch (e) { item.pagamento = { erro: e.message }; }
      }
      resultado.push({
        pedido_id: p.id, status: p.status, total_amount: p.total_amount,
        itens: (p.order_items || []).map(oi => ({ item_id: oi.item && oi.item.id, titulo: oi.item && oi.item.title, sale_fee: oi.sale_fee })),
        ...item
      });
    }
    res.json({
      ok: true, loja, titulo, periodo: { de, ate },
      total_pedidos_no_periodo: pedidos.length,
      total_combinando_titulo: combinam.length,
      mostrando: resultado.length,
      pedidos: resultado,
      avisos: log.avisos
    });
  } catch (e) {
    res.status(500).json({ ok: false, erro: e.message });
  }
});
/* rota de diagnostico v78c - compara, pedido a pedido, 3 formas diferentes de saber a comissao:
   1) sale_fee DECLARADO no pedido (o que ja vinha em order_items, hoje usado so' de fallback)
   2) tarifa CALCULADA pela % de comissao da categoria (metodo atual, v70) aplicada sobre o valor
      daquele pedido especifico
   3) cobranca REAL no pagamento (via Mercado Pago, charges_details filtrado por accounts.from
      === 'collector' - mesmo caminho ja usado e validado em /debug/frete-fulfillment)
   Objetivo: descobrir se o gap de ~2% visto no agregado (R$572,65 calculado vs R$561,76 de outra
   ferramenta) vem do metodo 2 usar o PRECO ATUAL do anuncio pra achar a % (em vez do preco de cada
   venda historica), ou de outra causa.
   Ex.: /debug/tarifa/comparar?loja=TorvStore&titulo=afiador&de=2026-07-01&ate=2026-07-31&limite=15 */
app.get('/debug/tarifa/comparar', async (req, res) => {
  try {
    const loja = req.query.loja;
    const titulo = (req.query.titulo || '').toLowerCase();
    const de = req.query.de, ate = req.query.ate;
    const limite = parseInt(req.query.limite || '15', 10);
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!titulo) return res.status(400).json({ ok: false, erro: 'Parametro "titulo" obrigatorio (trecho do titulo do anuncio, ex: "afiador").' });
    if (!de || !ate) return res.status(400).json({ ok: false, erro: 'Parametros "de" e "ate" obrigatorios (AAAA-MM-DD).' });
    const accessToken = await tokenValido(loja);
    const conta = await pegarConta(loja);
    const log = { avisos: [] };
    const deIso = `${de}T00:00:00-03:00`, ateIso = `${ate}T23:59:59-03:00`;
    const pedidos = await buscarPedidosNoIntervalo(accessToken, conta.ml_user_id, deIso, ateIso, log, 'order.date_closed');
    const combinam = pedidos.filter(p => p.status !== 'cancelled' && p.status !== 'invalid' && (p.order_items || []).some(oi => oi.item && (oi.item.title || '').toLowerCase().includes(titulo)));
    const amostra = combinam.slice(0, limite);
    const idsUnicos = [...new Set(amostra.flatMap(p => (p.order_items || []).filter(oi => oi.item && (oi.item.title || '').toLowerCase().includes(titulo)).map(oi => oi.item.id)))];
    const percentualPorItem = {};
    for (const itemId of idsUnicos) {
      try {
        const r = await fetch(`https://api.mercadolibre.com/items/${itemId}?attributes=id,price,category_id,listing_type_id,site_id`, { headers: { Authorization: `Bearer ${accessToken}` } });
        const item = await r.json();
        const url = `https://api.mercadolibre.com/sites/${item.site_id || 'MLB'}/listing_prices?price=${item.price}&category_id=${item.category_id}&listing_type_id=${item.listing_type_id}`;
        const j2 = await fetchMLDebug(url, { headers: { Authorization: `Bearer ${accessToken}` } });
        percentualPorItem[itemId] = {
          percentual: j2.sale_fee_details && typeof j2.sale_fee_details.percentage_fee === 'number' ? j2.sale_fee_details.percentage_fee : null,
          preco_atual_usado: item.price, category_id: item.category_id, listing_type_id: item.listing_type_id
        };
      } catch (e) { percentualPorItem[itemId] = { erro: e.message }; }
    }
    const resultado = [];
    for (const p of amostra) {
      const pgAprovado = (p.payments || []).find(pg => pg.status === 'approved') || (p.payments || [])[0];
      let cobrancasReais = null;
      if (pgAprovado && pgAprovado.id && tokenMpDaLoja(loja)) {
        try {
          const r = await mpFetch(loja, `/v1/payments/${pgAprovado.id}`, { method: 'GET' });
          const jp = await r.json();
          const cobrancasDoVendedor = (jp.charges_details || []).filter(c => c.accounts && c.accounts.from === 'collector');
          cobrancasReais = cobrancasDoVendedor.map(c => ({ nome: c.name, tipo: c.type, valor: c.amounts && c.amounts.original, destino: c.accounts.to, detalhe: c.metadata && c.metadata.source_detail }));
        } catch (e) { cobrancasReais = { erro: e.message }; }
      }
      for (const oi of (p.order_items || [])) {
        if (!oi.item || !(oi.item.title || '').toLowerCase().includes(titulo)) continue;
        const itemId = oi.item.id;
        const valorItem = (Number(oi.unit_price) || 0) * (oi.quantity || 0);
        const infoPercentual = percentualPorItem[itemId] || {};
        const tarifaCalculada = infoPercentual.percentual != null ? Math.round(valorItem * (infoPercentual.percentual / 100) * 100) / 100 : null;
        resultado.push({
          pedido_id: p.id, item_id: itemId, quantidade: oi.quantity,
          preco_de_venda_desse_pedido: oi.unit_price, valor_total_desse_item: valorItem,
          sale_fee_declarado_no_pedido: oi.sale_fee,
          percentual_categoria_hoje: infoPercentual.percentual, preco_atual_do_anuncio: infoPercentual.preco_atual_usado,
          tarifa_calculada_pela_percentual: tarifaCalculada,
          cobrancas_reais_no_pagamento_mp: cobrancasReais
        });
      }
    }
    res.json({
      ok: true, loja, titulo, periodo: { de, ate },
      total_pedidos_no_periodo: pedidos.length,
      total_combinando_titulo: combinam.length,
      mostrando: resultado.length,
      itens: resultado,
      avisos: log.avisos
    });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo }); }
});
/* ================= Auditoria financeira mensal (v81 - cobre TODOS os pedidos) =================
   Motivo original: o calculo do dia-a-dia (/financas/resumo) SEMPRE conta a tarifa (sale_fee) de
   um pedido CANCELADO, baseado na suposicao de que "o Mercado Livre normalmente nao devolve a
   comissao de um cancelamento". A v80 conferia SO os cancelados e achou uma diferenca pequena
   (ex.: R$13,70 numa loja em julho/2026) - muito menor que o gap de ~5% visto contra o painel do
   Mercado Livre e o Metrify. Ou seja, cancelamento NAO e' a causa principal do gap.
   v81: audita TODOS os pedidos do periodo (validos + cancelados, pedido por pedido, sem amostragem)
   contra a cobranca REAL no Mercado Pago (charges_details - mesmo caminho ja validado em
   /debug/tarifa/comparar e /debug/frete-fulfillment), pra achar o gap de verdade em qualquer
   pedido, nao so' nos cancelados. Tambem confere, pra pedido valido ja antigo, se o dinheiro
   (money_release_status) ja foi liberado pro vendedor - pra pegar o caso "vendeu e foi cobrado mas
   nao foi repassado" que o usuario pediu especificamente.
   E' 1 chamada extra ao Mercado Pago por pedido do periodo inteiro (nao so' cancelado) - rodar isso
   pra um mes inteiro com milhares de pedidos pode levar VARIOS minutos. Por isso roda em
   BACKGROUND (job assincrono) em vez de dentro do /financas/resumo normal, que precisa ser rapido
   pra abrir a tela toda vez. O resultado NAO e' aplicado automaticamente no calculo do dia a dia
   (esse continua rapido e aproximado) - e' uma conferencia sob demanda pro fechamento do mes, com
   os MESMOS rotulos (Faturamento/Tarifas/Frete/Cancelamentos) do Resumo Financeiro, so' que com
   valores confirmados pedido a pedido em vez de assumidos.
   Uso:
   1) POST /auditoria/mes/iniciar?loja=X&de=Y&ate=Z  -> devolve {jobId} na hora, começa a rodar
   2) GET  /auditoria/mes/status?id=JOBID            -> {status:'rodando'|'concluido'|'erro', progresso, resultado}
   Os jobs em memoria (auditoriaJobs) somem se o servidor reiniciar/dormir - normal no Render free
   tier apos inatividade - mas isso so' afeta uma auditoria RODANDO NA HORA: assim que termina, o
   resultado e' salvo na tabela auditoria_resultados (loja+periodo exato), entao reabrir o Doca
   depois nao precisa rodar de novo - ver GET /auditoria/mes/salvo. */
const auditoriaJobs = new Map(); // jobId -> {status, progresso:{feito,total}, resultado, erro, criadoEm}
function gerarJobId() { return 'aud_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8); }
const round2 = (n) => Math.round((Number(n) || 0) * 100) / 100;
const DIAS_LIMITE_REPASSE = 35; // depois disso, esperamos o dinheiro ja liberado pro vendedor
async function rodarAuditoriaMes(jobId, loja, de, ate) {
  const job = auditoriaJobs.get(jobId);
  try {
    if (!tokenMpDaLoja(loja)) { job.status = 'erro'; job.erro = 'Essa loja nao tem Mercado Pago configurado - a auditoria precisa dele pra confirmar as cobrancas reais.'; return; }
    const accessToken = await tokenValido(loja);
    const conta = await pegarConta(loja);
    const log = { avisos: [] };
    const deIso = `${de}T00:00:00-03:00`, ateIso = `${ate}T23:59:59-03:00`;
    const pedidos = await buscarPedidosNoIntervalo(accessToken, conta.ml_user_id, deIso, ateIso, log, 'order.date_closed');
    const cancelados = pedidos.filter(p => p.status === 'cancelled');
    const validos = pedidos.filter(p => p.status !== 'cancelled' && p.status !== 'invalid');
    const auditaveis = pedidos.filter(p => p.status !== 'invalid'); // tudo que entra no fechamento
    job.progresso = { feito: 0, total: auditaveis.length };
    let faturamento = 0, cancelamentosValor = 0;
    let tarifaAssumida = 0, tarifaReal = 0, freteReal = 0;
    let pedidosPendentesRepasse = 0, valorPendenteRepasse = 0;
    let repasseEsperadoTotal = 0, repasseLiberadoTotal = 0;
    let pedidosRepasseDivergente = 0, valorRepasseDivergente = 0;
    const anomalias = [];
    const agora = Date.now();
    const pagamentosContados = new Set();
    let pedidosMesmoCarrinho = 0;
    for (const p of auditaveis) {
      const cancelado = p.status === 'cancelled';
      const totalPedido = Number(p.total_amount) || 0;
      if (cancelado) cancelamentosValor += totalPedido; else faturamento += totalPedido;
      let saleFeeDoPedido = 0;
      for (const oi of (p.order_items || [])) saleFeeDoPedido += (Number(oi.sale_fee) || 0) * (oi.quantity || 1);
      tarifaAssumida += saleFeeDoPedido;
      const pgAprovado = (p.payments || []).find(pg => pg.status === 'approved' || pg.status === 'refunded' || pg.status === 'partially_refunded') || (p.payments || [])[0];
      if (!pgAprovado || !pgAprovado.id) {
        anomalias.push({ pedido_id: p.id, motivo: 'Sem pagamento associado pra conferir', total: totalPedido });
        job.progresso.feito++;
        continue;
      }
      if (pagamentosContados.has(pgAprovado.id)) {
        pedidosMesmoCarrinho++;
        job.progresso.feito++;
        continue;
      }
      pagamentosContados.add(pgAprovado.id);
      try {
        const r = await mpFetch(loja, `/v1/payments/${pgAprovado.id}`, { method: 'GET' });
        const jp = await r.json();
        /* CHECK 1 - "cobrou certo": tarifa e frete, os dois direto do charges_details do pagamento
           (a cobranca real que saiu da conta, nao uma estimativa) - pedido do Felipe 23/08: antes
           o frete vinha de uma API separada (/shipments/{id}/costs, so' uma referencia) em vez da
           cobranca de verdade; agora os dois usam a MESMA fonte e o mesmo padrao de confianca. */
        const cobrancas = (jp.charges_details || []).filter(c => c.accounts && c.accounts.from === 'collector');
        const temComissaoReal = cobrancas.some(c => c.name === 'ml_sale_fee' || c.name === 'mp_processing_fee');
        const valorComissaoReal = cobrancas.filter(c => c.name === 'ml_sale_fee' || c.name === 'mp_processing_fee').reduce((s, c) => s + ((c.amounts && c.amounts.original) || 0), 0);
        /* frete BRUTO cobrado (shp_fulfillment) inclui as duas pernas do envio - a sua e a que o
           COMPRADOR pagou a mais (jp.shipping_amount, quando o frete e' caro pro destino e o ML
           repassa parte pro comprador). Pedido do Felipe 23/08: um pedido real teve shp_fulfillment
           de R$20,94 sendo que so' R$6,95 era seu (R$13,99 era do comprador, embutido no
           total_paid_amount) - contar o bruto inteiro como "frete pago pelo vendedor" superestima.
           Desconta a parte do comprador pra sobrar so' a sua. */
        const valorFreteReal = Math.max(0, cobrancas.filter(c => c.type === 'shipping').reduce((s, c) => s + ((c.amounts && c.amounts.original) || 0), 0) - (Number(jp.shipping_amount) || 0));
        tarifaReal += valorComissaoReal;
        freteReal += valorFreteReal;
        if (cancelado && !temComissaoReal && saleFeeDoPedido > 0.009) {
          anomalias.push({ pedido_id: p.id, motivo: 'Pedido cancelado: comissao NAO foi cobrada de verdade (devolvida) - o calculo do dia a dia estava contando indevidamente', total: totalPedido, sale_fee_assumido: round2(saleFeeDoPedido) });
        } else if (!cancelado && Math.abs(valorComissaoReal - saleFeeDoPedido) > 1) {
          anomalias.push({ pedido_id: p.id, motivo: 'Comissao cobrada de verdade veio diferente do sale_fee declarado no pedido (diferenca > R$1 - pode ser cupom, financiamento etc)', total: totalPedido, sale_fee_assumido: round2(saleFeeDoPedido), sale_fee_real: round2(valorComissaoReal) });
        }
        /* CHECK 2 - "repassou certo": pega TODAS as cobrancas reais (nao so' tarifa/frete - inclui
           cupom, financiamento etc se tiver) e confere se o que sobrou bate com o que o Mercado
           Pago diz que efetivamente recebeu (net_received_amount) e se ja foi liberado - pedido do
           Felipe 23/08: "o que precisa auditar e' se repassou certo". So' roda pra pedido nao
           cancelado (cancelado nao tem repasse de venda esperado).
           CUIDADO (2 bugs achados em producao 23/08, ambos com o mesmo sintoma - repasseEsperado
           sistematicamente errado em subconjuntos de pedidos):
           1) pagamento parcelado: o Mercado Pago lanca financing_transfer (from:"payer",
              to:"collector" - ENTRADA extra, o valor do parcelamento) + financing_fee (a taxa que
              sai em cima). So' contar SAIDAS (from==='collector') ignorava essa entrada.
           2) frete pago pelo COMPRADOR (alem do preco do produto): esse valor nao aparece em
              charges_details nenhum - e' um campo separado do pagamento (jp.shipping_amount),
              incluido no jp.total_paid_amount mas NAO no jp.transaction_amount. Usar
              transaction_amount como base deixava de fora esse dinheiro que tambem entra pro
              vendedor.
           A base certa e' jp.total_paid_amount - ja inclui produto + financiamento do comprador +
           frete do comprador, tudo que efetivamente circula nesse pagamento antes das cobrancas
           reais saırem. Testado contra 2 pedidos reais (1 parcelado, 1 com frete do comprador) e
           bateu exato nos dois - dispensa somar entradas separadamente (senao duplica). */
        if (!cancelado) {
          const saidasReais = cobrancas.reduce((s, c) => s + ((c.amounts && Number(c.amounts.original)) || 0), 0);
          const baseTransacao = Number(jp.total_paid_amount) || Number(jp.transaction_amount) || totalPedido;
          const repasseEsperado = baseTransacao - saidasReais;
          const repasseReal = (jp.transaction_details && Number(jp.transaction_details.net_received_amount)) || 0;
          repasseEsperadoTotal += repasseEsperado;
          const statusRepasse = jp.money_release_status;
          const liberado = statusRepasse === 'released';
          if (liberado) {
            repasseLiberadoTotal += repasseReal;
            if (Math.abs(repasseReal - repasseEsperado) > 1) {
              pedidosRepasseDivergente++; valorRepasseDivergente += Math.abs(repasseReal - repasseEsperado);
              anomalias.push({ pedido_id: p.id, motivo: 'Repasse liberado veio diferente do esperado (total menos as cobrancas reais) - diferenca > R$1', total: totalPedido, repasse_esperado: round2(repasseEsperado), repasse_real: round2(repasseReal) });
            }
          } else {
            const dataAprovacao = pgAprovado.date_approved ? new Date(pgAprovado.date_approved).getTime() : null;
            const diasDesde = dataAprovacao ? (agora - dataAprovacao) / 86400000 : null;
            if (diasDesde != null && diasDesde > DIAS_LIMITE_REPASSE) {
              pedidosPendentesRepasse++; valorPendenteRepasse += repasseEsperado;
              anomalias.push({ pedido_id: p.id, motivo: `Vendeu e foi cobrado ha ${Math.round(diasDesde)} dias mas o dinheiro AINDA NAO foi liberado pro vendedor (status: ${statusRepasse})`, total: totalPedido, repasse_esperado: round2(repasseEsperado) });
            }
          }
        }
      } catch (e) {
        anomalias.push({ pedido_id: p.id, motivo: 'Erro ao consultar o pagamento: ' + e.message, total: totalPedido });
      }
      job.progresso.feito++;
      await sleep(180); // pausa entre chamadas ao Mercado Pago pra nao estourar limite
    }
    job.resultado = {
      loja, periodo: { de, ate },
      pedidos_no_periodo: pedidos.length, pedidos_validos: validos.length, pedidos_cancelados: cancelados.length,
      pedidos_mesmo_carrinho: pedidosMesmoCarrinho,
      faturamento: round2(faturamento),
      cancelamentos: round2(cancelamentosValor),
      tarifa_assumida: round2(tarifaAssumida),
      tarifa_real: round2(tarifaReal),
      diferenca_tarifa: round2(tarifaAssumida - tarifaReal),
      frete_real: round2(freteReal),
      repasse_esperado: round2(repasseEsperadoTotal),
      repasse_liberado: round2(repasseLiberadoTotal),
      pedidos_repasse_divergente: pedidosRepasseDivergente,
      valor_repasse_divergente: round2(valorRepasseDivergente),
      pedidos_pendentes_repasse: pedidosPendentesRepasse,
      valor_pendente_repasse: round2(valorPendenteRepasse),
      anomalias,
      avisos: log.avisos
    };
    job.status = 'concluido';
    try { await salvarAuditoriaResultado(loja, de, ate, job.resultado); }
    catch (e) { console.error('[auditoria] falha ao salvar resultado no banco:', e.message); }
  } catch (e) {
    job.status = 'erro';
    job.erro = e.message;
  }
}
/* guarda o resultado no banco por loja+periodo exato (pedido do Felipe 23/08: a auditoria demora
   varios minutos entao ele nao quer ter que rodar de novo toda vez que reabre o Doca) - sobrescreve
   se rodar de novo o MESMO periodo. O job em memoria (auditoriaJobs) continua existindo só pra
   acompanhar o progresso ENQUANTO roda; depois de concluido, quem "vale" é essa tabela. */
async function salvarAuditoriaResultado(loja, de, ate, resultado) {
  await pool.query(
    `insert into auditoria_resultados (loja, de, ate, resultado, criado_em)
     values ($1,$2,$3,$4,now())
     on conflict (loja, de, ate) do update set resultado = excluded.resultado, criado_em = excluded.criado_em`,
    [loja, de, ate, JSON.stringify(resultado)]
  );
}
app.get('/auditoria/mes/salvo', async (req, res) => {
  try {
    const loja = req.query.loja, de = req.query.de, ate = req.query.ate;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!de || !ate) return res.status(400).json({ ok: false, erro: 'Parametros "de" e "ate" obrigatorios (AAAA-MM-DD).' });
    const r = await pool.query('select resultado, criado_em from auditoria_resultados where loja = $1 and de = $2 and ate = $3', [loja, de, ate]);
    if (!r.rows.length) return res.json({ ok: true, encontrado: false });
    res.json({ ok: true, encontrado: true, resultado: r.rows[0].resultado, criadoEm: r.rows[0].criado_em });
  } catch (e) { res.status(500).json({ ok: false, erro: e.message }); }
});
app.post('/auditoria/mes/iniciar', async (req, res) => {
  try {
    const loja = req.query.loja;
    const de = req.query.de, ate = req.query.ate;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!de || !ate) return res.status(400).json({ ok: false, erro: 'Parametros "de" e "ate" obrigatorios (AAAA-MM-DD).' });
    const jobId = gerarJobId();
    auditoriaJobs.set(jobId, { status: 'rodando', progresso: { feito: 0, total: 0 }, resultado: null, erro: null, criadoEm: Date.now() });
    rodarAuditoriaMes(jobId, loja, de, ate); // roda em background, nao espera (fire-and-forget)
    res.json({ ok: true, jobId });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message }); }
});
app.get('/auditoria/mes/status', (req, res) => {
  const jobId = req.query.id;
  const job = auditoriaJobs.get(jobId);
  if (!job) return res.status(404).json({ ok: false, erro: 'Auditoria nao encontrada - pode ter expirado (o servidor guarda so a ultima leva de jobs em memoria, some se reiniciar).' });
  res.json({ ok: true, status: job.status, progresso: job.progresso, resultado: job.resultado, erro: job.erro });
});
/* ---- anexos de conciliacao (Relatorio de Conciliacao do Mercado Livre - "por venda" e "por
   liberacao de dinheiro", xlsx) - ver comentario da tabela auditoria_anexos la em cima. O
   parsing do xlsx e' feito no navegador (doca.html); aqui so' recebe o resumo ja pronto. */
app.post('/auditoria/anexo', async (req, res) => {
  try {
    const { loja, mes, tipo, nomeArquivo, resumo } = req.body || {};
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!/^\d{4}-\d{2}$/.test(mes || '')) return res.status(400).json({ ok: false, erro: 'Parametro "mes" invalido (use AAAA-MM).' });
    if (!['venda', 'liberacao'].includes(tipo)) return res.status(400).json({ ok: false, erro: 'Parametro "tipo" invalido (use venda ou liberacao).' });
    if (!resumo || typeof resumo !== 'object' || !resumo.linhasNoMes) return res.status(400).json({ ok: false, erro: 'O resumo do arquivo nao veio ou veio vazio - confira se o Doca conseguiu ler o arquivo.' });
    const r = await pool.query(
      `insert into auditoria_anexos (loja, mes, tipo, nome_arquivo, conteudo, resumo)
       values ($1,$2,$3,$4,null,$5) returning id, criado_em`,
      [loja, mes, tipo, nomeArquivo || null, resumo]
    );
    res.json({ ok: true, id: r.rows[0].id, criadoEm: r.rows[0].criado_em });
  } catch (e) {
    res.status(500).json({ ok: false, erro: e.message });
  }
});
app.get('/auditoria/anexo', async (req, res) => {
  try {
    const { loja, mes } = req.query;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!/^\d{4}-\d{2}$/.test(mes || '')) return res.status(400).json({ ok: false, erro: 'Parametro "mes" invalido (use AAAA-MM).' });
    const r = await pool.query(
      `select id, tipo, nome_arquivo, resumo, criado_em, (conteudo is not null) as tem_arquivo from auditoria_anexos
       where loja = $1 and mes = $2 order by criado_em desc`,
      [loja, mes]
    );
    res.json({ ok: true, anexos: r.rows });
  } catch (e) {
    res.status(500).json({ ok: false, erro: e.message });
  }
});
app.get('/auditoria/anexo/baixar', async (req, res) => {
  try {
    const id = req.query.id;
    if (!id) return res.status(400).json({ ok: false, erro: 'Parametro "id" obrigatorio.' });
    const r = await pool.query('select nome_arquivo, conteudo from auditoria_anexos where id = $1', [id]);
    if (!r.rows.length) return res.status(404).json({ ok: false, erro: 'Anexo nao encontrado.' });
    if (!r.rows[0].conteudo) return res.status(404).json({ ok: false, erro: 'Esse anexo so guardou o resumo, nao o arquivo original - baixe de novo direto no Mercado Livre (Vendas > Relatorios > Conciliacao).' });
    const nome = (r.rows[0].nome_arquivo || `anexo-${id}.csv`).replace(/"/g, '');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${nome}"`);
    res.send(r.rows[0].conteudo);
  } catch (e) {
    res.status(500).json({ ok: false, erro: e.message });
  }
});
app.delete('/auditoria/anexo', async (req, res) => {
  try {
    const id = req.query.id;
    if (!id) return res.status(400).json({ ok: false, erro: 'Parametro "id" obrigatorio.' });
    await pool.query('delete from auditoria_anexos where id = $1', [id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, erro: e.message });
  }
});
/* rota de diagnostico - busca UM pedido especifico direto na API (GET /orders/{id}), pra
   auditar pedido que aparece no painel "Vendas" do ML mas nao aparece no /orders/search.
   Ex.: /debug/pedido?loja=TorvShop&id=2000012345678901 */
app.get('/debug/pedido', async (req, res) => {
  try {
    const loja = req.query.loja;
    const id = req.query.id;
    if (!LOJAS_VALIDAS.includes(loja)) {
      return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    }
    if (!id) return res.status(400).json({ ok: false, erro: 'Parametro "id" obrigatorio (order_id).' });
    const accessToken = await tokenValido(loja);
    const r = await fetch(`https://api.mercadolibre.com/orders/${id}`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    const j = await r.json();
    res.status(r.status).json({ ok: r.ok, http_status: r.status, pedido: j });
  } catch (e) {
    res.status(500).json({ ok: false, erro: e.message });
  }
});
/* rota de auditoria - roda o MESMO calculo que o /sync usa de verdade (reusa processarVendas())
   restrito a 1 item, e devolve TODOS os pedidos encontrados pra esse item na janela de 30d, cada
   um marcado com contado:true/false e o motivo da exclusao quando nao contado. Ex.:
   /debug/vendas?loja=TorvShop&itemId=MLB7174620602 */
app.get('/debug/vendas', async (req, res) => {
  try {
    const loja = req.query.loja;
    const itemId = req.query.itemId;
    if (!LOJAS_VALIDAS.includes(loja)) {
      return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    }
    if (!itemId) return res.status(400).json({ ok: false, erro: 'Parametro "itemId" obrigatorio.' });
    const accessToken = await tokenValido(loja);
    const conta = await pegarConta(loja);
    const fim = inicioDoDiaBR(Date.now());
    const de = new Date(fim - 31 * 864e5).toISOString();
    const ate = new Date(fim).toISOString();
    const log = { avisos: [] };
    const pedidos = await buscarPedidosComPendentes(accessToken, conta.ml_user_id, de, ate, log);
    const { porItem, detalhe, janela } = processarVendas(pedidos, { itemIdFiltro: itemId });
    const totais = porItem.get(itemId) || { v7: 0, v15: 0, v30: 0 };
    const contados = detalhe.filter(d => d.contado);
    const excluidos = detalhe.filter(d => !d.contado);
    res.json({
      ok: true, loja, itemId, janela,
      vendas_calculadas: totais,
      pedidos_contados_30d: contados.length,
      unidades_contadas_30d: contados.reduce((s, d) => s + d.qtd, 0),
      pedidos_excluidos: excluidos.length,
      avisos: log.avisos,
      pedidos: detalhe.sort((a, b) => (a.date_closed || a.date_created || '').localeCompare(b.date_closed || b.date_created || ''))
    });
  } catch (e) {
    res.status(500).json({ ok: false, erro: e.message });
  }
});
/* ---- Mercado Pago: saldo / reconciliacao financeira (v16) ----
   Diferente do Mercado Livre, aqui NAO precisa de OAuth com redirect/callback: cada loja usa
   direto o Access Token de PRODUCAO da propria conta Mercado Pago, guardado como variavel de
   ambiente MP_ACCESS_TOKEN_<LOJA> (mesma normalizacao de nome que normalizarChaveLoja ja usa
   pro Mercado Livre - ver credenciaisDaLoja). */
function tokenMpDaLoja(loja) {
  const chave = normalizarChaveLoja(loja);
  return process.env[`MP_ACCESS_TOKEN_${chave}`] || process.env.MP_ACCESS_TOKEN || null;
}
/* rota de diagnostico - testa os candidatos mais prováveis de endpoint de saldo/conta e devolve
   a resposta CRUA de cada um. Ex.: /debug/mp?loja=TorvShop */
app.get('/debug/mp', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) {
      return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    }
    const token = tokenMpDaLoja(loja);
    if (!token) {
      return res.status(400).json({
        ok: false,
        erro: `Faltou a variavel de ambiente MP_ACCESS_TOKEN_${normalizarChaveLoja(loja)} (ou MP_ACCESS_TOKEN) no Render.`
      });
    }
    const candidatos = [
      { nome: 'account_balance_v1', url: 'https://api.mercadopago.com/v1/account/balance' },
      { nome: 'account_sem_v1', url: 'https://api.mercadopago.com/account/balance' },
      { nome: 'users_me', url: 'https://api.mercadopago.com/users/me' }
    ];
    const resultados = [];
    for (const c of candidatos) {
      try {
        const r = await fetch(c.url, { headers: { Authorization: `Bearer ${token}` } });
        let corpo;
        try { corpo = await r.json(); } catch (e) { corpo = { erro_ao_ler_json: e.message }; }
        resultados.push({ nome: c.nome, url: c.url, http_status: r.status, corpo });
      } catch (e) {
        resultados.push({ nome: c.nome, url: c.url, erro: e.message });
      }
    }
    res.json({ ok: true, loja, resultados });
  } catch (e) {
    res.status(500).json({ ok: false, erro: e.message });
  }
});
/* rota de diagnostico - pra CADA PRODUTO (nao pedido), consulta de uma vez (1) a comissao que a
   categoria dele cobra (API de precificacao do ML) e (2) o custo de frete gratis que o vendedor
   absorve (API de opcoes de frete gratis do proprio vendedor) - candidatos de endpoint mais leve
   que abrir pedido por pedido. Ex.: /debug/custo-estimado?loja=TorvStore&itemId=MLB6574356166 */
/* CUSTOS ATUAIS DO ANUNCIO (02/09, pedido do Felipe: "comissao e envio esta errado, deveria ser
   2,18 tarifa de venda e 6,85 custo de envio" - a meta de TACOS estava usando a MEDIA do que foi
   cobrado nas vendas do periodo, que sai um pouco diferente da condicao ATUAL do anuncio: no
   AFIADOR19 dava 2,28 e 7,15 no lugar de 2,18 e 6,85, comendo R$0,40 de margem por unidade).
   Aqui pega, direto do Mercado Livre e pra vários itens de uma vez, exatamente os dois numeros do
   simulador "Resumo de custos":
     - tarifa de venda -> /sites/{site}/listing_prices (sale_fee do preco/categoria/tipo atuais)
     - custo de envio  -> /users/{seller}/shipping_options/free (o que o vendedor paga de frete)
   Chamado pela aba Ads so' pros itens que ela mostra (poucos), nao pela sincronizacao inteira. */
app.get('/ml/custos-anuncio', exigirLogin, async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) {
      return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    }
    const ids = String(req.query.itemIds || '').split(',').map(s => s.trim()).filter(Boolean).slice(0, 60);
    if (!ids.length) return res.status(400).json({ ok: false, erro: 'Passe itemIds separados por virgula.' });
    const accessToken = await tokenValido(loja);
    const cab = { Authorization: `Bearer ${accessToken}` };
    /* POSICAO DE MAIS VENDIDO NA CATEGORIA (02/09, pedido do Felipe: "o musgo e' 1o mais vendido e
       o afiador 14o - da' pra puxar se tem tag de mais vendido na categoria?"). O Mercado Livre
       publica o ranking de destaques por categoria em /highlights/MLB/category/{id} - a posicao no
       array e' a colocacao. Busca 1x por categoria (varios anuncios costumam cair na mesma) e
       guarda aqui pra nao repetir a chamada dentro do mesmo pedido. */
    const rankingPorCategoria = {};
    async function posicaoNaCategoria(categoriaId, itemId) {
      if (!categoriaId || !itemId) return null;
      if (!(categoriaId in rankingPorCategoria)) {
        rankingPorCategoria[categoriaId] = null;
        try {
          const rH = await fetch(`https://api.mercadolibre.com/highlights/MLB/category/${encodeURIComponent(categoriaId)}`, { headers: cab });
          const jH = await rH.json();
          if (rH.ok && jH && Array.isArray(jH.content)) rankingPorCategoria[categoriaId] = jH.content;
        } catch (e) { /* sem ranking: segue sem posicao */ }
      }
      const lista = rankingPorCategoria[categoriaId];
      if (!Array.isArray(lista)) return null;
      const idx = lista.findIndex(x => x && (x.id === itemId || x.parent_id === itemId));
      return idx >= 0 ? { posicao: idx + 1, total: lista.length } : null;
    }
    const itens = [];
    for (const itemId of ids) {
      const linha = { itemId, preco: null, comissao: null, frete: null, posicaoCategoria: null, totalRanking: null, categoriaId: null, tagMaisVendido: false, erro: null };
      try {
        const rItem = await fetch(`https://api.mercadolibre.com/items/${itemId}`, { headers: cab });
        const j = await rItem.json();
        if (!rItem.ok || !j || !j.price) { linha.erro = 'item nao encontrado'; itens.push(linha); continue; }
        linha.preco = Number(j.price) || null;
        linha.categoriaId = j.category_id || null;
        /* alguns anuncios ja' vem marcados pelo proprio ML como candidatos a "Mais vendido" */
        linha.tagMaisVendido = Array.isArray(j.tags) && j.tags.some(t => String(t).indexOf('best_seller') >= 0);
        try {
          const pos = await posicaoNaCategoria(j.category_id, itemId);
          if (pos) { linha.posicaoCategoria = pos.posicao; linha.totalRanking = pos.total; }
        } catch (e) { /* sem posicao */ }
        try {
          const url = `https://api.mercadolibre.com/sites/${j.site_id || 'MLB'}/listing_prices?price=${j.price}&category_id=${j.category_id}&listing_type_id=${j.listing_type_id}`;
          const rC = await fetch(url, { headers: cab });
          const jc = await rC.json();
          /* CORRIGIDO 02/09 (Felipe: "envio puxou certo mas a comissao ainda esta errada" - veio
             R$4,37 no lugar de R$2,18, quase o dobro): quando a resposta e' uma LISTA, ela traz a
             tarifa de CADA tipo de anuncio (Classico, Premium...). Pegar o primeiro pegava o
             Premium (~23%) em vez do Classico (~11,5%), que e' o tipo real deste anuncio. Agora
             casa pelo listing_type_id do proprio anuncio. */
          const lista = Array.isArray(jc) ? jc : [jc];
          const escolhido = lista.find(x => x && x.listing_type_id === j.listing_type_id) || lista[0];
          if (escolhido && typeof escolhido.sale_fee_amount === 'number') linha.comissao = escolhido.sale_fee_amount;
          linha.tipoAnuncio = (escolhido && escolhido.listing_type_id) || j.listing_type_id || null;
          /* CORRIGIDO 02/09 (Felipe: "ainda esta mostrando a comissao errada" - vinha R$4,37, o
             DOBRO exato dos R$2,18 do simulador): a comissao em reais vem calculada sobre o preco
             que mandamos na consulta, e nesses anuncios o preco da API e' o do PACK (2 unidades),
             nao o de 1. Como a comissao e' percentual, o que serve pra qualquer preco e' a PARTE
             PERCENTUAL (mais a fixa, quando existe) - o Doca aplica isso no preco unitario. */
          const det = escolhido && escolhido.sale_fee_details;
          if (det) {
            if (typeof det.percentage_fee === 'number') linha.comissaoPercentual = det.percentage_fee;
            if (typeof det.fixed_fee === 'number') linha.comissaoFixa = det.fixed_fee;
          }
          if (linha.comissaoPercentual == null && typeof linha.comissao === 'number' && j.price > 0) {
            linha.comissaoPercentual = (linha.comissao / j.price) * 100;  /* deduz o percentual */
            linha.comissaoFixa = 0;
          }
          linha.precoConsultado = Number(j.price) || null;
        } catch (e) { /* sem comissao: o front cai na media real */ }
        try {
          const rF = await fetch(`https://api.mercadolibre.com/users/${j.seller_id}/shipping_options/free?item_id=${itemId}`, { headers: cab });
          const jf = await rF.json();
          const opcoes = (jf && (jf.coverage && jf.coverage.all_country ? [jf.coverage.all_country] : jf.options)) || [];
          const custos = opcoes.map(o => (o && (typeof o.list_cost === 'number' ? o.list_cost : o.cost))).filter(v => typeof v === 'number');
          if (custos.length) linha.frete = Math.max(...custos);
        } catch (e) { /* sem frete: o front cai na media real */ }
      } catch (e) { linha.erro = e.message; }
      itens.push(linha);
    }
    res.set('Cache-Control', 'no-store');
    res.json({ ok: true, loja, itens });
  } catch (e) {
    res.status(500).json({ ok: false, erro: e.message });
  }
});
/* RANKING DE MAIS VENDIDOS DA LOJA INTEIRA (02/09, pedido do Felipe: "tem como ir gravando o
   posicionamento de cada produto e fazer um card na Visao Geral dos que estao ganhando ou perdendo
   posicao e candidatos a mais vendido?").
   Diferente do /ml/custos-anuncio (que olha so' os anuncios da aba Ads e faz 1 chamada por item),
   aqui aproveita a categoria que a sincronizacao ja' gravou em ml_produtos: basta 1 chamada de
   destaques por CATEGORIA (varios anuncios caem na mesma) pra posicionar a loja toda. Fica barato
   o suficiente pra rodar todo dia e ir formando o historico. */
app.get('/ml/ranking-categoria', exigirLogin, async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) {
      return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    }
    const accessToken = await tokenValido(loja);
    const cab = { Authorization: `Bearer ${accessToken}` };
    const r = await pool.query(
      "select ml_item_id, sku, categoria_id from ml_produtos where loja = $1 and categoria_id is not null and coalesce(status,'') <> 'closed'",
      [loja]
    );
    const ids0 = r.rows.map(x => x.ml_item_id).filter(Boolean);
    const categorias = [...new Set(r.rows.map(x => x.categoria_id).filter(Boolean))];
    const ranking = {};
    const diagnostico = [];
    for (const cat of categorias) {
      try {
        const rH = await fetch(`https://api.mercadolibre.com/highlights/MLB/category/${encodeURIComponent(cat)}`, { headers: cab });
        const jH = await rH.json();
        if (rH.ok && jH && Array.isArray(jH.content)) ranking[cat] = jH.content;
        /* diagnostico (02/09): as posicoes vieram todas null com 17 categorias consultadas -
           precisa ver o que o endpoint devolve de fato (status, quantos itens, e o formato de
           cada entrada: o ranking pode vir por PRODUTO de catalogo em vez de por anuncio). */
        if (diagnostico.length < 3) {
          diagnostico.push({
            categoria: cat, status: rH.status,
            temContent: !!(jH && Array.isArray(jH.content)),
            qtd: (jH && Array.isArray(jH.content)) ? jH.content.length : null,
            amostra: (jH && Array.isArray(jH.content)) ? jH.content.slice(0, 3) : (jH || null)
          });
        }
      } catch (e) { if (diagnostico.length < 3) diagnostico.push({ categoria: cat, erro: e.message }); }
    }
    /* Junto do ranking, traz as etiquetas do anuncio (02/09 - o /ml/raio-x na TorvStore mostrou
       que dali saem coisas uteis que o Doca ainda ignorava: gold_pro = anuncio Premium pagando
       quase o dobro de comissao, standard_price_by_quantity = preco por faixa de quantidade -
       que foi exatamente o que fez a meta do AFIADOR19 sair errada -, good_quality_thumbnail,
       status pausado e logistic_type fora do fulfillment). Multiget: 1 chamada a cada 20. */
    const extras = {};
    for (let i = 0; i < ids0.length; i += 20) {
      const lote = ids0.slice(i, i + 20).join(',');
      try {
        const rr = await fetch(`https://api.mercadolibre.com/items?ids=${lote}&attributes=id,tags,listing_type_id,status,shipping,catalog_listing,catalog_product_id,user_product_id,seller_id,price`, { headers: cab });
        const jj = await rr.json();
        (Array.isArray(jj) ? jj : []).forEach(w => {
          const b = w && w.body; if (!b || !b.id) return;
          extras[b.id] = {
            tags: Array.isArray(b.tags) ? b.tags : [],
            tipoAnuncio: b.listing_type_id || null,
            status: b.status || null,
            logistica: (b.shipping && b.shipping.logistic_type) || null,
            /* CORRIGIDO 02/09 (Felipe: "quase todos meus anuncios sao de catalogo - o afiador e'
               tradicional e o musgo e' catalogo"): no anuncio de CATALOGO o ranking de destaques
               lista o PRODUTO de catalogo, nao o anuncio. Sem o catalog_product_id nao tinha como
               casar, e por isso TODAS as posicoes voltavam null. */
            catalogo: !!b.catalog_listing,
            produtoCatalogo: b.catalog_product_id || null,
            /* CORRIGIDO 02/09 (2a volta, com o diagnostico real do Felipe): o ranking mistura tres
               tipos de entrada - PRODUCT (produto de catalogo, ex: musgo), USER_PRODUCT (produto
               do proprio vendedor, id comecando com MLBU, que e' o caso do anuncio TRADICIONAL como
               o AFIADOR19) e o proprio anuncio. Sem o user_product_id, o tradicional continuava
               sem posicao mesmo estando no ranking. */
            produtoDoVendedor: b.user_product_id || null,
            vendedor: b.seller_id || null,
            preco: (typeof b.price === 'number') ? b.price : null
          };
        });
      } catch (e) { /* lote com problema: segue */ }
    }
    /* QUEM MAIS VENDE NO MEU CATALOGO (02/09, pedido do Felipe: "inclua na Visao Geral se tem algum
       vendedor vendendo no meu catalogo"). O status de price_to_win so' diz se estou ganhando ou
       perdendo a compra - nao diz QUANTOS estao disputando. /products/{id}/items lista todas as
       ofertas daquele produto de catalogo, entao da' pra contar os outros vendedores mesmo quando
       eu estou ganhando. 1 chamada por produto de catalogo, so' pra quem tem catalog_product_id. */
    const ofertasPorProduto = {};
    const diagnosticoOfertas = [];
    const produtosCat = [...new Set(Object.values(extras).map(e => e.produtoCatalogo).filter(Boolean))];
    for (const pid of produtosCat) {
      try {
        const rp = await fetch(`https://api.mercadolibre.com/products/${encodeURIComponent(pid)}/items?limit=50`, { headers: cab });
        const jp = await rp.json();
        const res = (jp && Array.isArray(jp.results)) ? jp.results : [];
        ofertasPorProduto[pid] = res.map(o => ({
          itemId: o.item_id || o.id || null,
          vendedor: o.seller_id || null,
          preco: (typeof o.price === 'number') ? o.price : ((o.price && o.price.amount) || null)
        }));
        /* diagnostico (02/09): o formato dessa lista foi suposto, nao confirmado na documentacao.
           Mostra a resposta crua dos 2 primeiros produtos pra dar pra conferir se seller_id/price
           vem mesmo assim - se vier diferente, a contagem sai zerada em silencio. */
        if (diagnosticoOfertas.length < 2) {
          diagnosticoOfertas.push({
            produtoCatalogo: pid, status: rp.status,
            temResults: !!(jp && Array.isArray(jp.results)),
            qtd: res.length,
            amostraCrua: res.slice(0, 2),
            interpretado: (ofertasPorProduto[pid] || []).slice(0, 2)
          });
        }
      } catch (e) { if (diagnosticoOfertas.length < 2) diagnosticoOfertas.push({ produtoCatalogo: pid, erro: e.message }); }
    }
    const itens = r.rows.map(x => {
      const ex = extras[x.ml_item_id] || {};
      const lista = ranking[x.categoria_id];
      let posicao = null, total = null, casouPor = null;
      if (Array.isArray(lista)) {
        /* casa de tres jeitos, porque o ranking mistura anuncio e produto de catalogo:
             1) pelo id do anuncio          (anuncio tradicional, ex: AFIADOR19)
             2) pelo produto de catalogo    (anuncio de catalogo, ex: MUSGO)
             3) pelo parent_id              (variacoes) */
        const idx = lista.findIndex(c => {
          if (!c) return false;
          if (c.id === x.ml_item_id || c.parent_id === x.ml_item_id) return true;
          if (ex.produtoCatalogo && (c.id === ex.produtoCatalogo || c.parent_id === ex.produtoCatalogo)) return true;
          if (ex.produtoDoVendedor && (c.id === ex.produtoDoVendedor || c.parent_id === ex.produtoDoVendedor)) return true;
          return false;
        });
        if (idx >= 0) {
          const achado = lista[idx];
          /* usa a posicao que o proprio ML manda; se nao vier, cai no indice da lista */
          posicao = (achado && typeof achado.position === 'number') ? achado.position : (idx + 1);
          total = lista.length;
          if (achado && (achado.id === x.ml_item_id || achado.parent_id === x.ml_item_id)) casouPor = 'anuncio';
          else if (ex.produtoDoVendedor && achado && (achado.id === ex.produtoDoVendedor || achado.parent_id === ex.produtoDoVendedor)) casouPor = 'produto_do_vendedor';
          else casouPor = 'catalogo';
        }
      }
      const ofertas = ex.produtoCatalogo ? (ofertasPorProduto[ex.produtoCatalogo] || null) : null;
      let outrosVendedores = null, menorPrecoConcorrente = null;
      if (Array.isArray(ofertas)) {
        const outros = ofertas.filter(o => o.vendedor && String(o.vendedor) !== String(ex.vendedor || ''));
        outrosVendedores = outros.length;
        const precos = outros.map(o => o.preco).filter(v => typeof v === 'number' && v > 0);
        if (precos.length) menorPrecoConcorrente = Math.min(...precos);
      }
      return { itemId: x.ml_item_id, sku: x.sku, categoriaId: x.categoria_id, posicao, total, casouPor,
        catalogo: !!ex.catalogo, produtoCatalogo: ex.produtoCatalogo || null, produtoDoVendedor: ex.produtoDoVendedor || null,
        outrosVendedores, menorPrecoConcorrente, meuPreco: ex.preco || null,
        tags: ex.tags || [], tipoAnuncio: ex.tipoAnuncio || null, status: ex.status || null, logistica: ex.logistica || null };
    });
    res.set('Cache-Control', 'no-store');
    res.json({ ok: true, loja, categorias: categorias.length, diagnostico, diagnosticoOfertas, itens });
  } catch (e) {
    res.status(500).json({ ok: false, erro: e.message });
  }
});
/* RAIO-X DO QUE A API DEVOLVE (02/09, pergunta do Felipe: "o que mais de notas interessantes como
   a de candidato a mais vendido a API traz que hoje nao utilizamos?"). Em vez de eu chutar pela
   documentacao, isto varre os anuncios REAIS da loja e resume: quais tags aparecem e em quantos
   anuncios, a nota de qualidade (health), tipo de anuncio, tipo logistico e status. E' so' leitura
   e usa multiget (1 chamada a cada 20 anuncios). Ver /diagnostico na tela do Doca. */
app.get('/ml/raio-x', exigirLogin, async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) {
      return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    }
    const accessToken = await tokenValido(loja);
    const cab = { Authorization: `Bearer ${accessToken}` };
    const r = await pool.query("select ml_item_id from ml_produtos where loja = $1 and coalesce(status,'') <> 'closed'", [loja]);
    const ids = r.rows.map(x => x.ml_item_id).filter(Boolean);
    const contaTag = {}, contaLogistica = {}, contaTipo = {}, contaStatus = {};
    const health = [];
    const exemploPorTag = {};
    let lidos = 0;
    for (let i = 0; i < ids.length; i += 20) {
      const lote = ids.slice(i, i + 20).join(',');
      try {
        const rr = await fetch(`https://api.mercadolibre.com/items?ids=${lote}&attributes=id,tags,health,listing_type_id,status,shipping,sold_quantity,available_quantity`, { headers: cab });
        const jj = await rr.json();
        (Array.isArray(jj) ? jj : []).forEach(w => {
          const b = w && w.body; if (!b) return;
          lidos++;
          (Array.isArray(b.tags) ? b.tags : []).forEach(t => {
            contaTag[t] = (contaTag[t] || 0) + 1;
            if (!exemploPorTag[t]) exemploPorTag[t] = b.id;
          });
          if (typeof b.health === 'number') health.push({ id: b.id, health: b.health });
          const log = b.shipping && b.shipping.logistic_type;
          if (log) contaLogistica[log] = (contaLogistica[log] || 0) + 1;
          if (b.listing_type_id) contaTipo[b.listing_type_id] = (contaTipo[b.listing_type_id] || 0) + 1;
          if (b.status) contaStatus[b.status] = (contaStatus[b.status] || 0) + 1;
        });
      } catch (e) { /* lote com problema: segue pros proximos */ }
    }
    const ordena = o => Object.keys(o).sort((a, b) => o[b] - o[a]).map(k => ({ chave: k, anuncios: o[k], exemplo: exemploPorTag[k] || null }));
    health.sort((a, b) => a.health - b.health);
    res.set('Cache-Control', 'no-store');
    res.json({
      ok: true, loja, anunciosLidos: lidos,
      tags: ordena(contaTag),
      tipoAnuncio: ordena(contaTipo),
      logistica: ordena(contaLogistica),
      status: ordena(contaStatus),
      healthPiores: health.slice(0, 15),
      healthMedia: health.length ? Math.round((health.reduce((s, x) => s + x.health, 0) / health.length) * 100) / 100 : null
    });
  } catch (e) {
    res.status(500).json({ ok: false, erro: e.message });
  }
});
app.get('/debug/custo-estimado', async (req, res) => {
  try {
    const loja = req.query.loja;
    const itemId = req.query.itemId;
    if (!LOJAS_VALIDAS.includes(loja)) {
      return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    }
    if (!itemId) return res.status(400).json({ ok: false, erro: 'Parametro "itemId" obrigatorio (ex: MLB6574356166).' });
    const accessToken = await tokenValido(loja);
    const resultado = { item: null, comissao: null, frete_gratis: null, opcoes_frete: null };
    const rItem = await fetch(`https://api.mercadolibre.com/items/${itemId}`, { headers: { Authorization: `Bearer ${accessToken}` } });
    const jItem = await rItem.json();
    resultado.item = {
      http_status: rItem.status,
      price: jItem.price, category_id: jItem.category_id, listing_type_id: jItem.listing_type_id,
      site_id: jItem.site_id, seller_id: jItem.seller_id,
      shipping: jItem.shipping || null,
      dados_completos: jItem
    };
    try {
      const url = `https://api.mercadolibre.com/sites/${jItem.site_id}/listing_prices?price=${jItem.price}&category_id=${jItem.category_id}&listing_type_id=${jItem.listing_type_id}`;
      const rComissao = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
      resultado.comissao = { url, http_status: rComissao.status, corpo: await rComissao.json() };
    } catch (e) { resultado.comissao = { erro: e.message }; }
    try {
      const url = `https://api.mercadolibre.com/users/${jItem.seller_id}/shipping_options/free?item_id=${itemId}`;
      const rFrete = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
      resultado.frete_gratis = { url, http_status: rFrete.status, corpo: await rFrete.json() };
    } catch (e) { resultado.frete_gratis = { erro: e.message }; }
    try {
      const url = `https://api.mercadolibre.com/items/${itemId}/shipping_options`;
      const rOpcoes = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
      resultado.opcoes_frete = { url, http_status: rOpcoes.status, corpo: await rOpcoes.json() };
    } catch (e) { resultado.opcoes_frete = { erro: e.message }; }
    res.json({ ok: true, loja, itemId, ...resultado });
  } catch (e) {
    res.status(500).json({ ok: false, erro: e.message });
  }
});
/* ---- Mercado Pago: relatorio de Liberacoes (v17) ----
   Fluxo de 3 passos: 1) POST /v1/account/release_report {begin_date, end_date} -> pede a geracao
   2) GET /v1/account/release_report/list -> lista os relatorios pedidos, com "status"
   3) GET /v1/account/release_report/:file_name -> baixa o CSV do relatorio pronto */
async function mpFetch(loja, path, opts) {
  const token = tokenMpDaLoja(loja);
  if (!token) throw new Error(`Faltou a variavel de ambiente MP_ACCESS_TOKEN_${normalizarChaveLoja(loja)} (ou MP_ACCESS_TOKEN) no Render.`);
  return fetch(`https://api.mercadopago.com${path}`, {
    ...opts,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json', ...((opts && opts.headers) || {}) }
  });
}
app.post('/debug/mp/relatorio/pedir', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const dias = Math.min(60, Math.max(1, parseInt(req.query.dias || '7', 10)));
    const diaUTC = (d) => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
    const fmtSemMs = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');
    const fim = fimHojeBRT();
    const inicio = diaUTC(new Date(fim.getTime() - dias * 864e5));
    const beginDate = fmtSemMs(inicio), endDate = fmtSemMs(fim);
    const r = await mpFetch(loja, '/v1/account/release_report', {
      method: 'POST',
      body: JSON.stringify({ begin_date: beginDate, end_date: endDate })
    });
    let corpo; try { corpo = await r.json(); } catch (e) { corpo = { aviso: 'resposta sem JSON', texto: await r.text().catch(() => null) }; }
    res.status(200).json({ ok: r.ok, http_status: r.status, janela: { begin_date: beginDate, end_date: endDate }, corpo });
  } catch (e) { res.status(500).json({ ok: false, erro: e.message }); }
});
app.get('/debug/mp/relatorio/testar-janela-hoje', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const diaUTC = (d) => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
    const fmtSemMs = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');
    const fim = fimHojeBRT();
    const inicio = diaUTC(new Date(fim.getTime() - 7 * 864e5));
    const beginDate = fmtSemMs(inicio), endDate = fmtSemMs(fim);
    const r = await mpFetch(loja, '/v1/account/release_report', {
      method: 'POST',
      body: JSON.stringify({ begin_date: beginDate, end_date: endDate })
    });
    let corpo; try { corpo = await r.json(); } catch (e) { corpo = { aviso: 'resposta sem JSON', texto: await r.text().catch(() => null) }; }
    res.status(200).json({ ok: r.ok, http_status: r.status, janela: { begin_date: beginDate, end_date: endDate }, corpo });
  } catch (e) { res.status(500).json({ ok: false, erro: e.message }); }
});
app.get('/debug/mp/relatorio/listar', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const r = await mpFetch(loja, '/v1/account/release_report/list', { method: 'GET' });
    let corpo; try { corpo = await r.json(); } catch (e) { corpo = { aviso: 'resposta sem JSON' }; }
    res.status(200).json({ ok: r.ok, http_status: r.status, corpo });
  } catch (e) { res.status(500).json({ ok: false, erro: e.message }); }
});
app.get('/debug/mp/relatorio/baixar', async (req, res) => {
  try {
    const loja = req.query.loja;
    const arquivo = req.query.arquivo;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!arquivo) return res.status(400).json({ ok: false, erro: 'Parametro "arquivo" obrigatorio (ver o campo do relatorio em /debug/mp/relatorio/listar).' });
    const r = await mpFetch(loja, `/v1/account/release_report/${encodeURIComponent(arquivo)}`, { method: 'GET' });
    const texto = await r.text();
    res.status(200).type('text/plain').send(`HTTP ${r.status}\n\n${texto.slice(0, 20000)}`);
  } catch (e) { res.status(500).json({ ok: false, erro: e.message }); }
});
app.get('/debug/mp/relatorio/categorias', async (req, res) => {
  try {
    const loja = req.query.loja;
    const arquivo = req.query.arquivo;
    const de = req.query.de, ate = req.query.ate;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!arquivo) return res.status(400).json({ ok: false, erro: 'Parametro "arquivo" obrigatorio (ver o campo do relatorio em /debug/mp/relatorio/listar).' });
    const r = await mpFetch(loja, `/v1/account/release_report/${encodeURIComponent(arquivo)}`, { method: 'GET' });
    const texto = await r.text();
    const { cabecalho, linhas } = parseCsvPontoEVirgula(texto);
    if (!linhas.length) return res.status(200).json({ ok: false, erro: 'Relatorio vazio ou nao processado ainda.', http_status: r.status, cabecalho });
    const filtradas = (de && ate)
      ? linhas.filter(l => { const d = (l.DATE || '').slice(0, 10); return d >= de && d <= ate; })
      : linhas;
    const colValor = ['NET_CREDIT_AMOUNT', 'GROSS_AMOUNT', 'AMOUNT', 'TRANSACTION_AMOUNT', 'SETTLEMENT_NET_AMOUNT', 'BALANCE_AMOUNT']
      .find(c => cabecalho.includes(c));
    const colDescricao = ['DESCRIPTION', 'TRANSACTION_TYPE', 'SOURCE_ID'].find(c => cabecalho.includes(c));
    const porCategoria = new Map();
    filtradas.forEach(l => {
      const chave = colDescricao ? (l[colDescricao] || '(sem descricao)') : '(sem coluna de descricao)';
      const valor = colValor ? (parseFloat(l[colValor]) || 0) : 0;
      const atual = porCategoria.get(chave) || { total: 0, linhas: 0 };
      atual.total += valor;
      atual.linhas += 1;
      porCategoria.set(chave, atual);
    });
    const totalDebitado = [...porCategoria.values()].reduce((s, v) => s + (v.total < 0 ? Math.abs(v.total) : 0), 0);
    const categorias = [...porCategoria.entries()]
      .map(([chave, v]) => ({
        categoria: chave,
        total: Math.round(v.total * 100) / 100,
        percentual_do_debitado: (totalDebitado > 0 && v.total < 0) ? Math.round((Math.abs(v.total) / totalDebitado) * 1000) / 10 : null,
        linhas: v.linhas
      }))
      .sort((a, b) => a.total - b.total);
    res.json({
      ok: true, loja, arquivo, filtro: { de: de || null, ate: ate || null },
      colunas_disponiveis: cabecalho,
      coluna_valor_usada: colValor || null,
      coluna_descricao_usada: colDescricao || null,
      total_linhas_no_relatorio: linhas.length,
      total_linhas_no_filtro: filtradas.length,
      total_debitado_da_conta: Math.round(totalDebitado * 100) / 100,
      categorias,
      amostra_3_linhas: filtradas.slice(0, 3)
    });
  } catch (e) { res.status(500).json({ ok: false, erro: e.message }); }
});
/* ---- "foi liberado certo?" (v20, pedido do Felipe 24/08) ----
   Compara o total que o proprio Mercado Pago diz ter liberado num periodo (relatorio oficial de
   Liberacoes, /v1/account/release_report, o mesmo que ja usamos pro saldo disponivel) com o
   relatorio "Por liberacao de dinheiro" que o Felipe sobe manual em Conciliacao (que e' o mesmo
   dado, so' que exportado pelo Mercado Livre). Roda em job assincrono (igual Auditoria) porque
   pedir um relatorio novo pro Mercado Pago pode demorar minutos pra ficar pronto - e' async lah
   fora tambem, entao esse job so' fica dando poll no /release_report/list ate achar.
   CUIDADO: isso e' uma pergunta DIFERENTE da Auditoria normal. A Auditoria agrupa por quando o
   pedido foi VENDIDO (date_closed); esse aqui agrupa por quando o dinheiro foi de fato LIBERADO
   (money release date) - dois pedidos vendidos no mesmo dia podem ser liberados em datas bem
   diferentes (14 dias corridos, ou mais se tiver reclamacao/mediacao no meio). Por isso NAO da
   pra comparar isso direto com o repasse_liberado da Auditoria (que so' conta liberacao de
   pedidos vendidos DENTRO do periodo da Auditoria, nao liberacoes que aconteceram no periodo) -
   so' compara com o anexo "Por liberacao de dinheiro" (que usa a mesma data de liberacao). */
const liberacaoJobs = new Map(); // jobId -> {status, resultado, erro, criadoEm}
function gerarJobIdLiberacao() { return 'lib_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8); }
async function rodarLiberacaoMes(jobId, loja, de, ate) {
  const job = liberacaoJobs.get(jobId);
  try {
    /* o Mercado Pago recusa o formato "-03:00" direto (HTTP 400 invalid_begin_date) - precisa ser
       UTC com sufixo Z, sem milissegundos, igual o /debug/mp/relatorio/pedir que ja funcionava
       (achado 24/08, testado em producao). */
    const fmtSemMs = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');
    const beginDate = fmtSemMs(new Date(`${de}T00:00:00-03:00`));
    const endDate = fmtSemMs(new Date(`${ate}T23:59:59-03:00`));
    const rPedido = await mpFetch(loja, '/v1/account/release_report', {
      method: 'POST',
      body: JSON.stringify({ begin_date: beginDate, end_date: endDate })
    });
    if (!rPedido.ok) {
      const corpoErro = await rPedido.text().catch(() => '');
      job.status = 'erro';
      job.erro = `O Mercado Pago recusou o pedido do relatorio (HTTP ${rPedido.status}) - pode ser que esse período seja antigo demais pra esse tipo de relatório. ${corpoErro.slice(0, 300)}`;
      return;
    }
    const inicio = Date.now();
    const LIMITE_MS = 5 * 60 * 1000; // MP pode levar alguns minutos pra gerar um relatorio novo
    let arquivoPronto = null;
    while (Date.now() - inicio < LIMITE_MS) {
      await sleep(6000);
      const rList = await mpFetch(loja, '/v1/account/release_report/list', { method: 'GET' });
      const jList = await rList.json().catch(() => null);
      const candidatos = (Array.isArray(jList) ? jList : [])
        .filter(x => x.file_name && x.begin_date && (x.begin_date.slice(0, 10) === de) && x.status === 'enabled')
        .sort((a, b) => new Date(b.date_created) - new Date(a.date_created));
      if (candidatos.length) { arquivoPronto = candidatos[0]; break; }
    }
    if (!arquivoPronto) {
      job.status = 'erro';
      job.erro = 'O Mercado Pago demorou demais pra gerar esse relatório (mais de 5 min) - tenta de novo daqui a pouco, ele pode ainda estar processando do lado deles.';
      return;
    }
    const rDown = await mpFetch(loja, `/v1/account/release_report/${encodeURIComponent(arquivoPronto.file_name)}`, { method: 'GET' });
    const texto = await rDown.text();
    const { cabecalho, linhas } = parseCsvPontoEVirgula(texto);
    if (!linhas.length) { job.status = 'erro'; job.erro = 'Relatório baixado mas veio vazio.'; return; }
    const colValor = ['NET_CREDIT_AMOUNT', 'SETTLEMENT_NET_AMOUNT', 'GROSS_AMOUNT', 'AMOUNT'].find(c => cabecalho.includes(c));
    if (!colValor) { job.status = 'erro'; job.erro = `Relatório baixado mas não achei coluna de valor conhecida (colunas disponíveis: ${cabecalho.join(', ')}).`; return; }
    const colData = ['DATE', 'TRANSACTION_DATE', 'MONEY_RELEASE_DATE'].find(c => cabecalho.includes(c));
    const doPeriodo = colData ? linhas.filter(l => { const d = (l[colData] || '').slice(0, 10); return d >= de && d <= ate; }) : linhas;
    const totalLiberado = doPeriodo.reduce((s, l) => s + (parseFloat(l[colValor]) || 0), 0);
    job.status = 'concluido';
    job.resultado = {
      loja, periodo: { de, ate },
      arquivo: arquivoPronto.file_name,
      coluna_valor_usada: colValor,
      total_linhas_relatorio: linhas.length,
      total_linhas_periodo: doPeriodo.length,
      total_liberado_mp: Math.round(totalLiberado * 100) / 100
    };
  } catch (e) {
    job.status = 'erro';
    job.erro = e.message;
  }
}
app.post('/liberacao/mes/iniciar', async (req, res) => {
  try {
    const loja = req.query.loja, de = req.query.de, ate = req.query.ate;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!de || !ate) return res.status(400).json({ ok: false, erro: 'Parametros "de" e "ate" obrigatorios (AAAA-MM-DD).' });
    const jobId = gerarJobIdLiberacao();
    liberacaoJobs.set(jobId, { status: 'rodando', resultado: null, erro: null, criadoEm: Date.now() });
    rodarLiberacaoMes(jobId, loja, de, ate); // fire-and-forget, roda em background
    res.json({ ok: true, jobId });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message }); }
});
app.get('/liberacao/mes/status', (req, res) => {
  const jobId = req.query.id;
  const job = liberacaoJobs.get(jobId);
  if (!job) return res.status(404).json({ ok: false, erro: 'Job não encontrado - pode ter expirado (fica só em memória, some se o servidor reiniciar).' });
  res.json({ ok: true, status: job.status, resultado: job.resultado, erro: job.erro });
});
app.get('/debug/mp/relatorio/pagamentos-resumo', async (req, res) => {
  try {
    const loja = req.query.loja;
    const arquivo = req.query.arquivo;
    const de = req.query.de, ate = req.query.ate;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!arquivo) return res.status(400).json({ ok: false, erro: 'Parametro "arquivo" obrigatorio (ver o campo do relatorio em /debug/mp/relatorio/listar).' });
    const r = await mpFetch(loja, `/v1/account/release_report/${encodeURIComponent(arquivo)}`, { method: 'GET' });
    const texto = await r.text();
    const { cabecalho, linhas } = parseCsvPontoEVirgula(texto);
    if (!linhas.length) return res.status(200).json({ ok: false, erro: 'Relatorio vazio ou nao processado ainda.', http_status: r.status, cabecalho });
    const filtradas = linhas.filter(l => {
      if (l.DESCRIPTION !== 'payment') return false;
      if (!de || !ate) return true;
      const d = (l.DATE || '').slice(0, 10);
      return d >= de && d <= ate;
    });
    let totalGross = 0, totalMpFee = 0, totalTaxes = 0, totalNet = 0;
    filtradas.forEach(l => {
      totalGross += parseFloat(l.GROSS_AMOUNT) || 0;
      totalMpFee += parseFloat(l.MP_FEE_AMOUNT) || 0;
      totalTaxes += parseFloat(l.TAXES_AMOUNT) || 0;
      totalNet += parseFloat(l.NET_CREDIT_AMOUNT) || 0;
    });
    const outrasDeducoes = totalGross - totalNet - Math.abs(totalMpFee) - Math.abs(totalTaxes);
    const arred = (n) => Math.round(n * 100) / 100;
    res.json({
      ok: true, loja, arquivo, filtro: { de: de || null, ate: ate || null },
      total_linhas_payment_no_filtro: filtradas.length,
      total_gross_amount: arred(totalGross),
      total_mp_fee_amount: arred(totalMpFee),
      total_taxes_amount: arred(totalTaxes),
      total_net_credit_amount: arred(totalNet),
      outras_deducoes_alem_mp_fee_e_taxes: arred(outrasDeducoes),
      percentual_outras_deducoes_sobre_gross: totalGross > 0 ? arred((outrasDeducoes / totalGross) * 100) : null
    });
  } catch (e) { res.status(500).json({ ok: false, erro: e.message }); }
});
app.get('/debug/mp/relatorio/busca', async (req, res) => {
  try {
    const loja = req.query.loja;
    const arquivo = req.query.arquivo;
    const sourceId = req.query.source_id;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!arquivo) return res.status(400).json({ ok: false, erro: 'Parametro "arquivo" obrigatorio.' });
    if (!sourceId) return res.status(400).json({ ok: false, erro: 'Parametro "source_id" obrigatorio (id do pagamento).' });
    const r = await mpFetch(loja, `/v1/account/release_report/${encodeURIComponent(arquivo)}`, { method: 'GET' });
    const texto = await r.text();
    const { cabecalho, linhas } = parseCsvPontoEVirgula(texto);
    const encontradas = linhas.filter(l => l.SOURCE_ID === sourceId);
    res.json({ ok: true, loja, arquivo, source_id: sourceId, total_encontrado: encontradas.length, linhas: encontradas, colunas: cabecalho });
  } catch (e) { res.status(500).json({ ok: false, erro: e.message }); }
});
function parseCsvPontoEVirgula(texto) {
  const linhas = texto.replace(/\r/g, '').split('\n').filter(l => l.trim().length > 0);
  if (!linhas.length) return { cabecalho: [], linhas: [] };
  const cabecalho = linhas[0].split(';');
  const linhasObj = linhas.slice(1).map(l => {
    const campos = l.split(';');
    const obj = {};
    cabecalho.forEach((c, i) => { obj[c] = campos[i]; });
    return obj;
  });
  return { cabecalho, linhas: linhasObj };
}
app.get('/debug/mp/relatorio/saldo', async (req, res) => {
  try {
    const loja = req.query.loja;
    const arquivo = req.query.arquivo;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!arquivo) return res.status(400).json({ ok: false, erro: 'Parametro "arquivo" obrigatorio (ver o campo do relatorio em /debug/mp/relatorio/listar).' });
    const r = await mpFetch(loja, `/v1/account/release_report/${encodeURIComponent(arquivo)}`, { method: 'GET' });
    const texto = await r.text();
    const { cabecalho, linhas } = parseCsvPontoEVirgula(texto);
    if (!linhas.length) return res.status(200).json({ ok: false, erro: 'Relatorio vazio ou nao processado ainda.', http_status: r.status, cabecalho });
    const comData = linhas.filter(l => (l.DATE || '').trim().length > 0);
    const ultima = comData.length ? comData[comData.length - 1] : linhas[linhas.length - 1];
    const saldo = parseFloat(ultima.BALANCE_AMOUNT);
    res.status(200).json({
      ok: true, loja, totalLinhas: linhas.length, linhasComData: comData.length,
      saldoDisponivel: isNaN(saldo) ? null : saldo,
      dataUltimaLinha: ultima.DATE || null,
      ultimaLinha: ultima
    });
  } catch (e) { res.status(500).json({ ok: false, erro: e.message }); }
});
/* ---- Mercado Pago: relatorio "Dinheiro em conta" / settlement_report (v18) ----
   Mesmo fluxo de 3 passos, outro relatorio. Tem IS_RELEASED (TRUE/FALSE) e
   SETTLEMENT_NET_AMOUNT - somando SETTLEMENT_NET_AMOUNT de toda linha com IS_RELEASED=FALSE
   dentro da janela pedida, da exatamente o "A Receber". */
app.post('/debug/mp/dinheiro/pedir', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const dias = Math.min(60, Math.max(1, parseInt(req.query.dias || '30', 10)));
    const diaUTC = (d) => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
    const fmtSemMs = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');
    const fim = fimHojeBRT();
    const inicio = diaUTC(new Date(fim.getTime() - dias * 864e5));
    const beginDate = fmtSemMs(inicio), endDate = fmtSemMs(fim);
    const r = await mpFetch(loja, '/v1/account/settlement_report', {
      method: 'POST',
      body: JSON.stringify({ begin_date: beginDate, end_date: endDate })
    });
    let corpo; try { corpo = await r.json(); } catch (e) { corpo = { aviso: 'resposta sem JSON', texto: await r.text().catch(() => null) }; }
    res.status(200).json({ ok: r.ok, http_status: r.status, janela: { begin_date: beginDate, end_date: endDate }, corpo });
  } catch (e) { res.status(500).json({ ok: false, erro: e.message }); }
});
const COLUNAS_DINHEIRO_EM_CONTA = [
  'TRANSACTION_DATE', 'SOURCE_ID', 'DESCRIPTION', 'TRANSACTION_TYPE', 'TRANSACTION_AMOUNT',
  'SETTLEMENT_NET_AMOUNT', 'IS_RELEASED', 'MONEY_RELEASE_DATE', 'BUSINESS_UNIT', 'PAYMENT_METHOD_TYPE'
].map(key => ({ key }));
app.post('/debug/mp/dinheiro/config', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const r = await mpFetch(loja, '/v1/account/settlement_report/config', {
      method: 'POST',
      body: JSON.stringify({
        file_name_prefix: `settlement-report-${normalizarChaveLoja(loja)}`,
        columns: COLUNAS_DINHEIRO_EM_CONTA,
        frequency: { type: 'daily', hour: 3, value: 1 },
        show_fee_prevision: false,
        show_chargeback_cancel: false
      })
    });
    let corpo; try { corpo = await r.json(); } catch (e) { corpo = { aviso: 'resposta sem JSON', texto: await r.text().catch(() => null) }; }
    res.status(200).json({ ok: r.ok, http_status: r.status, corpo });
  } catch (e) { res.status(500).json({ ok: false, erro: e.message }); }
});
app.get('/debug/mp/dinheiro/listar', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const r = await mpFetch(loja, '/v1/account/settlement_report/list', { method: 'GET' });
    let corpo; try { corpo = await r.json(); } catch (e) { corpo = { aviso: 'resposta sem JSON' }; }
    res.status(200).json({ ok: r.ok, http_status: r.status, corpo });
  } catch (e) { res.status(500).json({ ok: false, erro: e.message }); }
});
app.get('/debug/mp/dinheiro/baixar', async (req, res) => {
  try {
    const loja = req.query.loja;
    const arquivo = req.query.arquivo;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!arquivo) return res.status(400).json({ ok: false, erro: 'Parametro "arquivo" obrigatorio (ver o campo do relatorio em /debug/mp/dinheiro/listar).' });
    const r = await mpFetch(loja, `/v1/account/settlement_report/${encodeURIComponent(arquivo)}`, { method: 'GET' });
    const texto = await r.text();
    res.status(200).type('text/plain').send(`HTTP ${r.status}\n\n${texto.slice(0, 20000)}`);
  } catch (e) { res.status(500).json({ ok: false, erro: e.message }); }
});
app.get('/debug/mp/dinheiro/areceber', async (req, res) => {
  try {
    const loja = req.query.loja;
    const arquivo = req.query.arquivo;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!arquivo) return res.status(400).json({ ok: false, erro: 'Parametro "arquivo" obrigatorio (ver o campo do relatorio em /debug/mp/dinheiro/listar).' });
    const r = await mpFetch(loja, `/v1/account/settlement_report/${encodeURIComponent(arquivo)}`, { method: 'GET' });
    const texto = await r.text();
    const { cabecalho, linhas } = parseCsvPontoEVirgula(texto);
    if (!linhas.length) return res.status(200).json({ ok: false, erro: 'Relatorio vazio ou nao processado ainda.', http_status: r.status, cabecalho });
    const pendentes = linhas.filter(l => (l.IS_RELEASED || '').toUpperCase() === 'FALSE');
    const aReceber = pendentes.reduce((soma, l) => {
      const v = parseFloat(l.SETTLEMENT_NET_AMOUNT);
      return soma + (isNaN(v) ? 0 : v);
    }, 0);
    res.status(200).json({
      ok: true, loja,
      totalLinhas: linhas.length,
      linhasPendentes: pendentes.length,
      aReceber: Math.round(aReceber * 100) / 100
    });
  } catch (e) { res.status(500).json({ ok: false, erro: e.message }); }
});
/* ---- Mercado Pago: financeiro automatico de verdade (v19) ----
   saldo disponivel = BALANCE_AMOUNT da ultima linha COM DATA do relatorio de Liberacoes
   a receber = soma de SETTLEMENT_NET_AMOUNT de toda linha com IS_RELEASED=FALSE no
   relatorio "Dinheiro em conta". Os dois relatorios sao ASSINCRONOS, entao funciona em 2
   passadas guardadas na tabela mp_financeiro: termina o pendente ou pede um novo. */
async function pegarFinanceiroMp(loja) {
  const r = await pool.query('select * from mp_financeiro where loja = $1', [loja]);
  return r.rows[0] || null;
}
app.get('/debug/mp/forcar-atualizacao', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const antes = await pegarFinanceiroMp(loja);
    await passoSaldoMp(loja, antes);
    await passoAReceberMp(loja, antes);
    const depois = await pegarFinanceiroMp(loja);
    res.json({ ok: true, loja, antes, depois });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message }); }
});
app.get('/debug/mp/financeiro', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const row = await pegarFinanceiroMp(loja);
    res.json({ ok: true, loja, linha: row });
  } catch (e) { res.status(500).json({ ok: false, erro: e.message }); }
});
async function upsertFinanceiroMp(loja, patch) {
  const atual = await pegarFinanceiroMp(loja);
  const base = atual || {};
  const linha = { ...base, ...patch, loja };
  await pool.query(
    `insert into mp_financeiro (loja, saldo_disponivel, saldo_atualizado_em, saldo_report_id, saldo_pedido_em,
        a_receber, a_receber_atualizado_em, areceber_report_id, areceber_pedido_em, agenda_liberacoes,
        prazo_liberacao_dias, receita_diaria_media, receita_atualizado_em)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
     on conflict (loja) do update set
       saldo_disponivel = excluded.saldo_disponivel,
       saldo_atualizado_em = excluded.saldo_atualizado_em,
       saldo_report_id = excluded.saldo_report_id,
       saldo_pedido_em = excluded.saldo_pedido_em,
       a_receber = excluded.a_receber,
       a_receber_atualizado_em = excluded.a_receber_atualizado_em,
       areceber_report_id = excluded.areceber_report_id,
       areceber_pedido_em = excluded.areceber_pedido_em,
       agenda_liberacoes = excluded.agenda_liberacoes,
       prazo_liberacao_dias = excluded.prazo_liberacao_dias,
       receita_diaria_media = excluded.receita_diaria_media,
       receita_atualizado_em = excluded.receita_atualizado_em`,
    [loja, linha.saldo_disponivel ?? null, linha.saldo_atualizado_em ?? null, linha.saldo_report_id ?? null,
     linha.saldo_pedido_em ?? null, linha.a_receber ?? null, linha.a_receber_atualizado_em ?? null,
     linha.areceber_report_id ?? null, linha.areceber_pedido_em ?? null,
     linha.agenda_liberacoes != null ? JSON.stringify(linha.agenda_liberacoes) : null,
     linha.prazo_liberacao_dias ?? null, linha.receita_diaria_media ?? null, linha.receita_atualizado_em ?? null]
  );
}
async function passoSaldoMp(loja, row) {
  // JANELA_FRESCOR_MS: 8h -> 20h (25/08, achado com dado real da TorvStore via
  // /debug/mp/relatorio/listar). O Mercado Pago so' gera um release_report NOVO pra essa loja a
  // cada ~10-15h (bate com o volume de vendas dela - as outras 3 lojas geram bem mais rapido) -
  // isso e' um limite do lado do Mercado Pago, pedir de novo mais vezes nao ajuda (o Doca ja'
  // pede um novo a cada ciclo, gated por PAUSA_ENTRE_PEDIDOS_MS, sem sucesso: o mais recente da
  // lista simplesmente nao fica mais novo que isso). Com janela de 8h, o relatorio mais fresco
  // que existe ficava rejeitado por boa parte do dia (13h+ de idade e' normal pra essa loja) e o
  // saldo mostrado na tela ficava travado num valor ainda mais antigo, girando em pedidos novos
  // que nunca chegavam a tempo. 20h da' margem suficiente pra sempre aceitar o relatorio mais
  // recente que existe (evita usar algo de dias atras', que aí sim seria enganoso).
  /* CORRIGIDO 01/09 (Felipe: "porque o saldo esta tao desatualizado de algumas e de outras
     atualizado hoje"): a janela de frescor estava virando o proprio problema. Se o relatorio mais
     novo que existe pra loja tem, digamos, 22h, ele era REJEITADO por passar de 20h - mas o que
     fica na tela nesse caso nao e' nada mais novo, e' o valor guardado da ultima leitura aceita,
     que e' AINDA MAIS VELHO (na TorvStore chegou a 2 dias). Rejeitar o mais fresco que existe
     nunca deixa o numero mais atual, so' mais antigo. Como o rotulo na tela ja' mostra a idade
     real do saldo ("saldo MP 30/08 23:29 - ha 2 dias"), o certo e' sempre usar o melhor relatorio
     disponivel e deixar a idade visivel. Mantem um teto largo (7 dias) so' pra nao usar algo
     absurdamente velho de vez. O Doca continua pedindo um relatorio novo a cada ciclo; a diferenca
     de frequencia entre as lojas e' do lado do Mercado Pago (cada conta gera o relatorio em lote no
     seu proprio ritmo, mais rapido quanto maior o volume) e nao tem como forcar daqui. */
  const JANELA_FRESCOR_MS = 7 * 24 * 60 * 60 * 1000;
  try {
    const rList = await mpFetch(loja, '/v1/account/release_report/list', { method: 'GET' });
    const jList = await rList.json().catch(() => null);
    const prontos = (Array.isArray(jList) ? jList : [])
      .filter(x => x.file_name && x.date_created)
      .sort((a, b) => new Date(b.date_created) - new Date(a.date_created));
    if (prontos.length) {
      const maisRecente = prontos[0];
      const idadeMs = Date.now() - new Date(maisRecente.date_created).getTime();
      if (idadeMs < JANELA_FRESCOR_MS) {
        const rDown = await mpFetch(loja, `/v1/account/release_report/${encodeURIComponent(maisRecente.file_name)}`, { method: 'GET' });
        const texto = await rDown.text();
        const { linhas } = parseCsvPontoEVirgula(texto);
        const comData = linhas.filter(l => (l.DATE || '').trim().length > 0);
        const ultima = comData.length ? comData[comData.length - 1] : null;
        const saldo = ultima ? parseFloat(ultima.BALANCE_AMOUNT) : NaN;
        if (!isNaN(saldo)) {
          /* ACHADO 27/08 (pedido do Felipe: saldo mostrado no Doca nao batia com o saldo real do
             app do Mercado Pago). Antes gravava saldo_atualizado_em como new Date() (o momento em
             que O NOSSO SERVIDOR processou o relatorio) - isso MENTE sobre o quao "fresco" o saldo
             e', porque o release_report e' um relatorio em LOTE que o Mercado Pago gera de tempos
             em tempos (pra TorvStore, historicamente a cada 10-15h, aceito ate' 20h de idade pela
             JANELA_FRESCOR_MS acima) - o saldo em si e' de QUANDO O RELATORIO FOI MONTADO, nao de
             quando o Doca o leu. Ex. real: relatorio criado as 19h49 (BRT), Doca processou as
             21h27 - o rotulo antigo dizia "atualizado as 21h27", enganando por 1h38 (e podendo ser
             bem mais, ate' a idade maxima aceita). Agora usa a DATA DA ULTIMA LINHA do proprio
             relatorio (a transacao mais recente que compoe esse saldo) - se nao tiver, cai pra
             date_created do relatorio. Nao existe endpoint de saldo "ao vivo" no Mercado Pago
             (testado /v1/account/balance - 404); o release_report (BALANCE_AMOUNT) e' o mesmo
             caminho oficial da documentacao "Relatorio de Liberacoes" que o Felipe mandou - so' que
             ele e' inerentemente um snapshot em lote, nunca vai ser "ao vivo" de verdade. */
          const dataUltimaLinha = ultima.DATE ? new Date(ultima.DATE) : null;
          const asOf = (dataUltimaLinha && !isNaN(dataUltimaLinha.getTime())) ? dataUltimaLinha : new Date(maisRecente.date_created);
          await upsertFinanceiroMp(loja, {
            saldo_disponivel: saldo,
            saldo_atualizado_em: asOf,
            saldo_report_id: null, saldo_pedido_em: null
          });
          return;
        }
      }
    }
  } catch (e) {
    console.error('[financeiro-mp] falha ao tentar ler relatorio pronto (saldo):', loja, e.message);
  }
  const PAUSA_ENTRE_PEDIDOS_MS = 10 * 60 * 1000;
  if (row && row.saldo_pedido_em && (Date.now() - new Date(row.saldo_pedido_em).getTime() < PAUSA_ENTRE_PEDIDOS_MS)) return;
  const dias = 7;
  const diaUTC = (d) => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const fmtSemMs = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');
  const fim = fimHojeBRT();
  const inicio = diaUTC(new Date(fim.getTime() - dias * 864e5));
  const r = await mpFetch(loja, '/v1/account/release_report', {
    method: 'POST',
    body: JSON.stringify({ begin_date: fmtSemMs(inicio), end_date: fmtSemMs(fim) })
  });
  const corpo = await r.json().catch(() => null);
  if (r.ok && corpo && corpo.id != null) {
    await upsertFinanceiroMp(loja, { saldo_report_id: String(corpo.id), saldo_pedido_em: new Date() });
  }
}
async function passoAReceberMp(loja, row) {
  const JANELA_FRESCOR_MS = 6 * 60 * 60 * 1000;
  try {
    const rList = await mpFetch(loja, '/v1/account/settlement_report/list', { method: 'GET' });
    const jList = await rList.json().catch(() => null);
    const prontos = (Array.isArray(jList) ? jList : [])
      .filter(x => x.file_name && x.date_created)
      .sort((a, b) => new Date(b.date_created) - new Date(a.date_created));
    if (prontos.length) {
      const maisRecente = prontos[0];
      const idadeMs = Date.now() - new Date(maisRecente.date_created).getTime();
      if (idadeMs < JANELA_FRESCOR_MS) {
        const rDown = await mpFetch(loja, `/v1/account/settlement_report/${encodeURIComponent(maisRecente.file_name)}`, { method: 'GET' });
        const texto = await rDown.text();
        const { linhas } = parseCsvPontoEVirgula(texto);
        if (linhas.length) {
          const pendentes = linhas.filter(l => (l.IS_RELEASED || '').toUpperCase() === 'FALSE');
          const aReceber = Math.round(pendentes.reduce((s, l) => {
            const v = parseFloat(l.SETTLEMENT_NET_AMOUNT);
            return s + (isNaN(v) ? 0 : v);
          }, 0) * 100) / 100;
          /* agenda de liberacoes: agrupa as linhas pendentes por MONEY_RELEASE_DATE (dia em que
             o Mercado Pago vai liberar aquele valor) - e' isso que da pra montar a projecao de
             caixa dia a dia, em vez de so' saber o total parado. Linha sem data valida cai fora
             da agenda (mas continua contando no total a_receber acima). */
        const porData = {};
          pendentes.forEach(l => {
            const v = parseFloat(l.SETTLEMENT_NET_AMOUNT);
            if (isNaN(v)) return;
            const dataBruta = (l.MONEY_RELEASE_DATE || '').trim();
            const data = dataBruta ? dataBruta.slice(0, 10) : null;
            if (!data || !/^\d{4}-\d{2}-\d{2}$/.test(data)) return;
            porData[data] = (porData[data] || 0) + v;
          });
          const agendaLiberacoes = Object.keys(porData).sort().map(data => ({
            data, valor: Math.round(porData[data] * 100) / 100
          }));
          /* prazo de liberacao + receita diaria media (27/08, pedido do Felipe - coluna "Projetado"
             do Fluxo de Caixa) - usa o MESMO relatorio ja baixado acima, sem gastar chamada nova:
             1) prazo de liberacao empirico da loja: MEDIANA de dias entre TRANSACTION_DATE e
                MONEY_RELEASE_DATE das linhas SETTLEMENT/SETTLEMENT_SHIPPING.
                CORRIGIDO 27/08 (2a volta, com prova real do Felipe): a 1a versao usava TODAS as
                linhas, inclusive as ainda pendentes (IS_RELEASED=false) - e a MONEY_RELEASE_DATE
                de uma linha pendente e' só uma estimativa/teto conservador (a maioria aparecia
                cravada em D+28) que o proprio Mercado Pago revisa pra baixo assim que a entrega e'
                confirmada. O Felipe provou isso com um pedido real: venda 14/08 23:02, entrega
                19/08 14:54, dinheiro caiu 27/08 - exatamente D+8 apos a ENTREGA, batendo com a
                regra oficial de reputacao boa (MercadoLider Gold, confirmado) + Full + produto
                novo. Ou seja, so' as linhas JA LIBERADAS DE VERDADE (IS_RELEASED=true) refletem o
                prazo real; as pendentes inflavam a mediana pra D+28 por engano. Tambem exclui
                linhas cujo SOURCE_ID teve uma DISPUTE (essas liberam na hora por causa da disputa
                resolvida, nao pelo prazo normal de entrega - contaminaria a mediana pro lado
                curto demais).
             2) receita liquida diaria media dos ultimos 15 dias (por TRANSACTION_DATE, mesma janela
                usada no CMV de Previsao de Compra) - essa conta TODAS as linhas (pendente ou nao),
                porque a venda ja aconteceu independente de quando libera. */
          const idsComDisputa = new Set();
          linhas.forEach(l => { if ((l.TRANSACTION_TYPE || '').toUpperCase() === 'DISPUTE' && l.SOURCE_ID) idsComDisputa.add(l.SOURCE_ID); });
          const diasLag = [];
          const porDiaReceita = {};
          let dataMaisRecenteTx = null;
          linhas.forEach(l => {
            const tipo = (l.TRANSACTION_TYPE || '').toUpperCase();
            if (tipo !== 'SETTLEMENT' && tipo !== 'SETTLEMENT_SHIPPING') return;
            const dtTx = l.TRANSACTION_DATE ? new Date(l.TRANSACTION_DATE) : null;
            if (!dtTx || isNaN(dtTx.getTime())) return;
            if (!dataMaisRecenteTx || dtTx > dataMaisRecenteTx) dataMaisRecenteTx = dtTx;
            const jaLiberada = (l.IS_RELEASED || '').toUpperCase() === 'TRUE';
            const semDisputa = !l.SOURCE_ID || !idsComDisputa.has(l.SOURCE_ID);
            if (jaLiberada && semDisputa) {
              const dtRel = l.MONEY_RELEASE_DATE ? new Date(l.MONEY_RELEASE_DATE) : null;
              if (dtRel && !isNaN(dtRel.getTime())) {
                const lag = Math.round((dtRel.getTime() - dtTx.getTime()) / 864e5);
                if (lag >= 0) diasLag.push(lag);
              }
            }
            const v = parseFloat(l.SETTLEMENT_NET_AMOUNT);
            if (!isNaN(v)) {
              const diaTx = dtTx.toISOString().slice(0, 10);
              porDiaReceita[diaTx] = (porDiaReceita[diaTx] || 0) + v;
            }
          });
          let prazoLiberacaoDias = null;
          if (diasLag.length) {
            const ordenado = diasLag.slice().sort((a, b) => a - b);
            const meio = Math.floor(ordenado.length / 2);
            prazoLiberacaoDias = ordenado.length % 2 ? ordenado[meio] : Math.round((ordenado[meio - 1] + ordenado[meio]) / 2);
          }
          let receitaDiariaMedia = null;
          if (dataMaisRecenteTx) {
            const limite = new Date(dataMaisRecenteTx.getTime() - 15 * 864e5);
            const diasNoIntervalo = Object.keys(porDiaReceita).filter(d => new Date(d + 'T12:00:00Z') >= limite);
            if (diasNoIntervalo.length) {
              const total = diasNoIntervalo.reduce((s, d) => s + porDiaReceita[d], 0);
              receitaDiariaMedia = Math.round((total / diasNoIntervalo.length) * 100) / 100;
            }
          }
          await upsertFinanceiroMp(loja, {
            a_receber: aReceber, a_receber_atualizado_em: new Date(),
            areceber_report_id: null, areceber_pedido_em: null,
            agenda_liberacoes: agendaLiberacoes,
            prazo_liberacao_dias: prazoLiberacaoDias,
            receita_diaria_media: receitaDiariaMedia,
            receita_atualizado_em: new Date()
          });
          return;
        }
      }
    }
  } catch (e) {
    console.error('[financeiro-mp] falha ao tentar ler relatorio pronto (a-receber):', loja, e.message);
  }
  const PAUSA_ENTRE_PEDIDOS_MS = 10 * 60 * 1000;
  if (row && row.areceber_pedido_em && (Date.now() - new Date(row.areceber_pedido_em).getTime() < PAUSA_ENTRE_PEDIDOS_MS)) return;
  const dias = 60;
  const diaUTC = (d) => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const fmtSemMs = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');
  const fim = fimHojeBRT();
  const inicio = diaUTC(new Date(fim.getTime() - dias * 864e5));
  const r = await mpFetch(loja, '/v1/account/settlement_report', {
    method: 'POST',
    body: JSON.stringify({ begin_date: fmtSemMs(inicio), end_date: fmtSemMs(fim) })
  });
  const corpo = await r.json().catch(() => null);
  if (r.ok && corpo && corpo.id != null) {
    await upsertFinanceiroMp(loja, { areceber_report_id: String(corpo.id), areceber_pedido_em: new Date() });
  }
}
app.post('/financeiro/mp/sincronizar', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!tokenMpDaLoja(loja)) return res.json({ ok: true, loja, configurado: false });
    let row = await pegarFinanceiroMp(loja);
    try { await passoSaldoMp(loja, row); } catch (e) { console.error('[financeiro-mp] falha no passo saldo:', loja, e.message); }
    try { await passoAReceberMp(loja, row); } catch (e) { console.error('[financeiro-mp] falha no passo a receber:', loja, e.message); }
    row = await pegarFinanceiroMp(loja);
    const paraNumero = (v) => (v==null ? null : Number(v));
    res.json({
      ok: true, loja, configurado: true,
      saldoDisponivel: row ? paraNumero(row.saldo_disponivel) : null,
      saldoAtualizadoEm: row ? row.saldo_atualizado_em : null,
      aReceber: row ? paraNumero(row.a_receber) : null,
      aReceberAtualizadoEm: row ? row.a_receber_atualizado_em : null,
      agendaLiberacoes: row && row.agenda_liberacoes ? row.agenda_liberacoes : [],
      prazoLiberacaoDias: row ? paraNumero(row.prazo_liberacao_dias) : null,
      receitaDiariaMedia: row ? paraNumero(row.receita_diaria_media) : null,
      receitaAtualizadoEm: row ? row.receita_atualizado_em : null
    });
  } catch (e) {
    res.status(500).json({ ok: false, erro: e.message });
  }
});
app.get('/', (_req, res) => {
  res.type('text/plain').send('Doca <-> Mercado Livre sync backend. Veja /health.');
});
/* ---- app hospedado + dados na nuvem (v25) ----
   Serve o proprio Doca (arquivo estatico doca.html, salvo na raiz do projeto ao lado do
   server.js) numa URL fixa, protegida por login. E guarda o "estado" inteiro do Doca numa
   tabela de UMA linha so' (doca_estado, id sempre 1). */
app.get('/doca', exigirLogin, (_req, res) => {
  /* CORRIGIDO 01/09 (Felipe: FULL sumiram de novo; o irmao usa o Doca num notebook roteado pelo
     celular): sem no-store, o navegador guarda o proprio doca.html e pode ficar rodando uma VERSAO
     ANTIGA por tempo indeterminado - ainda mais em conexao instavel, onde o navegador prefere o
     cache. E uma versao antiga nao manda o "seAtualizadoEm", ou seja, nao passa pela protecao de
     conflito: ela grava por cima de tudo em silencio, com os dados velhos que tem na tela. Agora
     cada abertura busca a versao atual do servidor. */
  res.set('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'doca.html'), (err) => {
    if (err) res.status(404).send('doca.html nao encontrado no servidor - salve o arquivo do Doca na raiz do projeto (ao lado do server.js) com esse nome exato.');
  });
});
async function pegarEstadoNuvem() {
  const r = await pool.query('select dados, atualizado_em from doca_estado where id = 1');
  return r.rows[0] || null;
}
app.get('/estado', exigirLogin, async (req, res) => {
  /* CORRIGIDO 31/08 (3a volta - Felipe: mudanca feita no computador nao aparecia ao abrir no
     celular): sem Cache-Control, um GET repetido na mesma URL pode voltar do cache do navegador
     (comum em celular) em vez de ir ate o servidor de novo, mostrando dados velhos mesmo que o
     banco ja tenha o mais recente. Forca sempre buscar de novo. */
  res.set('Cache-Control', 'no-store');
  try {
    const linha = await pegarEstadoNuvem();
    if (!linha) return res.json({ ok: true, dados: null, atualizadoEm: null });
    res.json({ ok: true, dados: linha.dados, atualizadoEm: linha.atualizado_em });
  } catch (e) {
    res.status(500).json({ ok: false, erro: e.message });
  }
});
/* backup automatico antes de CADA gravacao - guarda o estado ANTERIOR numa tabela de historico:
     'rotativo' -> uma copia a cada gravacao, mantendo so as ultimas NUM_ROTATIVOS
     'horario'  -> 1 copia por hora, guardada por DIAS_GUARDAR_HORARIO dias
     'diario'   -> 1 copia por dia, guardada por mais tempo
   CORRIGIDO 31/08 (Felipe: tinha backup das ~16h aparecendo na lista, restaurou algumas vezes
   tentando achar o certo, e esses backups sumiram da lista pouco depois): NUM_ROTATIVOS era so'
   30 - numa sessao ativa (varios cliques, e cada tentativa de restaurar TAMBEM conta como uma
   gravacao nova) da' pra consumir 30 gravacoes em minutos, empurrando os backups bons pra fora
   da janela antes de alguem conseguir usa-los. 'diario' nao cobria esse buraco porque so' guarda
   o PRIMEIRO salvamento do dia (de manha', antes de qualquer coisa da tarde acontecer). Aumentado
   NUM_ROTATIVOS bastante e adicionado o nivel 'horario' (1 por hora, 14 dias) como uma rede de
   seguranca no meio do caminho entre o rotativo (fino, mas curto) e o diario (longo, mas grosso). */
const NUM_ROTATIVOS = 500;
const DIAS_GUARDAR_HORARIO = 14;
const DIAS_GUARDAR_DIARIO = 180;
/* CORRIGIDO 31/08 (Felipe: 'NAO SALVOU na nuvem: new row for relation "doca_estado_hist" violates
   check constraint "doca_estado_hist_tipo_check"'): a tabela foi criada com um CHECK que so' aceita
   os tipos antigos ('rotativo','diario'), entao o nivel novo 'horario' era recusado pelo banco - e
   como o backup roda ANTES da gravacao, isso derrubava a gravacao inteira junto. Solta o CHECK
   antigo e recria aceitando os tres tipos. Roda uma vez na subida do servidor e nao quebra se a
   tabela ainda nao existir ou se ja tiver sido ajustada antes. */
pool.query(`
  do $$
  begin
    if exists (select 1 from information_schema.tables where table_name = 'doca_estado_hist') then
      if exists (select 1 from information_schema.table_constraints
                 where table_name = 'doca_estado_hist' and constraint_name = 'doca_estado_hist_tipo_check') then
        alter table doca_estado_hist drop constraint doca_estado_hist_tipo_check;
      end if;
      alter table doca_estado_hist add constraint doca_estado_hist_tipo_check
        check (tipo in ('rotativo','horario','diario'));
    end if;
  end $$;
`).catch(e => console.error('Falha ao ajustar o check de doca_estado_hist:', e.message));
async function fazerBackupAntesDeGravar(dadosAntigos, atualizadoEmAntigo) {
  if (!dadosAntigos) return;
  await pool.query(
    `insert into doca_estado_hist (tipo, dados, criado_em) values ('rotativo', $1, coalesce($2, now()))`,
    [JSON.stringify(dadosAntigos), atualizadoEmAntigo || null]
  );
  const jaTemHorarioNestaHora = await pool.query(
    `select 1 from doca_estado_hist where tipo = 'horario' and date_trunc('hour', criado_em) = date_trunc('hour', now()) limit 1`
  );
  if (jaTemHorarioNestaHora.rowCount === 0) {
    await pool.query(
      `insert into doca_estado_hist (tipo, dados, criado_em) values ('horario', $1, coalesce($2, now()))`,
      [JSON.stringify(dadosAntigos), atualizadoEmAntigo || null]
    );
  }
  const jaTemDiarioHoje = await pool.query(
    `select 1 from doca_estado_hist where tipo = 'diario' and criado_em::date = now()::date limit 1`
  );
  if (jaTemDiarioHoje.rowCount === 0) {
    await pool.query(
      `insert into doca_estado_hist (tipo, dados, criado_em) values ('diario', $1, coalesce($2, now()))`,
      [JSON.stringify(dadosAntigos), atualizadoEmAntigo || null]
    );
  }
  await pool.query(
    `delete from doca_estado_hist where tipo = 'rotativo' and id not in (
       select id from doca_estado_hist where tipo = 'rotativo' order by criado_em desc limit $1
     )`,
    [NUM_ROTATIVOS]
  );
  await pool.query(
    `delete from doca_estado_hist where tipo = 'horario' and criado_em < now() - interval '${DIAS_GUARDAR_HORARIO} days'`
  );
  await pool.query(
    `delete from doca_estado_hist where tipo = 'diario' and criado_em < now() - interval '${DIAS_GUARDAR_DIARIO} days'`
  );
}
app.post('/estado', exigirLogin, async (req, res) => {
  try {
    const dados = req.body && req.body.dados;
    if (!dados || typeof dados !== 'object') return res.status(400).json({ ok: false, erro: 'Corpo precisa ter { dados: {...} }.' });
    const anterior = await pegarEstadoNuvem();
    /* CORRIGIDO 31/08 (Felipe: envios FULL programados sumiram - varios aparelhos abertos ao
       mesmo tempo, o mais antigo gravou por cima do mais novo sem avisar): antes so' o LADO DE
       LEITURA (verificarNuvem, no front) checava se outro aparelho tinha salvo algo mais novo -
       o lado de GRAVACAO nunca checava nada, entao um aparelho com a tela aberta ha' horas podia
       sobrescrever silenciosamente o que outro aparelho salvou depois. Agora o front manda junto
       o "seAtualizadoEm" (o timestamp que ELE acha que e' o mais recente, de quando carregou/
       salvou pela ultima vez) - se bater com o que esta' no banco agora, grava normal; se NAO
       bater, e' porque alguem gravou no meio do caminho - devolve 409 com os dados atuais do
       banco em vez de sobrescrever, e o front pergunta pra pessoa o que fazer (mesmo padrao de
       aviso que ja existia do lado da leitura). */
    /* CORRIGIDO 31/08 (4a volta - Felipe: "nao esta salvando mais nada, ele da a mensagem do que
       fez mas nao salva"): a comparacao era !== (igualdade exata em milissegundos). Basta o
       timestamp perder precisao em QUALQUER ponto do caminho (Postgres guarda microssegundos, o
       Date do JS so' vai ate milissegundo, e ainda passa por texto ISO na ida e na volta) pra
       nunca mais bater - e ai TODA gravacao virava conflito pra sempre, em qualquer aparelho,
       mesmo sem ninguem mais mexendo. Agora so' e' conflito de verdade se o banco estiver mais
       NOVO que o que o aparelho conhece, com uma folga de 1s pra absorver essa perda de precisao.
       Se o aparelho estiver igual ou a' frente, nao ha' nada pra proteger - grava normal. */
    /* CORRIGIDO 01/09 (mesma ocorrencia): a checagem so' rodava se o cliente MANDASSE o
       seAtualizadoEm - quem nao mandava passava direto e gravava por cima de tudo. Quem nao manda
       e' exatamente uma aba com versao antiga do Doca em cache (o caso do notebook roteado pelo
       celular). Agora, se ja' existe estado salvo e a gravacao chega sem timestamp e sem dizer
       explicitamente que e' pra sobrescrever (restauracao de backup / "usar os dados deste
       navegador"), ela e' recusada em vez de apagar o trabalho dos outros. */
    if (anterior && anterior.dados && req.body && !req.body.seAtualizadoEm && !req.body.sobrescreverMesmo) {
      return res.status(409).json({
        ok: false, conflito: true,
        erro: 'Esta aba esta rodando uma versao antiga do Doca (nao informa a versao dos dados que carregou). Recarregue a pagina com Ctrl+F5 antes de continuar - assim nada do que os outros salvaram e perdido.',
        dados: anterior.dados, atualizadoEm: anterior.atualizado_em
      });
    }
    if (anterior && req.body && req.body.seAtualizadoEm) {
      const doBanco = anterior.atualizado_em ? new Date(anterior.atualizado_em).getTime() : null;
      const doCliente = new Date(req.body.seAtualizadoEm).getTime();
      if (doBanco && !isNaN(doCliente) && doBanco > doCliente + 1000) {
        return res.status(409).json({ ok: false, conflito: true, erro: 'Outro aparelho salvou dados mais novos nesse meio tempo.', dados: anterior.dados, atualizadoEm: anterior.atualizado_em });
      }
    }
    /* CORRIGIDO 31/08 (mesma ocorrencia do check constraint): backup e' rede de seguranca, nao
       pode ser motivo pra NAO gravar. Se o backup falhar por qualquer motivo, registra o erro e
       segue gravando - perder um backup e' ruim, travar todas as gravacoes e' muito pior. */
    if (anterior && anterior.dados) {
      try {
        await fazerBackupAntesDeGravar(anterior.dados, anterior.atualizado_em);
      } catch (eBackup) {
        console.error('Falha ao gravar backup (a gravacao segue normalmente):', eBackup.message);
      }
    }
    await pool.query(
      `insert into doca_estado (id, dados, atualizado_em) values (1, $1, now())
       on conflict (id) do update set dados = excluded.dados, atualizado_em = excluded.atualizado_em`,
      [JSON.stringify(dados)]
    );
    const linha = await pegarEstadoNuvem();
    res.json({ ok: true, atualizadoEm: linha.atualizado_em });
  } catch (e) {
    res.status(500).json({ ok: false, erro: e.message });
  }
});
app.get('/estado/backups', exigirLogin, async (req, res) => {
  try {
    /* 31/08 (Felipe, envios FULL sumidos): agora traz tambem quantos envios cada backup tem
       (jsonb_array_length de dados->'envios'), igual ja fazia com produtos - antes a pessoa
       so' via a hora de cada backup e tinha que restaurar no escuro pra saber se tinha os envios
       de volta ou nao. Com essa coluna da' pra escanear a lista visualmente e achar o backup
       certo (o ultimo antes do numero de envios cair/zerar) sem precisar restaurar varias vezes
       tentando adivinhar. */
    const r = await pool.query(
      `select id, tipo, criado_em, jsonb_array_length(coalesce(dados->'produtos','[]'::jsonb)) as produtos,
              jsonb_array_length(coalesce(dados->'envios','[]'::jsonb)) as envios
       from doca_estado_hist order by criado_em desc limit 300`
    );
    res.json({ ok: true, backups: r.rows.map(x => ({ id: x.id, tipo: x.tipo, criadoEm: x.criado_em, produtos: x.produtos, envios: x.envios })) });
  } catch (e) {
    res.status(500).json({ ok: false, erro: e.message });
  }
});
app.get('/estado/backups/:id', exigirLogin, async (req, res) => {
  try {
    const r = await pool.query('select dados, criado_em from doca_estado_hist where id = $1', [req.params.id]);
    if (r.rowCount === 0) return res.status(404).json({ ok: false, erro: 'Backup nao encontrado.' });
    res.json({ ok: true, dados: r.rows[0].dados, criadoEm: r.rows[0].criado_em });
  } catch (e) {
    res.status(500).json({ ok: false, erro: e.message });
  }
});
app.get('/oauth/login', (req, res) => {
  const loja = req.query.loja;
  if (!LOJAS_VALIDAS.includes(loja)) {
    return res.status(400).send(`Parametro "loja" invalido ou ausente. Use um de: ${LOJAS_VALIDAS.join(', ')}`);
  }
  limparLoginsAntigos();
  const state = base64url(crypto.randomBytes(24));
  const { codeVerifier, codeChallenge } = gerarPkce();
  loginsPendentes.set(state, { loja, codeVerifier, criadoEm: Date.now() });
  const { clientId } = credenciaisDaLoja(loja);
  const url = new URL(ML_AUTH_DOMAIN + '/authorization');
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', ML_REDIRECT_URI);
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  res.redirect(url.toString());
});
app.get('/oauth/callback', async (req, res) => {
  try {
    const { code, state, error } = req.query;
    if (error) return res.status(400).send('Mercado Livre recusou a autorizacao: ' + error);
    const pendente = loginsPendentes.get(state);
    if (!pendente) return res.status(400).send('Sessao de login expirada ou invalida. Comece de novo pelo /oauth/login.');
    loginsPendentes.delete(state);
    const { clientId, clientSecret } = credenciaisDaLoja(pendente.loja);
    const resp = await fetch('https://api.mercadolibre.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: clientId,
        client_secret: clientSecret,
        code,
        redirect_uri: ML_REDIRECT_URI,
        code_verifier: pendente.codeVerifier
      })
    });
    const dados = await resp.json();
    if (!resp.ok) return res.status(400).send('Falha ao trocar o code pelo token: ' + JSON.stringify(dados));
    await salvarTokens(pendente.loja, dados);
    res.type('text/html').send(`<h2>Loja "${pendente.loja}" autorizada com sucesso.</h2><p>Pode fechar essa aba e voltar pro Doca.</p>`);
  } catch (e) {
    res.status(500).send('Erro no callback: ' + e.message);
  }
});
function extrairSku(it) {
  if (it.seller_custom_field) return it.seller_custom_field;
  if (it.seller_sku) return it.seller_sku;
  const attrs = it.attributes || [];
  const a = attrs.find(x => x.id === 'SELLER_SKU');
  if (a) return a.value_name || (a.values && a.values[0] && a.values[0].name) || '';
  return '';
}
async function buscarItensDoVendedor(loja, accessToken, mlUserId) {
  const ids = [];
  let offset = 0;
  const limit = 50;
  while (true) {
    const url = `https://api.mercadolibre.com/users/${mlUserId}/items/search?offset=${offset}&limit=${limit}`;
    const r = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
    const j = await r.json();
    if (!r.ok) throw new Error('Falha ao listar itens: ' + JSON.stringify(j));
    ids.push(...(j.results || []));
    offset += limit;
    if (!j.results || j.results.length < limit || offset >= (j.paging?.total || 0)) break;
  }
  const detalhes = [];
  for (let i = 0; i < ids.length; i += 20) {
    const lote = ids.slice(i, i + 20).join(',');
    const r = await fetch(`https://api.mercadolibre.com/items?ids=${lote}`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    const j = await r.json();
    if (!r.ok) throw new Error('Falha ao buscar detalhes dos itens: ' + JSON.stringify(j));
    j.forEach(entry => { if (entry.code === 200) detalhes.push(entry.body); });
  }
  return detalhes;
}
/* consulta se o anuncio catalogado esta perdendo ou empatando com outro vendedor na mesma
   pagina de catalogo. O ML desativou o endpoint que listava todos os concorrentes (10/2025);
   isso aqui usa o substituto oficial, que so diz se voce esta ganhando/perdendo/empatando
   e o preco de quem esta ganhando (nao a lista inteira de vendedores). */
async function buscarConcorrenciaCatalogo(accessToken, itemId) {
  try {
    const r = await fetch(`https://api.mercadolibre.com/items/${itemId}/price_to_win?siteId=MLB&version=v2`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    const j = await r.json();
    if (!r.ok) return null;
    return {
      status: j.status || null,
      precoConcorrente: (j.winner && typeof j.winner.price === 'number') ? j.winner.price : null
    };
  } catch (e) {
    return null;
  }
}
/* busca as perguntas sem resposta de todos os anuncios do vendedor de uma vez so (paginado),
   e devolve quantas tem por item_id. */
async function buscarPerguntasSemResposta(accessToken, sellerId) {
  const porItem = new Map();
  let offset = 0;
  const limit = 50;
  while (true) {
    const url = `https://api.mercadolibre.com/questions/search?seller_id=${sellerId}&status=UNANSWERED&api_version=4&limit=${limit}&offset=${offset}`;
    const r = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
    if (r.status === 404) break;
    const j = await r.json();
    if (!r.ok) throw new Error('Falha ao buscar perguntas: ' + JSON.stringify(j));
    const questions = j.questions || [];
    for (const q of questions) {
      if (!q.item_id) continue;
      porItem.set(q.item_id, (porItem.get(q.item_id) || 0) + 1);
    }
    offset += limit;
    if (questions.length < limit || offset >= (j.total || 0)) break;
  }
  return porItem;
}
/* dia calendario (AAAA-MM-DD) na hora de Brasilia. */
function diaBR(dataIso) {
  return new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Sao_Paulo' }).format(new Date(dataIso));
}
function diffDiasCivis(diaA, diaB) {
  return Math.round((Date.parse(diaA + 'T00:00:00Z') - Date.parse(diaB + 'T00:00:00Z')) / 864e5);
}
function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
/* fim do dia de HOJE em horario de Brasilia, convertido pra UTC real - usado nas janelas dos
   relatorios do Mercado Pago pra cobrir o dia inteiro ate' agora. */
function fimHojeBRT() {
  const agoraComoBRT = new Date(Date.now() - 3 * 3600 * 1000);
  const ano = agoraComoBRT.getUTCFullYear(), mes = agoraComoBRT.getUTCMonth(), dia = agoraComoBRT.getUTCDate();
  return new Date(Date.UTC(ano, mes, dia, 23, 59, 59) + 3 * 3600 * 1000);
}
/* chama o /orders/search com retry+backoff em 429 ("local_rate_limited"). */
async function buscarPaginaComRetry(url, accessToken, log, tentativa) {
  tentativa = tentativa || 0;
  const r = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  let j;
  try { j = await r.json(); } catch (e) { j = { error: 'resposta_invalida', message: 'corpo da resposta nao era JSON valido' }; }
  if (!r.ok) {
    const rateLimited = r.status === 429 || j.error === 'local_rate_limited' || j.message === 'local_rate_limited';
    /* alem do rate limit, tambem tenta de novo em erro 5xx (instabilidade passageira do lado do
       Mercado Livre, tipo "Oops! Something went wrong...") - encontrado em 21/08 com dado real: a
       Dor Block e a Orbix Brasil, por terem MUITO mais pedidos que TorvStore/TorvShop, precisam
       dividir a busca em bem mais paginas/intervalos (ver o "offset >= 950" mais abaixo) - isso
       aumenta a chance de pegar um 500 passageiro no meio do caminho, e antes disso NAO tentava de
       novo, so' desistia na hora - a venda inteira daquele sync ficava silenciosamente zerada
       (pega no catch generico do /sync, so' loga no servidor, o Doca nunca mostrava esse erro). */
    const erroPassageiro = rateLimited || r.status >= 500;
    if (erroPassageiro && tentativa < 5) {
      const espera = 800 * Math.pow(2, tentativa);
      if (log) log.avisos.push(`${rateLimited ? 'rate limit (429)' : 'erro ' + r.status + ' do Mercado Livre'} na busca de pedidos - tentativa ${tentativa + 1}/5, esperando ${espera}ms`);
      await sleep(espera);
      return buscarPaginaComRetry(url, accessToken, log, tentativa + 1);
    }
    throw new Error('Falha ao buscar pedidos: ' + JSON.stringify(j));
  }
  return j;
}
async function buscarPedidosNoIntervalo(accessToken, sellerId, deIso, ateIso, log, campoData) {
  campoData = campoData || 'order.date_created';
  const limit = 50;
  let offset = 0;
  let total = null;
  const pedidos = [];
  while (true) {
    const url = `https://api.mercadolibre.com/orders/search?seller=${sellerId}&${campoData}.from=${encodeURIComponent(deIso)}&${campoData}.to=${encodeURIComponent(ateIso)}&offset=${offset}&limit=${limit}`;
    const j = await buscarPaginaComRetry(url, accessToken, log);
    total = (j.paging && j.paging.total) || 0;
    const pagina = j.results || [];
    pedidos.push(...pagina);
    offset += limit;
    if (pagina.length < limit || offset >= total) break;
    await sleep(120);
    if (offset >= 950) {
      log.avisos.push(`intervalo ${deIso}..${ateIso} tem ${total} pedidos, perto do teto de 1000 - dividindo`);
      const meio = new Date((new Date(deIso).getTime() + new Date(ateIso).getTime()) / 2).toISOString();
      const [a, b] = await Promise.all([
        buscarPedidosNoIntervalo(accessToken, sellerId, deIso, meio, log, campoData),
        buscarPedidosNoIntervalo(accessToken, sellerId, meio, ateIso, log, campoData)
      ]);
      const vistos = new Set(pedidos.map(p => p.id));
      return pedidos.concat(a.filter(p => !vistos.has(p.id)), b.filter(p => !vistos.has(p.id) && !a.some(x => x.id === p.id)));
    }
  }
  return pedidos;
}
function inicioDoDiaBR(instanteMs) {
  const dia = diaBR(new Date(instanteMs).toISOString());
  return Date.parse(dia + 'T00:00:00-03:00');
}
/* logica de contagem de vendas, unica fonte de verdade usada tanto pelo /sync quanto pela rota
   de auditoria /debug/vendas. Janelas sao dias civis FECHADOS (fuso America/Sao_Paulo). */
function processarVendas(pedidos, { itemIdFiltro } = {}) {
  const fim = inicioDoDiaBR(Date.now());
  const inicio7 = fim - 7 * 864e5;
  const inicio15 = fim - 15 * 864e5;
  const inicio30 = fim - 30 * 864e5;
  const statusExcluidos = new Set(['cancelled', 'invalid']);
  const porItem = new Map();
  const detalhe = [];
  const porStatus = {};
  for (const pedido of pedidos) {
    porStatus[pedido.status] = (porStatus[pedido.status] || 0) + 1;
    let contado = true;
    let motivo = null;
    let dataUsada = null;
    let fonteData = null;
    if (statusExcluidos.has(pedido.status)) {
      contado = false; motivo = `status=${pedido.status}`;
    } else if (pedido.date_closed) {
      dataUsada = new Date(pedido.date_closed).getTime();
      fonteData = 'date_closed';
    } else if (pedido.date_created) {
      dataUsada = new Date(pedido.date_created).getTime();
      fonteData = 'date_created (pagamento ainda nao fechou)';
    } else {
      contado = false; motivo = 'sem date_closed nem date_created';
    }
    if (contado && (dataUsada < inicio30 || dataUsada >= fim)) {
      contado = false; motivo = `${fonteData} fora da janela de 30d`;
    }
    for (const oi of (pedido.order_items || [])) {
      const itemId = oi.item && oi.item.id;
      if (!itemId) continue;
      if (itemIdFiltro && itemId !== itemIdFiltro) continue;
      const qtd = oi.quantity || 0;
      if (contado) {
        if (!porItem.has(itemId)) porItem.set(itemId, { v7: 0, v15: 0, v30: 0 });
        const acc = porItem.get(itemId);
        if (dataUsada >= inicio30 && dataUsada < fim) acc.v30 += qtd;
        if (dataUsada >= inicio15 && dataUsada < fim) acc.v15 += qtd;
        if (dataUsada >= inicio7 && dataUsada < fim) acc.v7 += qtd;
      }
      if (itemIdFiltro) {
        detalhe.push({
          id: pedido.id,
          status: pedido.status,
          status_detail: pedido.status_detail || null,
          date_created: pedido.date_created,
          date_closed: pedido.date_closed,
          date_last_updated: pedido.date_last_updated || null,
          pack_id: pedido.pack_id || null,
          tags: pedido.tags || [],
          item_id: itemId,
          qtd,
          contado,
          fonte_data: fonteData,
          motivo
        });
      }
    }
  }
  return {
    porItem, detalhe, porStatus,
    janela: {
      fim: new Date(fim).toISOString(),
      inicio7: new Date(inicio7).toISOString(),
      inicio15: new Date(inicio15).toISOString(),
      inicio30: new Date(inicio30).toISOString()
    }
  };
}
/* busca pedidos por date_closed E por date_created, juntando sem duplicar - assim conta tambem
   pedido que ainda nao fechou pagamento, pra previsao de reposicao. */
async function buscarPedidosComPendentes(accessToken, sellerId, de, ate, log) {
  const porFechamento = await buscarPedidosNoIntervalo(accessToken, sellerId, de, ate, log, 'order.date_closed');
  const porCriacao = await buscarPedidosNoIntervalo(accessToken, sellerId, de, ate, log, 'order.date_created');
  const vistos = new Set();
  const pedidos = [];
  for (const p of porFechamento.concat(porCriacao)) {
    if (vistos.has(p.id)) continue;
    vistos.add(p.id);
    pedidos.push(p);
  }
  return pedidos;
}
async function buscarVendasPorItem(accessToken, sellerId) {
  const fim = inicioDoDiaBR(Date.now());
  const de = new Date(fim - 31 * 864e5).toISOString();
  const ate = new Date(fim).toISOString();
  const log = { avisos: [] };
  const pedidos = await buscarPedidosComPendentes(accessToken, sellerId, de, ate, log);
  const { porItem, porStatus } = processarVendas(pedidos);
  console.log(`[vendas] pedidos buscados=${pedidos.length} status=${JSON.stringify(porStatus)}${log.avisos.length ? ' avisos=' + JSON.stringify(log.avisos) : ''}`);
  const top5 = [...porItem.entries()].sort((a, b) => b[1].v30 - a[1].v30).slice(0, 5)
    .map(([id, v]) => `${id}:v7=${v.v7}/v15=${v.v15}/v30=${v.v30}`).join(' | ');
  console.log(`[vendas][top5] ${top5}`);
  return porItem;
}
/* quantidade em transferencia entre depositos do Full, pro item que ja tem inventory_id. */
async function buscarTransferenciaFull(accessToken, sellerId, inventoryId) {
  try {
    const r = await fetch(`https://api.mercadolibre.com/inventories/${inventoryId}/stock/fulfillment?seller_id=${sellerId}`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (!r.ok) return null;
    const j = await r.json();
    const detalhe = (j.not_available_detail || []).find(d => d.status === 'transfer');
    return detalhe ? (detalhe.quantity || 0) : 0;
  } catch (e) {
    return null;
  }
}
/* "Entrada Pendente 2.0" (28/08, pedido do Felipe: "existe possibilidade melhor?" depois de eu
   ter implementado uma estimativa por delta de aptas+transferencia). Achado real 28/08: o Mercado
   Livre TEM um endpoint de log de operacoes de estoque do Full
   (/stock/fulfillment/operations/search, documentado em developers.mercadolivre.com.br/en_us/
   fulfillment), incluindo o tipo inbound_reception - "entrada de estoque" de verdade, com data e
   quantidade, sem se confundir com venda/ajuste no meio do caminho (diferente de so' olhar o total
   de aptas+transferencia subir/descer, que mistura tudo). So' chama pra itens que o front avisa que
   tem algo "em processamento" pendente (ver pendentes= no /sync) - pra nao gastar chamada de API
   (e tempo de sync) em item sem nada esperando confirmacao. Retorna [{data:'YYYY-MM-DD', qtd}]. */
async function buscarRecebimentosFull(accessToken, sellerId, inventoryId, diasAtras) {
  try {
    const hj = new Date();
    const de = new Date(hj.getTime() - (diasAtras || 6) * 864e5);
    const fmt = d => d.toISOString().slice(0, 10);
    const url = `https://api.mercadolibre.com/stock/fulfillment/operations/search?seller_id=${sellerId}&inventory_id=${inventoryId}&date_from=${fmt(de)}&date_to=${fmt(hj)}&type=inbound_reception`;
    const r = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
    if (!r.ok) return null;
    const j = await r.json();
    return (j.results || [])
      .map(op => ({ data: (op.date_created || '').slice(0, 10), qtd: (op.detail && op.detail.available_quantity) || 0 }))
      .filter(x => x.data && x.qtd > 0);
  } catch (e) {
    return null;
  }
}
app.get('/debug/full/estoque', async (req, res) => {
  try {
    const loja = req.query.loja;
    const sku = req.query.sku;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!sku) return res.status(400).json({ ok: false, erro: 'Parametro "sku" obrigatorio.' });
    const rProd = await pool.query('select ml_item_id, sku, titulo from ml_produtos where loja = $1 and lower(sku) = lower($2)', [loja, sku]);
    if (!rProd.rows.length) return res.status(404).json({ ok: false, erro: `Nenhum produto com sku "${sku}" encontrado na loja ${loja} (ver /data?loja=...).` });
    const { ml_item_id, titulo } = rProd.rows[0];
    const accessToken = await tokenValido(loja);
    const rItem = await fetch(`https://api.mercadolibre.com/items/${ml_item_id}`, { headers: { Authorization: `Bearer ${accessToken}` } });
    const item = await rItem.json();
    if (!rItem.ok) return res.status(200).json({ ok: false, erro: 'Falha ao buscar o item.', http_status: rItem.status, corpo: item });
    if (!item.inventory_id) return res.status(200).json({ ok: false, erro: 'Esse item nao tem inventory_id (nao e Full, ou nao esta vinculado ao Full).', item_id: ml_item_id, titulo, logistic_type: item.shipping && item.shipping.logistic_type });
    const rInv = await fetch(`https://api.mercadolibre.com/inventories/${item.inventory_id}/stock/fulfillment?seller_id=${item.seller_id}`, { headers: { Authorization: `Bearer ${accessToken}` } });
    const inv = await rInv.json();
    res.status(200).json({
      ok: true, loja, sku, ml_item_id, titulo, inventory_id: item.inventory_id, seller_id: item.seller_id,
      logistic_type: item.shipping && item.shipping.logistic_type,
      available_quantity_item: item.available_quantity,
      inventario_cru: inv
    });
  } catch (e) { res.status(500).json({ ok: false, erro: e.message }); }
});
/* 21/08 (pedido real do Felipe): "ver TODA informacao disponivel na API e um relatorio das
   possibilidades" - chama de uma vez varios dos principais recursos do Mercado Livre relacionados
   a UM produto (item cru, descricao, visitas, vendedor/conta, categoria + atributos dela, e um
   pedido+envio recente pra amostra) e devolve o JSON CRU de cada um, sem filtrar nenhum campo. Cada
   secao roda isolada (uma falhando nao derruba as outras) pra dar pra ver o maximo possivel numa
   chamada so. */
async function tentarChamadaMl(fn) {
  try { return { ok: true, dados: await fn() }; }
  catch (e) { return { ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo }; }
}
app.get('/debug/relatorio-api-completo', async (req, res) => {
  try {
    const loja = req.query.loja;
    const sku = req.query.sku;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!sku) return res.status(400).json({ ok: false, erro: 'Parametro "sku" obrigatorio.' });
    const rProd = await pool.query('select ml_item_id, sku, titulo from ml_produtos where loja = $1 and lower(sku) = lower($2)', [loja, sku]);
    if (!rProd.rows.length) return res.status(404).json({ ok: false, erro: `Nenhum produto com sku "${sku}" encontrado na loja ${loja} (ver /data?loja=...).` });
    const { ml_item_id } = rProd.rows[0];
    const accessToken = await tokenValido(loja);
    const conta = await pegarConta(loja);
    const sellerId = conta.ml_user_id;
    const auth = { headers: { Authorization: `Bearer ${accessToken}` } };

    const item = await tentarChamadaMl(() => fetchMLDebug(`https://api.mercadolibre.com/items/${ml_item_id}`, auth));
    const categoriaId = item.ok ? item.dados.category_id : null;

    const [descricao, visitas, vendedor, categoria, atributosCategoria, pedidoBusca] = await Promise.all([
      tentarChamadaMl(() => fetchMLDebug(`https://api.mercadolibre.com/items/${ml_item_id}/description`, auth)),
      tentarChamadaMl(() => fetchMLDebug(`https://api.mercadolibre.com/items/${ml_item_id}/visits/time_window?last=30&unit=day`, auth)),
      tentarChamadaMl(() => fetchMLDebug(`https://api.mercadolibre.com/users/${sellerId}`, auth)),
      categoriaId ? tentarChamadaMl(() => fetchMLDebug(`https://api.mercadolibre.com/categories/${categoriaId}`, auth)) : Promise.resolve({ ok: false, erro: 'item sem category_id' }),
      categoriaId ? tentarChamadaMl(() => fetchMLDebug(`https://api.mercadolibre.com/categories/${categoriaId}/attributes`, auth)) : Promise.resolve({ ok: false, erro: 'item sem category_id' }),
      tentarChamadaMl(() => fetchMLDebug(`https://api.mercadolibre.com/orders/search?seller=${sellerId}&sort=date_desc&limit=1`, auth))
    ]);

    let pedidoDetalhe = { ok: false, erro: 'nenhum pedido encontrado pra essa loja' };
    let envioDetalhe = { ok: false, erro: 'sem pedido/envio pra buscar' };
    if (pedidoBusca.ok && pedidoBusca.dados.results && pedidoBusca.dados.results[0]) {
      const pedidoId = pedidoBusca.dados.results[0].id;
      pedidoDetalhe = await tentarChamadaMl(() => fetchMLDebug(`https://api.mercadolibre.com/orders/${pedidoId}`, auth));
      const shippingId = pedidoDetalhe.ok && pedidoDetalhe.dados.shipping && pedidoDetalhe.dados.shipping.id;
      if (shippingId) envioDetalhe = await tentarChamadaMl(() => fetchMLDebug(`https://api.mercadolibre.com/shipments/${shippingId}`, auth));
    }

    res.status(200).json({
      ok: true, loja, sku, ml_item_id, seller_id: sellerId,
      item, descricao, visitas, vendedor, categoria, atributos_categoria: atributosCategoria,
      pedido_busca: pedidoBusca, pedido_detalhe: pedidoDetalhe, envio_detalhe: envioDetalhe
    });
  } catch (e) {
    console.error('Erro no /debug/relatorio-api-completo:', e);
    res.status(500).json({ ok: false, erro: e.message });
  }
});
/* ---------- Mercado Ads (Product Ads) ---------- */
const ADS_METRICAS = [
  'clicks', 'prints', 'ctr', 'cost', 'cpc', 'acos', 'organic_units_quantity', 'organic_units_amount',
  'organic_items_quantity', 'direct_items_quantity', 'indirect_items_quantity', 'advertising_items_quantity',
  'cvr', 'roas', 'sov', 'direct_units_quantity', 'indirect_units_quantity', 'units_quantity', 'direct_amount',
  'indirect_amount', 'total_amount', 'impression_share', 'top_impression_share',
  'lost_impression_share_by_budget', 'lost_impression_share_by_ad_rank', 'acos_benchmark'
].join(',');
async function fetchMLDebug(url, opts) {
  const r = await fetch(url, opts);
  const bruto = await r.text();
  let corpo = bruto;
  try { corpo = bruto ? JSON.parse(bruto) : null; } catch (e) { /* nao era JSON - mantem texto cru */ }
  if (!r.ok) {
    const e = new Error(`A API do Mercado Livre respondeu status ${r.status} em ${url.split('?')[0]}`);
    e.http_status = r.status; e.corpo = corpo; e.corpo_bruto = bruto.slice(0, 500);
    throw e;
  }
  if (corpo === null) { const e = new Error('A API respondeu com o corpo vazio (status ' + r.status + ').'); e.http_status = r.status; throw e; }
  return corpo;
}
async function buscarAdvertiserId(loja) {
  const accessToken = await tokenValido(loja);
  const conta = await pegarConta(loja);
  const url = `https://api.mercadolibre.com/advertising/advertisers?product_id=PADS&user_id=${conta.ml_user_id}`;
  const j = await fetchMLDebug(url, { headers: { Authorization: `Bearer ${accessToken}`, 'Api-Version': '2' } });
  const advertisers = j.advertisers || [];
  return { advertisers, primeiro: advertisers[0] || null };
}
function dataYMD(d) { return new Date(d).toISOString().slice(0, 10); }
async function buscarCampanhasAds(loja, siteId, advertiserId, dias, deAteCustom) {
  const accessToken = await tokenValido(loja);
  const de = (deAteCustom && deAteCustom.de) || dataYMD(Date.now() - (dias - 1) * 864e5);
  const ate = (deAteCustom && deAteCustom.ate) || dataYMD(Date.now());
  let metricas = ADS_METRICAS.split(',');
  const removidas = [];
  const LIMIT = 50;
  async function buscarPagina(offset) {
    for (let tentativa = 0; tentativa < 15; tentativa++) {
      const url = `https://api.mercadolibre.com/marketplace/advertising/${siteId}/advertisers/${advertiserId}/product_ads/campaigns/search?limit=${LIMIT}&offset=${offset}&date_from=${de}&date_to=${ate}&metrics=${metricas.join(',')}`;
      try {
        return await fetchMLDebug(url, { headers: { Authorization: `Bearer ${accessToken}`, 'Api-Version': '2' } });
      } catch (e) {
        const desc = (e.corpo && e.corpo.description) || '';
        const m = desc.match(/Field (\w+) not allowed/i);
        if (e.http_status === 400 && m) {
          const campo = m[1].toLowerCase();
          const idx = metricas.indexOf(campo);
          if (idx >= 0) { metricas.splice(idx, 1); removidas.push(campo); continue; }
        }
        if ((e.http_status === 429 || e.http_status >= 500) && tentativa < 5) {
          await sleep(500 * (tentativa + 1));
          continue;
        }
        throw e;
      }
    }
    throw new Error('Muitas metricas invalidas seguidas - parei de tentar. Removidas: ' + removidas.join(', '));
  }
  const primeira = await buscarPagina(0);
  let todosResultados = (primeira.results || []).slice();
  let ultimaResposta = primeira;
  const total = (primeira.paging && primeira.paging.total) || 0;
  let avisoPaginacao = null;
  let offset = LIMIT;
  try {
    while (primeira.results && primeira.results.length === LIMIT && offset < total && offset < 5000) {
      await sleep(200);
      const pagina = await buscarPagina(offset);
      ultimaResposta = pagina;
      todosResultados = todosResultados.concat(pagina.results || []);
      if (!pagina.results || pagina.results.length < LIMIT) break;
      offset += LIMIT;
    }
  } catch (e) {
    avisoPaginacao = `Parou de paginar campanhas no offset ${offset} (motivo: ${e.message}) - a lista pode estar incompleta, mas o que ja tinha sido buscado foi mantido.`;
  }
  const resultado = Object.assign({}, ultimaResposta, { results: todosResultados });
  if (removidas.length) resultado._metricas_removidas_pela_api = removidas;
  if (avisoPaginacao) resultado._aviso_paginacao = avisoPaginacao;
  return resultado;
}
async function buscarItensAdsPeriodo(loja, siteId, advertiserId, de, ate, campaignIdSugerido) {
  const accessToken = await tokenValido(loja);
  const LIMIT = 50;
  let campaignIdQualquer = campaignIdSugerido || null;
  if (!campaignIdQualquer) {
    try {
      const campanhas = await buscarCampanhasAds(loja, siteId, advertiserId, null, { de, ate });
      campaignIdQualquer = (campanhas.results && campanhas.results[0] && campanhas.results[0].id) || null;
    } catch (e) { /* segue sem - tenta a busca de itens mesmo assim */ }
  }
  async function buscarPagina(offset) {
    const qs = new URLSearchParams({ date_from: de, date_to: ate, metrics: 'cost,clicks,prints', limit: String(LIMIT), offset: String(offset) });
    if (campaignIdQualquer) qs.set('campaign_id', campaignIdQualquer);
    const url = `https://api.mercadolibre.com/marketplace/advertising/${siteId}/advertisers/${advertiserId}/product_ads/ads/search?${qs.toString()}`;
    for (let tentativa = 0; tentativa < 6; tentativa++) {
      try {
        return await fetchMLDebug(url, { headers: { Authorization: `Bearer ${accessToken}`, 'Api-Version': '2' } });
      } catch (e) {
        if ((e.http_status === 429 || e.http_status >= 500) && tentativa < 5) { await sleep(500 * (tentativa + 1)); continue; }
        throw e;
      }
    }
  }
  const primeira = await buscarPagina(0);
  let todos = (primeira.results || []).slice();
  const total = (primeira.paging && primeira.paging.total) || 0;
  let offset = LIMIT;
  try {
    while (primeira.results && primeira.results.length === LIMIT && offset < total && offset < 5000) {
      await sleep(200);
      const pagina = await buscarPagina(offset);
      todos = todos.concat(pagina.results || []);
      if (!pagina.results || pagina.results.length < LIMIT) break;
      offset += LIMIT;
    }
  } catch (e) { /* fica com as paginas que ja tinha conseguido */ }
  const porItem = new Map();
  for (const it of todos) {
    const m = it.metrics || {};
    const atual = porItem.get(it.item_id) || { itemId: it.item_id, cost: 0, clicks: 0, prints: 0, campaignId: it.campaign_id };
    atual.cost += m.cost || 0;
    atual.clicks += m.clicks || 0;
    atual.prints += m.prints || 0;
    porItem.set(it.item_id, atual);
  }
  return [...porItem.values()];
}
app.get('/debug/ads/advertiser', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido (recebi: ${JSON.stringify(loja || null)}). Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const { advertisers, primeiro } = await buscarAdvertiserId(loja);
    res.json({ ok: true, loja, advertisers, advertiser_id_sugerido: primeiro && primeiro.advertiser_id });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo, corpo_bruto: e.corpo_bruto }); }
});
app.get('/debug/ads/campanhas', async (req, res) => {
  try {
    const loja = req.query.loja;
    const dias = parseInt(req.query.dias || '30', 10);
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido (recebi: ${JSON.stringify(loja || null)}). Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    let advertiserId = req.query.advertiserId;
    let siteId = req.query.siteId;
    if (!advertiserId || !siteId) {
      const { primeiro } = await buscarAdvertiserId(loja);
      if (!primeiro) return res.status(200).json({ ok: false, erro: 'Nenhum advertiser_id encontrado pra essa loja (ver /debug/ads/advertiser).' });
      advertiserId = advertiserId || primeiro.advertiser_id;
      siteId = siteId || primeiro.site_id;
    }
    const campanhas = await buscarCampanhasAds(loja, siteId, advertiserId, dias);
    res.json({ ok: true, loja, siteId, advertiserId, dias, campanhas });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo, corpo_bruto: e.corpo_bruto }); }
});
app.get('/debug/ads/leiloes', async (req, res) => {
  try {
    const loja = req.query.loja;
    const campanhaId = req.query.campanhaId;
    const dias = parseInt(req.query.dias || '30', 10);
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!campanhaId) return res.status(400).json({ ok: false, erro: 'Parametro "campanhaId" obrigatorio (pegue um "id" de campanha no /debug/ads/campanhas).' });
    const accessToken = await tokenValido(loja);
    const { primeiro } = await buscarAdvertiserId(loja);
    const siteId = primeiro && primeiro.site_id;
    const advertiserId = primeiro && primeiro.advertiser_id;
    const de = dataYMD(Date.now() - (dias - 1) * 864e5);
    const ate = dataYMD(Date.now());
    const metricas = 'impression_share,top_impression_share,lost_impression_share_by_budget,lost_impression_share_by_ad_rank,clicks,prints,cost';
    const candidatos = [
      { nome: 'novo prefixo, singular, sem /search', url: `https://api.mercadolibre.com/marketplace/advertising/${siteId}/advertisers/${advertiserId}/product_ads/campaigns/${campanhaId}?date_from=${de}&date_to=${ate}&metrics=${metricas}` },
      { nome: 'novo prefixo, singular, com /search', url: `https://api.mercadolibre.com/marketplace/advertising/${siteId}/advertisers/${advertiserId}/product_ads/campaigns/${campanhaId}/search?date_from=${de}&date_to=${ate}&metrics=${metricas}` },
      { nome: 'prefixo antigo (advertisers/id), singular', url: `https://api.mercadolibre.com/advertising/advertisers/${advertiserId}/product_ads/campaigns/${campanhaId}?date_from=${de}&date_to=${ate}&metrics=${metricas}` },
      { nome: 'endpoint de busca em lote filtrando por 1 campanha', url: `https://api.mercadolibre.com/marketplace/advertising/${siteId}/advertisers/${advertiserId}/product_ads/campaigns/search?campaign_ids=${campanhaId}&date_from=${de}&date_to=${ate}&metrics=${metricas}` }
    ];
    const tentativas = [];
    for (const cand of candidatos) {
      try {
        const j = await fetchMLDebug(cand.url, { headers: { Authorization: `Bearer ${accessToken}`, 'Api-Version': '2' } });
        return res.json({ ok: true, loja, campanhaId, dias, funcionou: cand.nome, url: cand.url, resultado: j, tentativas_anteriores: tentativas });
      } catch (e) {
        tentativas.push({ nome: cand.nome, url: cand.url, http_status: e.http_status, erro: e.message, corpo: e.corpo });
      }
    }
    res.json({ ok: false, erro: 'Nenhum dos formatos de endpoint testados funcionou.', tentativas });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo, corpo_bruto: e.corpo_bruto }); }
});
app.get('/debug/ads/itens-campanha', async (req, res) => {
  try {
    const loja = req.query.loja;
    let campanhaId = req.query.campanhaId;
    const nome = req.query.nome;
    const dias = parseInt(req.query.dias || '30', 10);
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!campanhaId && !nome) return res.status(400).json({ ok: false, erro: 'Informe "campanhaId" (pegue no /debug/ads/campanhas) ou "nome" (parte do nome da campanha, ex.: nome=ALHO).' });
    const accessToken = await tokenValido(loja);
    const { primeiro } = await buscarAdvertiserId(loja);
    const siteId = primeiro && primeiro.site_id;
    const advertiserId = primeiro && primeiro.advertiser_id;
    const de = dataYMD(Date.now() - (dias - 1) * 864e5);
    const ate = dataYMD(Date.now());
    let campanhaEncontrada = null;
    if (!campanhaId && nome) {
      const campanhas = await buscarCampanhasAds(loja, siteId, advertiserId, dias);
      const nomeNorm = nome.toUpperCase();
      const achadas = (campanhas.results || []).filter(c => (c.name || '').toUpperCase().includes(nomeNorm));
      if (!achadas.length) return res.json({ ok: false, erro: `Nenhuma campanha com "${nome}" no nome nos ultimos ${dias} dia(s).`, nomes_disponiveis: (campanhas.results || []).map(c => c.name) });
      campanhaEncontrada = achadas[0];
      campanhaId = achadas[0].id;
      if (achadas.length > 1) campanhaEncontrada = { aviso: `${achadas.length} campanhas bateram com "${nome}" - usando a primeira.`, escolhida: achadas[0], todas: achadas.map(c => ({ id: c.id, name: c.name })) };
    }
    const metricas = 'cost,clicks,prints';
    const candidatos = [
      { nome: 'ads (novo prefixo) - lista de anuncios da campanha', url: `https://api.mercadolibre.com/marketplace/advertising/${siteId}/advertisers/${advertiserId}/product_ads/campaigns/${campanhaId}/ads?date_from=${de}&date_to=${ate}&metrics=${metricas}` },
      { nome: 'ads (novo prefixo) - com /search', url: `https://api.mercadolibre.com/marketplace/advertising/${siteId}/advertisers/${advertiserId}/product_ads/campaigns/${campanhaId}/ads/search?date_from=${de}&date_to=${ate}&metrics=${metricas}` },
      { nome: 'items (novo prefixo)', url: `https://api.mercadolibre.com/marketplace/advertising/${siteId}/advertisers/${advertiserId}/product_ads/campaigns/${campanhaId}/items?date_from=${de}&date_to=${ate}&metrics=${metricas}` },
      { nome: 'ads (prefixo antigo, advertisers/id)', url: `https://api.mercadolibre.com/advertising/advertisers/${advertiserId}/product_ads/campaigns/${campanhaId}/ads?date_from=${de}&date_to=${ate}&metrics=${metricas}` },
      { nome: 'items (prefixo antigo)', url: `https://api.mercadolibre.com/advertising/advertisers/${advertiserId}/product_ads/campaigns/${campanhaId}/items?date_from=${de}&date_to=${ate}&metrics=${metricas}` },
      { nome: 'product_ads direto (sem campanha) filtrando por campaign_id', url: `https://api.mercadolibre.com/marketplace/advertising/${siteId}/advertisers/${advertiserId}/product_ads/ads/search?campaign_id=${campanhaId}&date_from=${de}&date_to=${ate}&metrics=${metricas}` }
    ];
    const tentativas = [];
    for (const cand of candidatos) {
      try {
        const j = await fetchMLDebug(cand.url, { headers: { Authorization: `Bearer ${accessToken}`, 'Api-Version': '2' } });
        return res.json({ ok: true, loja, campanhaId, campanha: campanhaEncontrada, dias, funcionou: cand.nome, url: cand.url, resultado: j, tentativas_anteriores: tentativas });
      } catch (e) {
        tentativas.push({ nome: cand.nome, url: cand.url, http_status: e.http_status, erro: e.message, corpo: e.corpo });
      }
    }
    res.json({ ok: false, erro: 'Nenhum dos formatos de endpoint testados funcionou.', campanhaId, campanha: campanhaEncontrada, tentativas });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo, corpo_bruto: e.corpo_bruto }); }
});
app.get('/debug/ads/metrica', async (req, res) => {
  try {
    const loja = req.query.loja;
    const campanhaId = req.query.campanhaId;
    const dias = parseInt(req.query.dias || '7', 10);
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!campanhaId) return res.status(400).json({ ok: false, erro: 'Parametro "campanhaId" obrigatorio (pegue um "id" de campanha no /debug/ads/campanhas).' });
    const accessToken = await tokenValido(loja);
    const { primeiro } = await buscarAdvertiserId(loja);
    const siteId = primeiro && primeiro.site_id;
    const advertiserId = primeiro && primeiro.advertiser_id;
    const de = dataYMD(Date.now() - (dias - 1) * 864e5);
    const ate = dataYMD(Date.now());
    const candidatos = (req.query.campos || 'lost_impression_share_by_budget,lost_impression_share_by_ad_rank,top_impression_share,impression_share,acos_benchmark')
      .split(',').map(s => s.trim()).filter(Boolean);
    const resultado = {};
    for (const campo of candidatos) {
      const metricas = `cost,clicks,prints,${campo}`;
      const url = `https://api.mercadolibre.com/marketplace/advertising/${siteId}/advertisers/${advertiserId}/product_ads/campaigns/search?campaign_ids=${campanhaId}&date_from=${de}&date_to=${ate}&metrics=${metricas}`;
      try {
        const j = await fetchMLDebug(url, { headers: { Authorization: `Bearer ${accessToken}`, 'Api-Version': '2' } });
        const m = (j.results && j.results[0] && j.results[0].metrics) || null;
        resultado[campo] = { ok: true, valor: m && (campo in m) ? m[campo] : m };
      } catch (e) {
        resultado[campo] = { ok: false, http_status: e.http_status, erro: e.message, corpo: e.corpo };
      }
    }
    res.json({ ok: true, loja, campanhaId, dias, resultado });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo, corpo_bruto: e.corpo_bruto }); }
});
app.get('/debug/ads/diario', async (req, res) => {
  try {
    const loja = req.query.loja;
    const campanhaId = req.query.campanhaId;
    const dias = parseInt(req.query.dias || '7', 10);
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!campanhaId) return res.status(400).json({ ok: false, erro: 'Parametro "campanhaId" obrigatorio (pegue um "id" de campanha no /debug/ads/campanhas).' });
    const accessToken = await tokenValido(loja);
    const { primeiro } = await buscarAdvertiserId(loja);
    const siteId = primeiro && primeiro.site_id;
    const advertiserId = primeiro && primeiro.advertiser_id;
    const de = dataYMD(Date.now() - (dias - 1) * 864e5);
    const ate = dataYMD(Date.now());
    let metricas = (req.query.metricas || 'cost,clicks,prints,sov,direct_amount,indirect_amount,total_amount,organic_units_amount,organic_units_quantity,units_quantity,roas,acos').split(',').map(s => s.trim()).filter(Boolean);
    const removidas = [];
    for (let tentativa = 0; tentativa < 20; tentativa++) {
      const url = `https://api.mercadolibre.com/marketplace/advertising/${siteId}/advertisers/${advertiserId}/product_ads/campaigns/search?campaign_ids=${campanhaId}&date_from=${de}&date_to=${ate}&metrics=${metricas.join(',')}&aggregation_type=DAILY`;
      try {
        const j = await fetchMLDebug(url, { headers: { Authorization: `Bearer ${accessToken}`, 'Api-Version': '2' } });
        return res.json({ ok: true, loja, campanhaId, dias, url, metricas_removidas: removidas, resultado: j });
      } catch (e) {
        const desc = (e.corpo && e.corpo.description) || '';
        const m = desc.match(/Field (\w+) not allowed/i);
        if (e.http_status === 400 && m) {
          const campo = m[1].toLowerCase();
          const idx = metricas.indexOf(campo);
          if (idx >= 0) { metricas.splice(idx, 1); removidas.push(campo); continue; }
        }
        return res.json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo, metricas_removidas: removidas });
      }
    }
    res.json({ ok: false, erro: 'Muitas metricas invalidas seguidas.', metricas_removidas: removidas });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo, corpo_bruto: e.corpo_bruto }); }
});
/* estudo diario de Ads (job em background) - repete, um dia de cada vez, a mesma chamada de
   /debug/ads/campanhas (sem aggregation_type, que respeita o filtro por campanha). */
const estudoAdsJobs = new Map();
function gerarJobIdAds() { return 'ads_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8); }
async function rodarEstudoDiarioAds(jobId, loja, campanhaId, dias) {
  const job = estudoAdsJobs.get(jobId);
  try {
    const { primeiro } = await buscarAdvertiserId(loja);
    const siteId = primeiro && primeiro.site_id;
    const advertiserId = primeiro && primeiro.advertiser_id;
    const resultado = [];
    const avisos = [];
    job.progresso = { feito: 0, total: dias };
    for (let i = dias - 1; i >= 0; i--) {
      const dia = dataYMD(Date.now() - i * 864e5);
      try {
        const resp = await buscarCampanhasAds(loja, siteId, advertiserId, null, { de: dia, ate: dia });
        const camp = (resp.results || []).find(c => String(c.id) === campanhaId);
        const m = (camp && camp.metrics) || {};
        resultado.push({
          date: dia,
          cost: m.cost || 0,
          direct_amount: m.direct_amount || 0,
          indirect_amount: m.indirect_amount || 0,
          total_amount: m.total_amount || 0,
          organic_units_amount: m.organic_units_amount || 0,
          organic_units_quantity: m.organic_units_quantity || 0,
          units_quantity: m.units_quantity || 0,
          roas: m.roas || 0,
          acos: m.acos || 0,
          sov: m.sov || 0,
          semDados: !camp
        });
      } catch (e) {
        avisos.push(`Falha no dia ${dia}: ${e.message}`);
        resultado.push({ date: dia, cost: 0, direct_amount: 0, indirect_amount: 0, total_amount: 0, organic_units_amount: 0, organic_units_quantity: 0, units_quantity: 0, roas: 0, acos: 0, sov: 0, erro: e.message });
      }
      job.progresso.feito++;
      await sleep(300);
    }
    job.resultado = { loja, campanhaId, dias, resultado, avisos };
    job.status = 'concluido';
  } catch (e) {
    job.status = 'erro'; job.erro = e.message;
  }
}
app.get('/debug/ads/estudo-diario/iniciar', async (req, res) => {
  try {
    const loja = req.query.loja;
    const campanhaId = String(req.query.campanhaId || '');
    const dias = Math.min(90, Math.max(1, parseInt(req.query.dias || '30', 10)));
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!campanhaId) return res.status(400).json({ ok: false, erro: 'Parametro "campanhaId" obrigatorio (pegue um "id" de campanha no /debug/ads/campanhas).' });
    const jobId = gerarJobIdAds();
    estudoAdsJobs.set(jobId, { status: 'rodando', progresso: { feito: 0, total: dias }, resultado: null, erro: null, criadoEm: Date.now() });
    rodarEstudoDiarioAds(jobId, loja, campanhaId, dias);
    res.json({ ok: true, jobId });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message }); }
});
app.get('/debug/ads/estudo-diario/status', (req, res) => {
  const jobId = req.query.id;
  const job = estudoAdsJobs.get(jobId);
  if (!job) return res.status(404).json({ ok: false, erro: 'Job nao encontrado - pode ter expirado (fica so em memoria, some se o servidor reiniciar/dormir).' });
  res.json({ ok: true, status: job.status, progresso: job.progresso, resultado: job.resultado, erro: job.erro });
});
const estudoAdsLojaJobs = new Map();
async function rodarEstudoDiarioLoja(jobId, loja, dias) {
  const job = estudoAdsLojaJobs.get(jobId);
  try {
    const { primeiro } = await buscarAdvertiserId(loja);
    const siteId = primeiro && primeiro.site_id;
    const advertiserId = primeiro && primeiro.advertiser_id;
    const porDia = [];
    const avisos = [];
    job.progresso = { feito: 0, total: dias };
    for (let i = dias - 1; i >= 0; i--) {
      const dia = dataYMD(Date.now() - i * 864e5);
      try {
        const resp = await buscarCampanhasAds(loja, siteId, advertiserId, null, { de: dia, ate: dia });
        const campanhas = {};
        (resp.results || []).forEach(c => {
          const m = c.metrics || {};
          campanhas[c.id] = {
            nome: c.name || '',
            cost: m.cost || 0,
            total_amount: m.total_amount || 0,
            organic_units_amount: m.organic_units_amount || 0,
            organic_units_quantity: m.organic_units_quantity || 0,
            units_quantity: m.units_quantity || 0,
            roas: m.roas || 0
          };
        });
        porDia.push({ date: dia, campanhas });
      } catch (e) {
        avisos.push(`Falha no dia ${dia}: ${e.message}`);
        porDia.push({ date: dia, campanhas: {}, erro: e.message });
      }
      job.progresso.feito++;
      await sleep(300);
    }
    job.resultado = { loja, dias, porDia, avisos };
    job.status = 'concluido';
  } catch (e) {
    job.status = 'erro'; job.erro = e.message;
  }
}
app.get('/debug/ads/estudo-diario-loja/iniciar', async (req, res) => {
  try {
    const loja = req.query.loja;
    const dias = Math.min(90, Math.max(1, parseInt(req.query.dias || '90', 10)));
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const jobId = gerarJobIdAds();
    estudoAdsLojaJobs.set(jobId, { status: 'rodando', progresso: { feito: 0, total: dias }, resultado: null, erro: null, criadoEm: Date.now() });
    rodarEstudoDiarioLoja(jobId, loja, dias);
    res.json({ ok: true, jobId });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message }); }
});
app.get('/debug/ads/estudo-diario-loja/status', (req, res) => {
  const jobId = req.query.id;
  const job = estudoAdsLojaJobs.get(jobId);
  if (!job) return res.status(404).json({ ok: false, erro: 'Job nao encontrado - pode ter expirado (fica so em memoria, some se o servidor reiniciar/dormir).' });
  res.json({ ok: true, status: job.status, progresso: job.progresso, resultado: job.resultado, erro: job.erro });
});
/* ---------- sincronizacao "de verdade" de Ads (grava no banco, pro Doca so' ler) ---------- */
async function sincronizarAdsLoja(loja) {
  const { primeiro } = await buscarAdvertiserId(loja);
  if (!primeiro) throw new Error('Nenhum advertiser_id encontrado pra essa loja.');
  const { advertiser_id, site_id } = primeiro;
  const periodos = [1, 7, 15, 30];
  const resultado = {};
  for (const dias of periodos) {
    const campanhas = await buscarCampanhasAds(loja, site_id, advertiser_id, dias);
    const chave = 'd' + dias;
    resultado[chave] = campanhas;
    await pool.query(
      `insert into ml_ads_campanhas (loja, periodo, advertiser_id, site_id, dados, atualizado_em)
       values ($1,$2,$3,$4,$5, now())
       on conflict (loja, periodo) do update set
         advertiser_id = excluded.advertiser_id, site_id = excluded.site_id,
         dados = excluded.dados, atualizado_em = now()`,
      [loja, chave, advertiser_id, site_id, JSON.stringify(campanhas)]
    );
  }
  return { advertiserId: advertiser_id, siteId: site_id, periodos: resultado };
}
app.post('/ads/sync', async (req, res) => {
  try {
    const loja = req.query.loja || req.body?.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const r = await sincronizarAdsLoja(loja);
    res.json({ ok: true, loja, advertiserId: r.advertiserId, siteId: r.siteId });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo }); }
});
app.get('/ads/data', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const r = await pool.query('select periodo, advertiser_id, site_id, dados, atualizado_em from ml_ads_campanhas where loja = $1', [loja]);
    const periodos = {};
    let atualizadoEm = null;
    r.rows.forEach(row => {
      periodos[row.periodo] = row.dados;
      if (!atualizadoEm || row.atualizado_em > atualizadoEm) atualizadoEm = row.atualizado_em;
    });
    res.json({ ok: true, loja, periodos, atualizadoEm });
  } catch (e) { res.status(500).json({ ok: false, erro: e.message }); }
});
app.get('/ads/campanhas-periodo', async (req, res) => {
  try {
    const loja = req.query.loja;
    const de = req.query.de, ate = req.query.ate;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!de || !ate) return res.status(400).json({ ok: false, erro: 'Parametros "de" e "ate" obrigatorios (AAAA-MM-DD).' });
    const { primeiro } = await buscarAdvertiserId(loja);
    if (!primeiro) return res.status(200).json({ ok: false, erro: 'Nenhum advertiser_id encontrado pra essa loja.' });
    const campanhas = await buscarCampanhasAds(loja, primeiro.site_id, primeiro.advertiser_id, null, { de, ate });
    res.json({ ok: true, loja, periodo: { de, ate }, campanhas });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo }); }
});
/* ================= Financas: fatura (cobrança mensal) do Mercado Livre ================= */
function anoRazoavel(dataIso) {
  const ano = Number(String(dataIso || '').slice(0, 4));
  return ano && ano <= 2100 ? true : false;
}
/* busca o detalhamento (itens/cobranças) de UM período de fatura pela key - separado de
   buscarFaturaMl pra dar pra reaproveitar tanto na busca do período mais recente quanto sob
   demanda pra um período JÁ CONHECIDO (ver /financas/fatura-ml/detalhar) - o endpoint de listagem
   de períodos só devolve o mais recente (limit=1), mas o detalhamento por key funciona pra
   qualquer período antigo desde que a gente já saiba a key (o Doca guarda ela em cada despesa,
   ver faturaKey). */
async function buscarItensFaturaPorKey(loja, key) {
  const accessToken = await tokenValido(loja);
  let itens = [];
  let itensAviso = null;
  if (key) {
    try {
      const urlResumo = `https://api.mercadolibre.com/billing/integration/periods/key/${key}/summary?group=ML&document_type=BILL`;
      const jResumo = await fetchMLDebug(urlResumo, { headers: { Authorization: `Bearer ${accessToken}` } });
      const charges = (jResumo.summary && jResumo.summary.charges) || [];
      const bonuses = (jResumo.summary && jResumo.summary.bonuses) || [];
      itens = [
        ...charges.map(c => ({ label: c.label, valor: c.amount })),
        ...bonuses.map(b => ({ label: `Bonificação: ${b.label}`, valor: -Math.abs(b.amount) }))
      ];
    } catch (eResumo) {
      try {
        const porLabel = new Map();
        let offset = 0;
        const limite = 150;
        let total = null;
        // retry com espera crescente em 429 - pedido do Felipe 24/08: esse endpoint de detalhamento
        // vem esbarrando bastante no limite de chamadas do Mercado Livre logo depois da
        // sincronização automática ao abrir o Doca (que já dispara bastante chamada em sequência).
        async function buscarDetalhesComRetry(url) {
          for (let tentativa = 0; tentativa < 4; tentativa++) {
            try {
              return await fetchMLDebug(url, { headers: { Authorization: `Bearer ${accessToken}` } });
            } catch (e) {
              if (e.http_status === 429 && tentativa < 3) { await sleep(800 * (tentativa + 1)); continue; }
              throw e;
            }
          }
        }
        do {
          const urlDetalhes = `https://api.mercadolibre.com/billing/integration/periods/key/${key}/group/ML/details?document_type=BILL&limit=${limite}&offset=${offset}`;
          const jDetalhes = await buscarDetalhesComRetry(urlDetalhes);
          const linhas = jDetalhes.results || [];
          total = typeof jDetalhes.total === 'number' ? jDetalhes.total : linhas.length;
          linhas.forEach(r => {
            const info = r.charge_info || {};
            const label = info.transaction_detail || 'Outras cobranças';
            const valor = Number(info.detail_amount) || 0;
            porLabel.set(label, (porLabel.get(label) || 0) + valor);
          });
          offset += limite;
        } while (offset < total && offset < 2000);
        itens = [...porLabel.entries()].map(([label, valor]) => ({ label, valor }));
      } catch (eDetalhes) {
        itensAviso = `Detalhamento indisponível: /summary respondeu ${eResumo.http_status || '?'}, /details respondeu ${eDetalhes.http_status || '?'} (${eDetalhes.message})`;
      }
    }
  }
  return { itens, itensAviso };
}
async function buscarFaturaMl(loja) {
  const accessToken = await tokenValido(loja);
  // limit=3 (nao mais 1) - pedido do Felipe 24/08: com limit=1 o Doca so' via' o periodo MAIS
  // RECENTE, que assim que um novo mes abre passa a ser o periodo AINDA EM ANDAMENTO (sem
  // vencimento confirmado, ainda acumulando) - e o periodo anterior, que estava FECHADO e "A
  // VENCER" de verdade (com data de vencimento real e valor que precisa ser pago em poucos dias),
  // sumia do radar do Doca inteiramente. Buscando mais periodos, da' pra escolher certo qual e' o
  // que realmente importa agora.
  const url = 'https://api.mercadolibre.com/billing/integration/monthly/periods?group=ML&document_type=BILL&limit=3';
  const j = await fetchMLDebug(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  const periodos = j.results || [];
  if (!periodos.length) return null;
  // pega o periodo mais recente que ja FECHOU (period_status==='CLOSED') e ainda tem divida
  // (unpaid_amount>0) - esse e' o que esta' "A VENCER" de verdade (confirmado via debug 24/08 com
  // a TorvStore: results[0] era o periodo ainda OPEN, com debt_expiration_date/expiration_date
  // = "9999-12-31" - um valor sentinela de "sem data ainda" que o Mercado Livre usa em vez de
  // null, e que passava como se fosse uma data real na tentativa anterior). period_status e' o
  // sinal limpo e direto, sem precisar interpretar datas sentinela. Sem nenhum periodo fechado
  // com divida (tudo pago ou sem periodo fechado ainda), cai pro mais recente mesmo.
  let p = periodos.find(x => x.period_status === 'CLOSED' && typeof x.unpaid_amount === 'number' && x.unpaid_amount > 0);
  if (!p) p = periodos[0];
  const { itens, itensAviso } = await buscarItensFaturaPorKey(loja, p.key);
  const extrairVencimento = (per) => {
    // NAO cai pro period.date_to como fallback de vencimento (esse era o bug real, achado no
    // debug 24/08 com Orbix/TorvShop: pra periodo ainda OPEN, esse date_to e' so' a data em que
    // o periodo FECHA, nao quando a fatura VENCE). Sem vencimento confirmado de verdade, fica
    // null mesmo - o frontend sabe estimar certo pelo ciclo de cada loja (FATURA_CICLO) usando
    // dataFim/dataInicio.
    let v = per.debt_expiration_date || per.expiration_date || null;
    if (v && !anoRazoavel(v)) v = null;
    return v;
  };
  const vencimento = extrairVencimento(p);
  // outros: pedido do Felipe 25/08 - a Orbix e a TorvShop tinham fatura de Agosto ja' quitada
  // que sumia inteira do Doca (nem aparecia como despesa) assim que o periodo de Setembro virava
  // o "principal" (p acima) - o Doca so' olhava pra 1 periodo por vez. Manda os OUTROS periodos
  // do mesmo lote ja' buscado (sem chamada extra na API) pro frontend poder criar/reconciliar a
  // despesa de cada um, mesmo nao sendo mais o "principal" rastreado agora.
  const outros = periodos.filter(x => x.key && x.key !== p.key).map(x => ({
    key: x.key,
    valor: typeof x.unpaid_amount === 'number' ? x.unpaid_amount : (typeof x.amount === 'number' ? x.amount : null),
    valorTotal: typeof x.amount === 'number' ? x.amount : null,
    valorPendente: typeof x.unpaid_amount === 'number' ? x.unpaid_amount : null,
    dataInicio: (x.period && x.period.date_from) || null,
    dataFim: (x.period && x.period.date_to && anoRazoavel(x.period.date_to)) ? x.period.date_to : null,
    vencimento: extrairVencimento(x),
    status: x.period_status || null
  }));
  return {
    key: p.key || null,
    valor: typeof p.unpaid_amount === 'number' ? p.unpaid_amount : (typeof p.amount === 'number' ? p.amount : null),
    valorTotal: typeof p.amount === 'number' ? p.amount : null,
    valorPendente: typeof p.unpaid_amount === 'number' ? p.unpaid_amount : null,
    dataInicio: (p.period && p.period.date_from) || null,
    dataFim: (p.period && p.period.date_to && anoRazoavel(p.period.date_to)) ? p.period.date_to : null,
    vencimento,
    status: p.period_status || null,
    outros,
    itens,
    itensAviso
  };
}
app.get('/financas/fatura-ml', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const fatura = await buscarFaturaMl(loja);
    res.json({ ok: true, loja, fatura });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo }); }
});
/* debug 24/08: devolve os períodos CRUS que o Mercado Livre manda (sem passar pela seleção nem
   pela formatação de buscarFaturaMl), pra conferir de verdade os nomes/valores dos campos
   (debt_expiration_date, expiration_date, unpaid_amount, period_status etc) numa loja específica
   - a TorvStore continuou mostrando vencimento 22/08 (dia do fechamento) mesmo depois do fix de
   buscar 3 períodos, então precisa ver o payload de verdade em vez de continuar advinhando. */
app.get('/debug/fatura-ml/periodos', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const accessToken = await tokenValido(loja);
    const url = 'https://api.mercadolibre.com/billing/integration/monthly/periods?group=ML&document_type=BILL&limit=5';
    const j = await fetchMLDebug(url, { headers: { Authorization: `Bearer ${accessToken}` } });
    res.json({ ok: true, loja, bruto: j });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo }); }
});
/* detalhamento sob demanda de uma fatura JÁ CONHECIDA (qualquer mês, não só a mais recente) -
   pedido do Felipe 23/08: o botão "Detalhar" só funcionava na fatura mais atual porque
   buscarFaturaMl só traz o período mais recente (limit=1); aqui o frontend manda a key que já
   tem guardada na despesa (faturaKey) e a gente busca o detalhamento direto por ela. */
app.get('/financas/fatura-ml/detalhar', async (req, res) => {
  try {
    const loja = req.query.loja;
    const key = req.query.key;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!key) return res.status(400).json({ ok: false, erro: 'Parametro "key" obrigatorio.' });
    const { itens, itensAviso } = await buscarItensFaturaPorKey(loja, key);
    res.json({ ok: true, itens, itensAviso });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo }); }
});
/* ================= Financas: Resumo Financeiro (faturamento, margem, deducoes por periodo) ================= */
function calcularPeriodoResumo(periodo, deQuery, ateQuery) {
  const hojeStr = diaBR(new Date().toISOString());
  const diasAtras = n => diaBR(new Date(Date.now() - n * 864e5).toISOString());
  if (periodo === 'hoje') {
    return { de: hojeStr, ate: hojeStr };
  }
  if (periodo === 'personalizado') {
    if (!deQuery || !ateQuery) throw new Error('Informe "de" e "ate" (AAAA-MM-DD) pro periodo personalizado.');
    return { de: deQuery, ate: ateQuery };
  }
  if (periodo === 'mes_fechado') {
    const hoje = new Date();
    const primeiroDiaMesAtual = new Date(Date.UTC(hoje.getUTCFullYear(), hoje.getUTCMonth(), 1));
    const ultimoDiaMesAnterior = new Date(primeiroDiaMesAtual.getTime() - 864e5);
    const primeiroDiaMesAnterior = new Date(Date.UTC(ultimoDiaMesAnterior.getUTCFullYear(), ultimoDiaMesAnterior.getUTCMonth(), 1));
    return { de: dataYMD(primeiroDiaMesAnterior), ate: dataYMD(ultimoDiaMesAnterior) };
  }
  if (periodo === 'mes_corrente') {
    const hoje = new Date();
    const primeiroDiaMesAtual = new Date(Date.UTC(hoje.getUTCFullYear(), hoje.getUTCMonth(), 1));
    return { de: dataYMD(primeiroDiaMesAtual), ate: hojeStr };
  }
  const dias = { '7d': 7, '15d': 15, '30d': 30 }[periodo] || 30;
  return { de: diasAtras(dias - 1), ate: hojeStr };
}
async function buscarFaturamentoRapido(loja, de, ate) {
  const accessToken = await tokenValido(loja);
  const conta = await pegarConta(loja);
  const log = { avisos: [] };
  const deIso = `${de}T00:00:00-03:00`;
  const ateIso = `${ate}T23:59:59-03:00`;
  const pedidos = await buscarPedidosNoIntervalo(accessToken, conta.ml_user_id, deIso, ateIso, log, 'order.date_closed');
  let faturamento = 0;
  for (const pedido of pedidos) {
    if (pedido.status === 'cancelled' || pedido.status === 'invalid') continue;
    faturamento += Number(pedido.total_amount) || 0;
  }
  return faturamento;
}
async function buscarResumoFinanceiro(loja, de, ate, onProgress) {
  if (typeof onProgress !== 'function') onProgress = () => {};
  const accessToken = await tokenValido(loja);
  const conta = await pegarConta(loja);
  const log = { avisos: [] };
  const deIso = `${de}T00:00:00-03:00`;
  const ateIso = `${ate}T23:59:59-03:00`;
  onProgress(5, 'Buscando pedidos do período...');
  const pedidos = await buscarPedidosNoIntervalo(accessToken, conta.ml_user_id, deIso, ateIso, log, 'order.date_closed');
  onProgress(20, `${pedidos.length} pedido(s) encontrado(s) - calculando itens vendidos...`);
  let faturamento = 0, tarifas = 0, cancelamentosValor = 0, reembolsosValor = 0;
  let pedidosValidos = 0, pedidosCancelados = 0;
  const itensVendidos = new Map();
  const shippingIds = new Set();
  const itensPorShipping = new Map();
  let tarifaCancelados = 0;
  const itensPorPagamento = new Map();
  for (const pedido of pedidos) {
    if (pedido.status === 'invalid') continue;
    const cancelado = pedido.status === 'cancelled';
    const total = Number(pedido.total_amount) || 0;
    if (cancelado) {
      pedidosCancelados++;
      cancelamentosValor += total;
    } else {
      pedidosValidos++;
      faturamento += total;
    }
    const itensDoPedido = [];
    for (const oi of (pedido.order_items || [])) {
      const saleFee = (Number(oi.sale_fee) || 0) * (oi.quantity || 1);
      if (cancelado) tarifaCancelados += saleFee;
      const itemId = oi.item && oi.item.id;
      const valorItem = (Number(oi.unit_price) || 0) * (oi.quantity || 0);
      if (itemId) {
        const atual = itensVendidos.get(itemId) || { qtd: 0, valor: 0, pedidos: 0, tarifa: 0, freteMl: 0, faturamentoTotal: 0, tarifaDeclarada: 0, qtdCancelada: 0, pedidosCancelados: 0 };
        if (!cancelado) {
          atual.qtd += oi.quantity || 0;
          atual.valor += valorItem;
          atual.pedidos += 1;
        } else {
          atual.qtdCancelada += oi.quantity || 0;
          atual.pedidosCancelados += 1;
        }
        atual.faturamentoTotal += valorItem;
        atual.tarifaDeclarada += saleFee;
        itensVendidos.set(itemId, atual);
        if (pedido.shipping && pedido.shipping.id) {
          const lista = itensPorShipping.get(pedido.shipping.id) || [];
          lista.push({ itemId, qtd: oi.quantity || 1 });
          itensPorShipping.set(pedido.shipping.id, lista);
        }
        itensDoPedido.push({ itemId, valor: valorItem || 1 });
      }
    }
    if (pedido.shipping && pedido.shipping.id) shippingIds.add(pedido.shipping.id);
    for (const pg of (pedido.payments || [])) {
      if (pg.status === 'approved' && (pg.installments || 1) > 1 && pg.id) {
        const lista = itensPorPagamento.get(pg.id) || [];
        itensPorPagamento.set(pg.id, lista.concat(itensDoPedido));
      }
    }
    if (!cancelado) {
      for (const pg of (pedido.payments || [])) {
        if (pg.status === 'refunded' || pg.status === 'partially_refunded') {
          reembolsosValor += Number(pg.transaction_amount) || 0;
        }
      }
    }
  }
  onProgress(30, 'Calculando peso dos itens...');
  const pesosPorItem = new Map();
  try {
    const idsParaPeso = [...itensVendidos.keys()];
    for (let i = 0; i < idsParaPeso.length; i += 20) {
      const lote = idsParaPeso.slice(i, i + 20).join(',');
      const r = await fetch(`https://api.mercadolibre.com/items?ids=${lote}&attributes=id,attributes`, { headers: { Authorization: `Bearer ${accessToken}` } });
      const j2 = await r.json();
      (j2 || []).forEach(entry => {
        if (entry.code !== 200) return;
        const atributos = (entry.body && entry.body.attributes) || [];
        const acharPeso = (id) => {
          const attr = atributos.find(a => a.id === id);
          const struct = attr && attr.value_struct;
          if (!struct || typeof struct.number !== 'number') return null;
          const unidade = (struct.unit || 'g').toLowerCase();
          return unidade === 'kg' ? struct.number * 1000 : struct.number;
        };
        const peso = acharPeso('SELLER_PACKAGE_WEIGHT') ?? acharPeso('PACKAGE_WEIGHT');
        if (peso != null && peso > 0) pesosPorItem.set(entry.body.id, peso);
      });
    }
  } catch (e) { log.avisos.push('Nao foi possivel buscar o peso dos itens vendidos (rateio de frete entre produtos de um mesmo envio caiu pra 1g cada, quando nao achar o peso real): ' + e.message); }
  onProgress(45, 'Calculando comissão (tarifa) por produto...');
  itensVendidos.forEach(atual => { atual.tarifa = atual.tarifaDeclarada; });
  let itensSemComissao = 0;
  try {
    const idsSemSaleFee = [...itensVendidos.entries()].filter(([id, v]) => !v.tarifaDeclarada && v.faturamentoTotal > 0).map(([id]) => id);
    if (idsSemSaleFee.length) {
      const dadosItem = new Map();
      for (let i = 0; i < idsSemSaleFee.length; i += 20) {
        const lote = idsSemSaleFee.slice(i, i + 20).join(',');
        const r = await fetch(`https://api.mercadolibre.com/items?ids=${lote}&attributes=id,price,category_id,listing_type_id,site_id`, { headers: { Authorization: `Bearer ${accessToken}` } });
        const j2 = await r.json();
        (j2 || []).forEach(entry => { if (entry.code === 200) dadosItem.set(entry.body.id, entry.body); });
      }
      const CONCORRENCIA_COMISSAO = 8;
      const idsComDados = [...dadosItem.keys()];
      let cursorComissao = 0;
      async function workerComissao() {
        while (cursorComissao < idsComDados.length) {
          const itemId = idsComDados[cursorComissao++];
          const dados = dadosItem.get(itemId);
          const atual = itensVendidos.get(itemId);
          if (!atual || !dados || !dados.price || !dados.category_id || !dados.listing_type_id) { itensSemComissao++; continue; }
          try {
            const url = `https://api.mercadolibre.com/sites/${dados.site_id || 'MLB'}/listing_prices?price=${dados.price}&category_id=${dados.category_id}&listing_type_id=${dados.listing_type_id}`;
            const r = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
            const j3 = await r.json();
            const percentual = j3 && j3.sale_fee_details && typeof j3.sale_fee_details.percentage_fee === 'number' ? j3.sale_fee_details.percentage_fee : null;
            if (percentual != null) {
              atual.tarifa = atual.faturamentoTotal * (percentual / 100);
            } else {
              itensSemComissao++;
            }
          } catch (e) {
            itensSemComissao++;
          }
        }
      }
      await Promise.all(Array.from({ length: Math.min(CONCORRENCIA_COMISSAO, idsComDados.length) }, workerComissao));
    }
  } catch (e) {
    log.avisos.push('Nao foi possivel buscar a comissao por categoria pros produtos sem sale_fee declarado (ficaram com Tarifa em R$0 - pode estar subestimado): ' + e.message);
  }
  if (itensSemComissao) log.avisos.push(`${itensSemComissao} produto(s) sem sale_fee declarado E sem comissao por categoria disponivel - Tarifa desses pode estar subestimada (R$0).`);
  tarifas = [...itensVendidos.values()].reduce((s, v) => s + v.tarifa, 0);
  let freteComprador = 0, freteVendedor = 0, freteFalhas = 0;
  const idsArray = [...shippingIds];
  const LIMITE_SHIPMENTS = 6000;
  const idsParaBuscar = idsArray.slice(0, LIMITE_SHIPMENTS);
  if (idsArray.length > LIMITE_SHIPMENTS) log.avisos.push(`${idsArray.length} envios no periodo, so' os primeiros ${LIMITE_SHIPMENTS} entraram no calculo de frete (limite de seguranca).`);
  async function buscarCustoShipmentComRetry(shippingId, tentativa) {
    tentativa = tentativa || 0;
    try {
      return await fetchMLDebug(`https://api.mercadolibre.com/shipments/${shippingId}/costs`, { headers: { Authorization: `Bearer ${accessToken}` } });
    } catch (e) {
      const rateLimited = e.http_status === 429 || (e.corpo && (e.corpo.error === 'local_rate_limited' || e.corpo.message === 'local_rate_limited'));
      if (rateLimited && tentativa < 4) {
        await sleep(500 * Math.pow(2, tentativa));
        return buscarCustoShipmentComRetry(shippingId, tentativa + 1);
      }
      throw e;
    }
  }
  onProgress(50, `Calculando frete de ${idsParaBuscar.length} envio(s)...`);
  const CONCORRENCIA_FRETE = 10;
  let cursorFrete = 0;
  let concluidosFrete = 0;
  async function workerFrete() {
    while (cursorFrete < idsParaBuscar.length) {
      const shippingId = idsParaBuscar[cursorFrete++];
      try {
        const j = await buscarCustoShipmentComRetry(shippingId);
        const receivers = j.receivers || [];
        const senders = j.senders || [];
        freteComprador += receivers.reduce((s, r) => s + (Number(r.cost) || 0), 0);
        const custoVendedorShipment = senders.reduce((s, r) => s + (Number(r.cost) || 0), 0);
        freteVendedor += custoVendedorShipment;
        if (custoVendedorShipment) {
          const itensDoShipment = itensPorShipping.get(shippingId) || [];
          const pesoDoItem = (it) => (pesosPorItem.get(it.itemId) || 1) * it.qtd;
          const pesoTotalShipment = itensDoShipment.reduce((s, it) => s + pesoDoItem(it), 0);
          if (pesoTotalShipment > 0) {
            itensDoShipment.forEach(it => {
              const atual = itensVendidos.get(it.itemId);
              if (atual) atual.freteMl = (atual.freteMl || 0) + custoVendedorShipment * (pesoDoItem(it) / pesoTotalShipment);
            });
          }
        }
      } catch (e) {
        freteFalhas++;
      }
      concluidosFrete++;
      if (concluidosFrete % 15 === 0 || concluidosFrete === idsParaBuscar.length) {
        const pct = 50 + Math.round((concluidosFrete / idsParaBuscar.length) * 38);
        onProgress(pct, `Calculando frete: ${concluidosFrete}/${idsParaBuscar.length} envio(s)...`);
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(CONCORRENCIA_FRETE, idsParaBuscar.length) }, workerFrete));
  if (freteFalhas) log.avisos.push(`${freteFalhas} de ${idsParaBuscar.length} envio(s) nao respondeu(ram) o custo de frete (ignorados no total - pode subestimar levemente o frete).`);
  if (pedidosCancelados > 0) log.avisos.push(`${pedidosCancelados} pedido(s) cancelado(s) no periodo - o faturamento deles continua entrando na base de calculo da Tarifa (confirmado que o Mercado Livre normalmente nao devolve a comissao so' por causa do cancelamento).`);
  onProgress(90, 'Buscando gasto de Ads do período...');
  let adsCusto = 0;
  let adsCampanhas = [];
  let adsItens = [];
  try {
    const { primeiro } = await buscarAdvertiserId(loja);
    if (primeiro) {
      const campanhas = await buscarCampanhasAds(loja, primeiro.site_id, primeiro.advertiser_id, null, { de, ate });
      adsCampanhas = (campanhas.results || []).map(c => ({ id: c.id, name: c.name, cost: (c.metrics && c.metrics.cost) || 0 }));
      adsCusto = adsCampanhas.reduce((s, c) => s + c.cost, 0);
      if (campanhas._aviso_paginacao) log.avisos.push(campanhas._aviso_paginacao);
      try {
        const campanhaIdJaConhecida = (campanhas.results && campanhas.results[0] && campanhas.results[0].id) || null;
        adsItens = await buscarItensAdsPeriodo(loja, primeiro.site_id, primeiro.advertiser_id, de, ate, campanhaIdJaConhecida);
      } catch (e) { log.avisos.push('Nao foi possivel buscar o custo de Ads por item do periodo (ficou so o casamento por nome de campanha): ' + e.message); }
    }
  } catch (e) { log.avisos.push('Nao foi possivel buscar o custo de Ads do periodo: ' + e.message); }
  onProgress(96, 'Calculando vendas de hoje e títulos dos produtos...');
  const vendasHoje = { pedidos: 0, faturamento: 0, unidades: 0 };
  try {
    const hojeStr = diaBR(new Date().toISOString());
    const deHoje = `${hojeStr}T00:00:00-03:00`;
    const ateHoje = `${hojeStr}T23:59:59-03:00`;
    const pedidosHoje = await buscarPedidosNoIntervalo(accessToken, conta.ml_user_id, deHoje, ateHoje, log, 'order.date_closed');
    for (const p of pedidosHoje) {
      if (p.status !== 'cancelled' && p.status !== 'invalid') {
        vendasHoje.pedidos++;
        vendasHoje.faturamento += Number(p.total_amount) || 0;
        for (const oi of (p.order_items || [])) vendasHoje.unidades += oi.quantity || 0;
      }
    }
  } catch (e) { log.avisos.push('Nao foi possivel buscar as vendas de hoje: ' + e.message); }
  const itensVendidosArr = [...itensVendidos.entries()].map(([itemId, v]) => ({ itemId, qtd: v.qtd, valor: v.valor, pedidos: v.pedidos, tarifa: v.tarifa, freteMl: v.freteMl || 0, qtdCancelada: v.qtdCancelada || 0, pedidosCancelados: v.pedidosCancelados || 0, titulo: null }));
  try {
    const idsUnicos = itensVendidosArr.map(x => x.itemId);
    const titulos = {};
    for (let i = 0; i < idsUnicos.length; i += 20) {
      const lote = idsUnicos.slice(i, i + 20).join(',');
      const r = await fetch(`https://api.mercadolibre.com/items?ids=${lote}&attributes=id,title`, { headers: { Authorization: `Bearer ${accessToken}` } });
      const j2 = await r.json();
      (j2 || []).forEach(entry => { if (entry.code === 200) titulos[entry.body.id] = entry.body.title; });
    }
    itensVendidosArr.forEach(x => { x.titulo = titulos[x.itemId] || null; });
  } catch (e) { log.avisos.push('Nao foi possivel buscar o titulo dos itens vendidos (ranking vai mostrar so o item_id): ' + e.message); }
  onProgress(100, 'Concluído.');
  return {
    periodo: { de, ate },
    faturamento, tarifas, cancelamentosValor, reembolsosValor,
    pedidosValidos, pedidosCancelados,
    itensVendidos: itensVendidosArr,
    frete: { comprador: freteComprador, vendedor: freteVendedor },
    ads: { custo: adsCusto, campanhas: adsCampanhas, itens: adsItens },
    vendasHoje,
    avisos: log.avisos
  };
}
const resumoJobs = new Map();
function gerarJobIdResumo() { return 'res_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8); }
async function rodarResumoJob(jobId, loja, periodo, deQuery, ateQuery) {
  const job = resumoJobs.get(jobId);
  try {
    const { de, ate } = calcularPeriodoResumo(periodo, deQuery, ateQuery);
    const resumo = await buscarResumoFinanceiro(loja, de, ate, (pct, etapa) => {
      job.progresso = { feito: pct, total: 100, etapa };
    });
    job.resultado = { loja, periodo, resumo };
    job.status = 'concluido';
  } catch (e) {
    job.status = 'erro'; job.erro = e.message;
  }
}
app.get('/financas/resumo-job/iniciar', async (req, res) => {
  try {
    const loja = req.query.loja;
    const periodo = req.query.periodo || '30d';
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const jobId = gerarJobIdResumo();
    resumoJobs.set(jobId, { status: 'rodando', progresso: { feito: 0, total: 100, etapa: 'Iniciando...' }, resultado: null, erro: null, criadoEm: Date.now() });
    rodarResumoJob(jobId, loja, periodo, req.query.de, req.query.ate);
    res.json({ ok: true, jobId });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message }); }
});
app.get('/financas/resumo-job/status', (req, res) => {
  const job = resumoJobs.get(req.query.id);
  if (!job) return res.status(404).json({ ok: false, erro: 'Job nao encontrado - pode ter expirado (fica so em memoria, some se o servidor reiniciar/dormir).' });
  res.json({ ok: true, status: job.status, progresso: job.progresso, resultado: job.resultado, erro: job.erro });
});
app.get('/financas/resumo', async (req, res) => {
  try {
    const loja = req.query.loja;
    const periodo = req.query.periodo || '30d';
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const { de, ate } = calcularPeriodoResumo(periodo, req.query.de, req.query.ate);
    const resumo = await buscarResumoFinanceiro(loja, de, ate);
    res.json({ ok: true, loja, periodo, resumo });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo }); }
});
app.get('/financas/faturamento-mes', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    // de/ate opcionais (pedido do Felipe 23/08 - despesa de Imposto automática, base no
    // faturamento do MES ANTERIOR, não do mes corrente) - sem eles, comportamento de sempre.
    const { de, ate } = (req.query.de && req.query.ate) ? calcularPeriodoResumo('personalizado', req.query.de, req.query.ate) : calcularPeriodoResumo('mes_corrente');
    const faturamento = await buscarFaturamentoRapido(loja, de, ate);
    res.json({ ok: true, loja, periodo: { de, ate }, faturamento });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo }); }
});
/* ================= Perguntas sem resposta (completas, pra ler e responder) ================= */
async function buscarPerguntasCompletas(accessToken, sellerId) {
  const perguntas = [];
  let offset = 0;
  const limit = 50;
  while (true) {
    const url = `https://api.mercadolibre.com/questions/search?seller_id=${sellerId}&status=UNANSWERED&api_version=4&limit=${limit}&offset=${offset}&sort_fields=date_created&sort_types=DESC`;
    const r = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
    if (r.status === 404) break;
    const j = await r.json();
    if (!r.ok) throw new Error('Falha ao buscar perguntas: ' + JSON.stringify(j));
    const questions = j.questions || [];
    perguntas.push(...questions);
    offset += limit;
    if (questions.length < limit || offset >= (j.total || 0)) break;
  }
  return perguntas;
}
app.get('/perguntas', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const accessToken = await tokenValido(loja);
    const conta = await pegarConta(loja);
    const perguntas = await buscarPerguntasCompletas(accessToken, conta.ml_user_id);
    const itemIds = [...new Set(perguntas.map(q => q.item_id).filter(Boolean))];
    const itens = {};
    for (let i = 0; i < itemIds.length; i += 20) {
      const lote = itemIds.slice(i, i + 20).join(',');
      const r = await fetch(`https://api.mercadolibre.com/items?ids=${lote}&attributes=id,title,thumbnail,permalink`, {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      const j = await r.json();
      (j || []).forEach(entry => { if (entry.code === 200) itens[entry.body.id] = entry.body; });
    }
    const resultado = perguntas.map(q => ({
      id: q.id,
      itemId: q.item_id,
      texto: q.text,
      dataCriada: q.date_created,
      titulo: (itens[q.item_id] && itens[q.item_id].title) || null,
      thumbnail: (itens[q.item_id] && itens[q.item_id].thumbnail) || null,
      permalink: (itens[q.item_id] && itens[q.item_id].permalink) || null
    }));
    res.json({ ok: true, loja, perguntas: resultado });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo }); }
});
app.post('/perguntas/responder', async (req, res) => {
  try {
    const loja = req.query.loja || req.body?.loja;
    const questionId = req.body?.questionId;
    const texto = req.body?.texto;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!questionId || !texto) return res.status(400).json({ ok: false, erro: 'Informe questionId e texto.' });
    if (String(texto).length > 2000) return res.status(400).json({ ok: false, erro: 'Resposta com mais de 2000 caracteres (limite do Mercado Livre).' });
    const accessToken = await tokenValido(loja);
    const r = await fetch('https://api.mercadolibre.com/answers', {
      method: 'POST',
      headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json; charset=utf-8' },
      body: JSON.stringify({ question_id: questionId, text: texto })
    });
    const j = await r.json();
    if (!r.ok) return res.status(200).json({ ok: false, erro: j.message || 'Falha ao responder a pergunta.', corpo: j });
    res.json({ ok: true, resposta: j });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo }); }
});
/* ================= Encerrar anuncio no Mercado Livre =================
   Felipe (21/08) pediu: produto descontinuado que ele nao consegue excluir direto no Mercado
   Livre (pelo site/app) - fazer isso pelo Doca. O Mercado Livre nao tem "excluir" de verdade pra
   a maioria dos anuncios (so' pra alguns casos bem especificos, tipo status=payment_required) - o
   equivalente e' ENCERRAR (status="closed"), que e' IRREVERSIVEL (diferente de pausar, que da' pra
   reativar depois) - confirmado na doc oficial: "Once closed, it cannot be reactivated again, but
   it can be relisted." Depois de encerrado, o Mercado Livre descarta o anuncio sozinho depois de
   um tempo (nao precisa fazer mais nada). */
app.post('/produtos/encerrar-anuncio', async (req, res) => {
  try {
    const loja = req.query.loja || req.body?.loja;
    const itemId = req.body?.itemId;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!itemId) return res.status(400).json({ ok: false, erro: 'Informe itemId.' });
    const accessToken = await tokenValido(loja);
    const r = await fetch(`https://api.mercadolibre.com/items/${itemId}`, {
      method: 'PUT',
      headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'closed' })
    });
    const j = await r.json();
    if (!r.ok) return res.status(200).json({ ok: false, erro: j.message || 'Falha ao encerrar o anuncio.', corpo: j });
    res.json({ ok: true, item: j });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo }); }
});
/* ================= Mensagens pos-venda (mensagem privada apos a compra) =================
   Diferente de Perguntas (publicas, antes da venda), essas sao mensagens privadas trocadas
   DEPOIS da compra (duvida de uso, problema, etc). Felipe (20/08) pediu: responde MANUAL (nao
   automatico), mas com sugestao de resposta pronta pra so' clicar Responder. Mostrada logo
   abaixo de Perguntas no Doca.

   IMPORTANTE (21/08) - por que isso NAO busca sob demanda como Reclamacoes:
   testei todas as variacoes documentadas do endpoint "buscar todas as mensagens nao lidas de uma
   vez" (/marketplace/messages/unread com role+tag+user_id, sem user_id, so' com role, sem NENHUM
   parametro, e ate' o endpoint "classico" sem o prefixo marketplace/) - todas deram 403 "Invalid
   caller.id" ou 404 "resource not found", em TODAS as 4 lojas, o tempo todo. Nao e' bug de
   parametro - essa chamada especifica parece bloqueada pra essa conta/app.
   Solucao: em vez de perguntar pro ML "quais mensagens estao pendentes" (bloqueado), o Doca
   ESCUTA quando chega mensagem nova via webhook (topico "messages" - Felipe confirmou 21/08 que
   ja deixou todos os topicos marcados no cadastro do app) e guarda na tabela
   ml_mensagens_pendentes ate' o Felipe responder (dai' e' removida da lista - ver
   /mensagens/responder). GET num recurso especifico (1 mensagem por vez) nao parece ter o mesmo
   bloqueio da busca "tudo de uma vez" - mas isso so' fica confirmado de verdade quando uma
   notificacao real chegar; se der erro tambem, fica registrado no log do Render
   ("[webhook mensagens] falha ao processar notificacao").
   LIMITACAO REAL: mensagens que chegaram ANTES desse webhook estar funcionando nao aparecem
   sozinhas - so' as novas, a partir de agora que isso foi ligado. */
pool.query(`create table if not exists ml_mensagens_pendentes (
  id serial primary key,
  loja text not null,
  pack_id text not null,
  buyer_id text,
  titulo text,
  texto text,
  message_id text,
  data_mensagem timestamptz,
  criado_em timestamptz not null default now(),
  atualizado_em timestamptz not null default now(),
  unique(loja, pack_id)
)`).catch(e => console.error('Falha ao garantir tabela "ml_mensagens_pendentes":', e.message));

async function processarWebhookMensagem(userId, resource) {
  const rConta = await pool.query('select loja from ml_accounts where ml_user_id = $1', [String(userId)]);
  const loja = rConta.rows[0] && rConta.rows[0].loja;
  if (!loja) return; // notificacao de um user_id que nao e' nenhuma das nossas 4 lojas
  const accessToken = await tokenValido(loja);
  const conta = await pegarConta(loja);
  const sellerId = conta.ml_user_id;
  const detalhe = await fetchMLDebug(`https://api.mercadolibre.com${resource}`, { headers: { Authorization: `Bearer ${accessToken}` } });
  /* formato esperado (baseado na doc classica de "Get message by ID" - PRECISA confirmar que o
     recurso novo /marketplace/messages/{id} devolve igual): message_resources: [{id, name:"packs"},
     {id, name:"sellers"}]. Se vier diferente na pratica, cai no "nao consegui identificar" abaixo
     e fica logado - me manda esse log que eu ajusto o parsing rapido. */
  let packId = null;
  const recursos = detalhe.message_resources || [];
  const packRes = recursos.find(r => r.name === 'packs' || r.name === 'pack');
  if (packRes) packId = String(packRes.id);
  if (!packId && detalhe.resource === 'orders' && detalhe.resource_id) packId = String(detalhe.resource_id);
  if (!packId) {
    console.error('[webhook mensagens] nao consegui identificar o pack_id na resposta do recurso', resource, ':', JSON.stringify(detalhe).slice(0, 500));
    return;
  }
  const fromId = detalhe.from && detalhe.from.user_id;
  if (fromId && String(fromId) === String(sellerId)) return; // mensagem que o proprio vendedor mandou (por outro canal) - nao e' pendente de resposta
  let titulo = null;
  try {
    const rOrd = await fetch(`https://api.mercadolibre.com/orders/search?seller=${sellerId}&pack_id=${packId}`, { headers: { Authorization: `Bearer ${accessToken}` } });
    const jOrd = await rOrd.json();
    const pedido = (jOrd.results || [])[0];
    const oi = pedido && pedido.order_items && pedido.order_items[0];
    titulo = (oi && oi.item && oi.item.title) || null;
  } catch (e) { /* nao bloqueia - segue sem titulo */ }
  const texto = typeof detalhe.text === 'string' ? detalhe.text : ((detalhe.text && detalhe.text.plain) || '');
  const dataMsg = (detalhe.message_date && detalhe.message_date.received) || detalhe.date_received || detalhe.date || null;
  await pool.query(
    `insert into ml_mensagens_pendentes (loja, pack_id, buyer_id, titulo, texto, message_id, data_mensagem, atualizado_em)
     values ($1,$2,$3,$4,$5,$6,$7, now())
     on conflict (loja, pack_id) do update set
       buyer_id = excluded.buyer_id, titulo = coalesce(excluded.titulo, ml_mensagens_pendentes.titulo),
       texto = excluded.texto, message_id = excluded.message_id, data_mensagem = excluded.data_mensagem, atualizado_em = now()`,
    [loja, packId, fromId ? String(fromId) : null, titulo, texto, detalhe.id || detalhe.message_id || null, dataMsg]
  );
}
/* rota de diagnostico (so' LE, nao salva nada) - pra conferir o formato exato que o Mercado Livre
   devolve pra um recurso de mensagem especifico, sem precisar esperar um webhook real chegar.
   Ex.: /debug/mensagens/detalhe?loja=TorvStore&resource=/marketplace/messages/abc123 */
app.get('/debug/mensagens/detalhe', async (req, res) => {
  try {
    const loja = req.query.loja;
    const resource = req.query.resource;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!resource) return res.status(400).json({ ok: false, erro: 'Parametro "resource" obrigatorio (ex: /marketplace/messages/ID, vem no campo "resource" da notificacao do webhook).' });
    const accessToken = await tokenValido(loja);
    const detalhe = await fetchMLDebug(`https://api.mercadolibre.com${resource}`, { headers: { Authorization: `Bearer ${accessToken}` } });
    res.json({ ok: true, loja, resource, detalhe });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo }); }
});
/* rota de diagnostico (so' LE, nao manda nada) - a partir de um numero de pedido que o Felipe ja'
   sabe que tem mensagem (visto direto no Mercado Livre), acha o pack_id e o buyer_id, e busca a
   conversa (sem marcar como lida) - serve pra confirmar que o GET pontual funciona ANTES de tentar
   mandar mensagem de verdade. Ex.: /debug/mensagens/pack-do-pedido?loja=Orbix%20Brasil&orderId=2000014582806363 */
app.get('/debug/mensagens/pack-do-pedido', async (req, res) => {
  try {
    const loja = req.query.loja;
    const orderId = req.query.orderId;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!orderId) return res.status(400).json({ ok: false, erro: 'Parametro "orderId" obrigatorio (numero do pedido, visto no Mercado Livre).' });
    const accessToken = await tokenValido(loja);
    const conta = await pegarConta(loja);
    const pedido = await fetchMLDebug(`https://api.mercadolibre.com/orders/${orderId}`, { headers: { Authorization: `Bearer ${accessToken}` } });
    const packId = String(pedido.pack_id || pedido.id); // se pack_id vier vazio, usa o proprio id do pedido (mesmo criterio da doc oficial)
    const buyerId = pedido.buyer && pedido.buyer.id;
    let thread = null, erroThread = null;
    try {
      thread = await fetchMLDebug(`https://api.mercadolibre.com/messages/packs/${packId}/sellers/${conta.ml_user_id}?tag=post_sale&mark_as_read=false&limit=5&offset=0`, { headers: { Authorization: `Bearer ${accessToken}` } });
    } catch (e) { erroThread = e.message; }
    res.json({ ok: true, loja, orderId, packId, buyerId, thread, erroThread });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo }); }
});
/* rota de diagnostico que MANDA MENSAGEM DE VERDADE (nao e' so' leitura) - serve pra testar se o
   envio funciona nessa conta ANTES de depender do webhook, usando um pedido que o Felipe ja' sabe
   que tem conversa em aberto. Usa os mesmos dados/endpoint de /mensagens/responder. Ex.:
   /debug/mensagens/testar-envio?loja=Orbix%20Brasil&orderId=2000014582806363&texto=Ola! Como posso ajudar? */
app.get('/debug/mensagens/testar-envio', async (req, res) => {
  try {
    const loja = req.query.loja;
    const orderId = req.query.orderId;
    const texto = req.query.texto;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!orderId || !texto) return res.status(400).json({ ok: false, erro: 'Parametros "orderId" e "texto" obrigatorios.' });
    const accessToken = await tokenValido(loja);
    const conta = await pegarConta(loja);
    const pedido = await fetchMLDebug(`https://api.mercadolibre.com/orders/${orderId}`, { headers: { Authorization: `Bearer ${accessToken}` } });
    const packId = String(pedido.pack_id || pedido.id);
    const buyerId = pedido.buyer && pedido.buyer.id;
    if (!buyerId) return res.status(200).json({ ok: false, erro: 'Nao achei o buyer_id desse pedido.', pedido });
    const r = await fetch(`https://api.mercadolibre.com/messages/packs/${packId}/sellers/${conta.ml_user_id}?tag=post_sale`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: { user_id: String(conta.ml_user_id) }, to: { user_id: String(buyerId) }, text: texto })
    });
    const j = await r.json();
    if (!r.ok) return res.status(200).json({ ok: false, loja, orderId, packId, buyerId, erro: j.message || 'Falha ao enviar a mensagem.', corpo: j });
    res.json({ ok: true, loja, orderId, packId, buyerId, resposta: j });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo }); }
});
app.get('/mensagens', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    /* Felipe (21/08) pediu: so' mostrar mensagem das ultimas 24h - se for de dias anteriores e ainda
       nao foi respondida, ele ja deve ter cuidado direto no Mercado Livre, nao precisa continuar
       aparecendo aqui (evita acumular mensagem velha no card). Usa coalesce porque data_mensagem
       pode vir nula (se o parsing do webhook nao achou a data - nesse caso usa quando o Doca
       recebeu/salvou, que e' sempre preenchido). */
    const r = await pool.query(
      `select pack_id, buyer_id, titulo, texto, data_mensagem from ml_mensagens_pendentes
       where loja = $1 and coalesce(data_mensagem, criado_em) > now() - interval '24 hours'
       order by atualizado_em desc`,
      [loja]
    );
    const mensagens = r.rows.map(row => ({
      packId: row.pack_id, buyerId: row.buyer_id, titulo: row.titulo,
      ultimaMensagem: row.texto ? { texto: row.texto, data: row.data_mensagem } : null
    }));
    res.json({ ok: true, loja, mensagens });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo }); }
});
app.post('/mensagens/responder', async (req, res) => {
  try {
    const loja = req.query.loja || req.body?.loja;
    const packId = req.body?.packId;
    const buyerId = req.body?.buyerId;
    const texto = req.body?.texto;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!packId || !buyerId || !texto) return res.status(400).json({ ok: false, erro: 'Informe packId, buyerId e texto.' });
    if (String(texto).length > 2000) return res.status(400).json({ ok: false, erro: 'Resposta com mais de 2000 caracteres.' });
    const accessToken = await tokenValido(loja);
    const conta = await pegarConta(loja);
    const r = await fetch(`https://api.mercadolibre.com/messages/packs/${packId}/sellers/${conta.ml_user_id}?tag=post_sale`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: { user_id: String(conta.ml_user_id) }, to: { user_id: String(buyerId) }, text: texto })
    });
    const j = await r.json();
    if (!r.ok) return res.status(200).json({ ok: false, erro: j.message || 'Falha ao enviar a mensagem.', corpo: j });
    // ja' respondida - sai da lista de pendentes (ver comentario grande la' em cima, perto de
    // "Mensagens pos-venda", sobre por que isso e' alimentado por webhook e nao busca sob demanda)
    await pool.query('delete from ml_mensagens_pendentes where loja = $1 and pack_id = $2', [loja, String(packId)]).catch(e => console.error('Falha ao remover mensagem respondida da lista de pendentes:', e.message));
    res.json({ ok: true, resposta: j });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message, http_status: e.http_status, corpo: e.corpo }); }
});
/* ================= Sugestao de resposta pronta (IA) - Perguntas e Mensagens pos-venda =================
   Felipe (20/08) pediu: tanto em Perguntas quanto em Mensagens pos-venda, deixar uma resposta
   sugerida ja' pronta na caixa de texto, so' pra clicar Responder (ou editar antes). Usa a API do
   Claude (Anthropic) - precisa da variavel de ambiente ANTHROPIC_API_KEY no Render. Custo e'
   pequeno (poucos centavos por chamada, so' gera quando o Felipe abre o item pra responder). */
async function gerarSugestaoResposta({ tipo, texto, titulo }) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) throw new Error('Faltou a variavel de ambiente ANTHROPIC_API_KEY no Render (crie uma chave em console.anthropic.com).');
  const contexto = titulo ? ` Produto: "${titulo}".` : '';
  const instrucao = tipo === 'mensagem'
    ? 'Voce e um atendente de uma loja no Mercado Livre respondendo a uma MENSAGEM PRIVADA pos-venda de um cliente que ja comprou o produto (duvida, problema, ou pedido de informacao).'
    : 'Voce e um atendente de uma loja no Mercado Livre respondendo a uma PERGUNTA publica de um possivel comprador, feita ANTES da compra, direto no anuncio.';
  const prompt = `${instrucao}${contexto}

Mensagem do cliente: "${texto}"

Escreva uma resposta curta (1 a 3 frases), educada, direta e profissional, em portugues do Brasil, PRONTA pra ser enviada sem edicao - sem saudacao tipo "Prezado(a)" ou "Ola, tudo bem?" desnecessaria, sem assinatura no final. Se a pergunta pedir uma informacao especifica que voce nao tem (prazo exato de entrega, status daquele pedido especifico, etc), responda de forma generica mas util, sem inventar numero ou prazo que voce nao sabe. Responda so' com o texto da mensagem, nada mais.`;
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 300, messages: [{ role: 'user', content: prompt }] })
  });
  const j = await r.json();
  if (!r.ok) throw new Error('Falha ao gerar sugestao: ' + ((j.error && j.error.message) || JSON.stringify(j)));
  const textoResposta = (j.content || []).map(c => c.text || '').join('').trim();
  if (!textoResposta) throw new Error('A IA nao devolveu texto de sugestao.');
  return textoResposta;
}
app.post('/sugestao/resposta', async (req, res) => {
  try {
    const { tipo, texto, titulo } = req.body || {};
    if (!texto) return res.status(400).json({ ok: false, erro: 'Informe "texto".' });
    const sugestao = await gerarSugestaoResposta({ tipo: tipo === 'mensagem' ? 'mensagem' : 'pergunta', texto, titulo: titulo || null });
    res.json({ ok: true, sugestao });
  } catch (e) { res.status(200).json({ ok: false, erro: e.message }); }
});

app.post('/sync', async (req, res) => {
const loja = req.query.loja || req.body?.loja;
  if (!LOJAS_VALIDAS.includes(loja)) {
    return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
  }
  /* "Entrada Pendente 2.0" (28/08): lista de ml_item_id que o front avisa terem algo "em
     processamento" (envio confirmado como FULL, aguardando o ML mostrar o recebimento - ver
     confirmarEnvioFull/fullCalc no doca.html). So' pra esses e' que vale a pena gastar uma
     chamada extra pro log real de recebimento (buscarRecebimentosFull) - resto do catalogo fica
     sem nada em processamento na maior parte do tempo, gastar a chamada a toa so' deixa o /sync
     mais lento sem necessidade. */
  const pendentesSet = new Set(String(req.query.pendentes || req.body?.pendentes || '').split(',').map(s => s.trim()).filter(Boolean));
  let logId = null;
  try {
    const logInsert = await pool.query(
      'insert into ml_sync_log (loja) values ($1) returning id', [loja]
    );
    logId = logInsert.rows[0].id;
    const accessToken = await tokenValido(loja);
    const conta = await pegarConta(loja);
    const itens = await buscarItensDoVendedor(loja, accessToken, conta.ml_user_id);
    let mapaPerguntas = new Map();
    try {
      mapaPerguntas = await buscarPerguntasSemResposta(accessToken, conta.ml_user_id);
    } catch (e) {
      console.error('Falha ao buscar perguntas (seguindo sem essa info):', e.message);
    }
    let mapaVendas = new Map();
    try {
      mapaVendas = await buscarVendasPorItem(accessToken, conta.ml_user_id);
    } catch (e) {
      console.error('Falha ao buscar vendas (seguindo sem essa info):', e.message);
    }
    /* reclamacoes e mediacoes (claims) - roda automaticamente a cada sincronizacao (ao abrir o
       Doca ou apertar Atualizar), aplicando a regra do Felipe (frete vendedor -> devolucao,
       senao -> reembolso 100%). Nao trava o /sync se falhar - fica registrado nos avisos e o
       relatorio completo pode ser conferido em /reclamacoes/relatorio?loja=... */
    let relatorioReclamacoes = null;
    try {
      relatorioReclamacoes = await processarReclamacoesDaLoja(loja);
    } catch (e) {
      console.error('Falha ao processar reclamacoes automaticamente (seguindo sem essa etapa):', e.message);
    }
    for (const it of itens) {
      let concorrencia = null;
      if (it.catalog_listing === true) {
        concorrencia = await buscarConcorrenciaCatalogo(accessToken, it.id);
      }
      let transferenciaFull = null;
      if (it.inventory_id) {
        transferenciaFull = await buscarTransferenciaFull(accessToken, conta.ml_user_id, it.inventory_id);
      }
      let recebimentosFull = null;
      if (it.inventory_id && pendentesSet.has(it.id)) {
        recebimentosFull = await buscarRecebimentosFull(accessToken, conta.ml_user_id, it.inventory_id, 6);
      }
      const vendas = mapaVendas.get(it.id) || { v7: 0, v15: 0, v30: 0 };
      console.log(`[sync-item] id=${it.id} sku=${extrairSku(it)} titulo="${(it.title||'').slice(0,30)}" vendas=${JSON.stringify(vendas)}`);
      await pool.query(
        `insert into ml_produtos (loja, ml_item_id, sku, titulo, quantidade_disponivel, preco, status, catalog_listing, concorrencia_status, concorrencia_preco, perguntas_sem_resposta, vendas_7d, vendas_15d, vendas_30d, transferencia_full, categoria_id, recebimentos_full, atualizado_em)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17, now())
         on conflict (loja, ml_item_id) do update set
           sku = excluded.sku, titulo = excluded.titulo,
           quantidade_disponivel = excluded.quantidade_disponivel,
           preco = excluded.preco, status = excluded.status,
           catalog_listing = excluded.catalog_listing,
           concorrencia_status = excluded.concorrencia_status,
           concorrencia_preco = excluded.concorrencia_preco,
           perguntas_sem_resposta = excluded.perguntas_sem_resposta,
           vendas_7d = excluded.vendas_7d, vendas_15d = excluded.vendas_15d, vendas_30d = excluded.vendas_30d,
           transferencia_full = excluded.transferencia_full, categoria_id = excluded.categoria_id,
           recebimentos_full = coalesce(excluded.recebimentos_full, ml_produtos.recebimentos_full),
           atualizado_em = now()`,
        [
          loja, it.id,
          extrairSku(it),
          it.title || '',
          it.available_quantity ?? 0,
          it.price ?? null,
          it.status || '',
          it.catalog_listing === true,
          concorrencia ? concorrencia.status : null,
          concorrencia ? concorrencia.precoConcorrente : null,
          mapaPerguntas.get(it.id) || 0,
          vendas.v7, vendas.v15, vendas.v30,
          transferenciaFull,
          it.category_id || null,
          recebimentosFull ? JSON.stringify(recebimentosFull) : null
        ]
      );
    }
    /* achado com dado real do Felipe 23/08: um anuncio CANCELADO no Mercado Livre some da
       listagem /users/{id}/items/search (buscarItensDoVendedor) - o loop acima so' faz UPSERT
       dos itens que vieram na resposta, entao a linha desse anuncio em ml_produtos ficava
       congelada pra sempre com o ultimo status conhecido (ex: "paused"), porque nada nunca
       marcava ela como fechada. O Doca (frontend) ate' tem logica pra tratar status="closed"
       como "sumiu, ignora" (marcarAusentesNoML), mas dependia do BACKEND ja' ter marcado assim -
       o que nunca acontecia. Aqui fecha o buraco: qualquer linha dessa loja que nao veio nesta
       sincronizacao (e ainda nao estava "closed") vira "closed" agora. So' roda quando a
       sincronizacao trouxe pelo menos 1 item - se vier vazia (ex: falha passageira da API do
       ML), nao mexe em nada, pra nao fechar a loja inteira por engano numa falha transitoria. */
    if (itens.length > 0) {
      const idsAtuais = itens.map(it => it.id);
      await pool.query(
        `update ml_produtos set status = 'closed', atualizado_em = now()
         where loja = $1 and status <> 'closed' and not (ml_item_id = any($2::text[]))`,
        [loja, idsAtuais]
      );
    }
    await pool.query(
      'update ml_sync_log set concluido_em = now(), itens_sincronizados = $2 where id = $1',
      [logId, itens.length]
    );
    res.json({ ok: true, loja, itensSincronizados: itens.length, atualizadoEm: new Date().toISOString(), reclamacoes: relatorioReclamacoes });
  } catch (e) {
    console.error('Erro no /sync:', e);
    if (logId != null) {
      try {
        await pool.query('update ml_sync_log set concluido_em = now(), erro = $2 where id = $1', [logId, e.message]);
      } catch (e2) {
        console.error('Falha ao gravar log de erro:', e2);
      }
    }
    res.status(500).json({ ok: false, erro: e.message });
  }
});
app.get('/data', async (req, res) => {
  const loja = req.query.loja;
  if (!LOJAS_VALIDAS.includes(loja)) {
    return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
  }
  try {
    const conta = await pegarConta(loja);
    const produtos = await pool.query(
      'select ml_item_id, sku, titulo, quantidade_disponivel, preco, status, catalog_listing, concorrencia_status, concorrencia_preco, perguntas_sem_resposta, vendas_7d, vendas_15d, vendas_30d, transferencia_full, recebimentos_full, atualizado_em from ml_produtos where loja = $1 order by titulo',
      [loja]
    );
    res.json({
      ok: true,
      loja,
      autorizado: !!conta,
      ultimaAtualizacao: conta ? conta.atualizado_em : null,
      produtos: produtos.rows
    });
  } catch (e) {
    console.error('Erro no /data:', e);
    res.status(500).json({ ok: false, erro: e.message });
  }
});
/* ================= Analise de Mercado (21/08) =================
   Compara as vendas do PRODUTO com as vendas da CATEGORIA inteira no Mercado Livre, mes a mes.
   Nao existe API publica pro painel "Analise de mercado" do vendedor (tendencias por categoria,
   concorrencia) - so' da pra ver logado, direto no navegador. Por isso os numeros da CATEGORIA sao
   alimentados a mao (Felipe manda o print de vendedores.mercadolivre.com.br/metricas/analise-de-
   mercado/tendencias-por-categorias/detalhe?category_id=X, eu registro o mes corrente aqui) - mes
   a mes vai formando um historico proprio, dentro do Doca, pra comparar com a sazonalidade.
   Ja' as vendas PROPRIAS de cada mes sao 100% automaticas (calculadas a partir do historico real
   de pedidos, reaproveitando buscarPedidosNoIntervalo). */
function mesReferencia(anoMes) {
  // "anoMes" no formato "YYYY-MM" -> limites do mes em ISO com fuso America/Sao_Paulo (-03:00)
  const [ano, mes] = anoMes.split('-').map(Number);
  const de = `${ano}-${String(mes).padStart(2, '0')}-01T00:00:00-03:00`;
  const proxAno = mes === 12 ? ano + 1 : ano;
  const proxMes = mes === 12 ? 1 : mes + 1;
  const ate = `${proxAno}-${String(proxMes).padStart(2, '0')}-01T00:00:00-03:00`;
  return { de, ate };
}
function ultimosMeses(qtd) {
  // lista de "YYYY-MM" dos ultimos "qtd" meses (incluindo o mes corrente), do mais antigo pro mais novo
  const hojeBR = diaBR(new Date().toISOString()); // "YYYY-MM-DD" em America/Sao_Paulo
  let [ano, mes] = hojeBR.split('-').slice(0, 2).map(Number);
  const meses = [];
  for (let i = qtd - 1; i >= 0; i--) {
    let a = ano, m = mes - i;
    while (m <= 0) { m += 12; a -= 1; }
    meses.push(`${a}-${String(m).padStart(2, '0')}`);
  }
  return meses;
}
app.get('/mercado/produtos', async (req, res) => {
  const loja = req.query.loja;
  if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
  try {
    const r = await pool.query('select ml_item_id, sku, titulo, categoria_id from ml_produtos where loja = $1 order by titulo', [loja]);
    res.json({ ok: true, produtos: r.rows });
  } catch (e) {
    console.error('Erro no /mercado/produtos:', e);
    res.status(500).json({ ok: false, erro: e.message });
  }
});
app.get('/mercado/categoria', async (req, res) => {
  const loja = req.query.loja;
  const itemId = req.query.itemId;
  if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
  if (!itemId) return res.status(400).json({ ok: false, erro: 'Informe itemId.' });
  try {
    const prod = await pool.query('select categoria_id, titulo, sku from ml_produtos where loja = $1 and ml_item_id = $2', [loja, itemId]);
    const historico = await pool.query(
      `select mes, vendas_brutas_categoria, unidades_categoria, preco_medio_categoria,
              periodo_de, periodo_ate, categoria_nome, produtos_analisados, top_produtos, fonte
       from ml_mercado_categoria where loja = $1 and ml_item_id = $2 order by mes`,
      [loja, itemId]
    );
    const categoriaId = prod.rows[0] && prod.rows[0].categoria_id;
    // o category_id que a API normal devolve vem com o prefixo da letra do site (ex: "MLB244659"),
    // mas essa pagina especifica de tendencias por categoria so' aceita a parte numerica (ex:
    // "244659") - sem isso a pagina cai direto em "Ocorreu um erro" (achado com teste real do
    // Felipe, 21/08: o link gerado com "MLB244659" quebrava, o exemplo funcional dele usava so' "244659").
    const categoriaIdNumerica = categoriaId ? categoriaId.replace(/^\D+/, '') : null;
    res.json({
      ok: true,
      categoriaId: categoriaId || null,
      urlTendencia: categoriaIdNumerica ? `https://vendedores.mercadolivre.com.br/metricas/analise-de-mercado/tendencias-por-categorias/detalhe?category_id=${categoriaIdNumerica}&period=currentMonth` : null,
      titulo: prod.rows[0] ? prod.rows[0].titulo : null,
      sku: prod.rows[0] ? prod.rows[0].sku : null,
      historico: historico.rows
    });
  } catch (e) {
    console.error('Erro no /mercado/categoria (get):', e);
    res.status(500).json({ ok: false, erro: e.message });
  }
});
app.post('/mercado/categoria', async (req, res) => {
  try {
    const {
      loja, itemId, mes, vendasBrutas, unidades, precoMedio,
      periodoDe, periodoAte, categoriaNome, produtosAnalisados, topProdutos, fonte
    } = req.body || {};
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!itemId) return res.status(400).json({ ok: false, erro: 'Informe itemId.' });
    // "mes" e' so' uma CHAVE de identificacao do periodo (nao precisa ser um mes civil de verdade):
    // digitacao manual manda "YYYY-MM"; importacao de .xlsx manda "YYYY-MM-DD_a_YYYY-MM-DD" (o
    // periodo exato que o Mercado Livre usou no relatorio, que pode ser qualquer intervalo).
    const mesRegexOk = /^\d{4}-\d{2}$/.test(mes || '') || /^\d{4}-\d{2}-\d{2}_a_\d{4}-\d{2}-\d{2}$/.test(mes || '');
    if (!mesRegexOk) return res.status(400).json({ ok: false, erro: 'Informe mes no formato YYYY-MM (ou um periodo valido).' });
    // top_produtos vem como array (top ~20 linhas do relatorio) - guarda so' o necessario pra
    // mostrar um ranking, sem virar um payload gigante (o relatorio inteiro tem ate' 100 linhas).
    const topProdutosSeguro = Array.isArray(topProdutos) ? topProdutos.slice(0, 20) : null;
    await pool.query(
      `insert into ml_mercado_categoria (
         loja, ml_item_id, mes, vendas_brutas_categoria, unidades_categoria, preco_medio_categoria,
         periodo_de, periodo_ate, categoria_nome, produtos_analisados, top_produtos, fonte, atualizado_em
       )
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12, now())
       on conflict (loja, ml_item_id, mes) do update set
         vendas_brutas_categoria = excluded.vendas_brutas_categoria,
         unidades_categoria = excluded.unidades_categoria,
         preco_medio_categoria = excluded.preco_medio_categoria,
         periodo_de = excluded.periodo_de,
         periodo_ate = excluded.periodo_ate,
         categoria_nome = excluded.categoria_nome,
         produtos_analisados = excluded.produtos_analisados,
         top_produtos = excluded.top_produtos,
         fonte = excluded.fonte,
         atualizado_em = now()`,
      [
        loja, itemId, mes, vendasBrutas ?? null, unidades ?? null, precoMedio ?? null,
        periodoDe || null, periodoAte || null, categoriaNome || null, produtosAnalisados ?? null,
        topProdutosSeguro ? JSON.stringify(topProdutosSeguro) : null, fonte || 'manual'
      ]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('Erro no /mercado/categoria (post):', e);
    res.status(500).json({ ok: false, erro: e.message });
  }
});
app.delete('/mercado/categoria', async (req, res) => {
  try {
    const { loja, itemId, mes } = req.query;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    await pool.query('delete from ml_mercado_categoria where loja = $1 and ml_item_id = $2 and mes = $3', [loja, itemId, mes]);
    res.json({ ok: true });
  } catch (e) {
    console.error('Erro no /mercado/categoria (delete):', e);
    res.status(500).json({ ok: false, erro: e.message });
  }
});
/* vendas PROPRIAS do produto, mes a mes (calculado, nao precisa print) - reaproveita a mesma
   busca de pedidos usada no /sync, so' que agrupada por mes civil (fuso America/Sao_Paulo) em vez
   de janela corrida de 7/15/30 dias. */
function somarVendasDoItem(pedidos, itemId) {
  const statusExcluidos = new Set(['cancelled', 'invalid']);
  let unidades = 0, valorBruto = 0;
  for (const pedido of pedidos) {
    if (statusExcluidos.has(pedido.status)) continue;
    for (const oi of (pedido.order_items || [])) {
      if (!oi.item || oi.item.id !== itemId) continue;
      const qtd = oi.quantity || 0;
      unidades += qtd;
      valorBruto += qtd * (oi.unit_price || 0);
    }
  }
  return { unidades, valorBruto: Math.round(valorBruto * 100) / 100 };
}
app.get('/mercado/vendas-proprias', async (req, res) => {
  const loja = req.query.loja;
  const itemId = req.query.itemId;
  // "de"/"ate" (opcionais, YYYY-MM-DD) pedem o total de UM periodo exato - usado pra comparar com
  // um periodo importado de um relatorio .xlsx (que raramente e' um mes civil fechado). Sem isso,
  // cai no comportamento antigo: quebra por mes civil, dos ultimos "meses" meses.
  if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
  if (!itemId) return res.status(400).json({ ok: false, erro: 'Informe itemId.' });
  try {
    const conta = await pegarConta(loja);
    if (!conta) return res.status(400).json({ ok: false, erro: `A loja "${loja}" ainda nao foi autorizada.` });
    const accessToken = await tokenValido(loja);
    const sellerId = conta.ml_user_id;
    const log = { avisos: [] };
    if (req.query.de && req.query.ate) {
      // 21/08 (achado real do Felipe): ele esticou o periodo pra 1 ano inteiro (2025-08-01 a
      // 2026-08-21) na tela de importacao, e isso tentou buscar TODOS os pedidos da loja inteira
      // num intervalo de 365 dias numa unica chamada - pesado o suficiente pra travar o servidor
      // por um bom tempo e derrubar outras chamadas em paralelo com 429. Esse endpoint foi feito
      // pra comparar com um periodo de relatorio (normalmente ~21 dias), entao trava aqui num
      // maximo generoso (120 dias) em vez de deixar o servidor tentar e sofrer.
      const diasSpan = (new Date(`${req.query.ate}T00:00:00-03:00`) - new Date(`${req.query.de}T00:00:00-03:00`)) / 86400000;
      if (diasSpan > 120) {
        return res.status(400).json({ ok: false, erro: `Periodo de ${Math.round(diasSpan)} dias e' longo demais pra calcular de uma vez (max 120 dias). Pra comparar sazonalidade mes a mes ao longo de mais de um ano, use os campos de "Sazonalidade mensal" (um mes por vez) em vez de esticar esse periodo.` });
      }
      const de = `${req.query.de}T00:00:00-03:00`;
      const ate = `${req.query.ate}T23:59:59-03:00`;
      const pedidos = await buscarPedidosNoIntervalo(accessToken, sellerId, de, ate, log, 'order.date_closed');
      const totalPeriodo = somarVendasDoItem(pedidos, itemId);
      return res.json({ ok: true, periodo: { de: req.query.de, ate: req.query.ate }, ...totalPeriodo, avisos: log.avisos });
    }
    const meses = Math.min(Math.max(parseInt(req.query.meses, 10) || 12, 1), 24);
    const listaMeses = ultimosMeses(meses);
    const porMes = [];
    for (const mes of listaMeses) {
      const { de, ate } = mesReferencia(mes);
      const pedidos = await buscarPedidosNoIntervalo(accessToken, sellerId, de, ate, log, 'order.date_closed');
      const { unidades, valorBruto } = somarVendasDoItem(pedidos, itemId);
      porMes.push({ mes, unidades, valorBruto });
    }
    res.json({ ok: true, meses: porMes, avisos: log.avisos });
  } catch (e) {
    console.error('Erro no /mercado/vendas-proprias:', e);
    res.status(500).json({ ok: false, erro: e.message });
  }
});
/* relatorio compartilhavel (link publico, sem login) - depois de gerar o fechamento de todas as
   lojas, poder mandar um link por WhatsApp pra alguem abrir os dados sem precisar entrar no Doca. */
app.post('/relatorio', async (req, res) => {
  try {
    const html = req.body && req.body.html;
    if (!html || typeof html !== 'string' || html.length < 20) {
      return res.status(400).json({ ok: false, erro: 'Corpo "html" obrigatorio.' });
    }
    if (html.length > 2000000) {
      return res.status(400).json({ ok: false, erro: 'Relatorio grande demais pra compartilhar.' });
    }
    const id = base64url(crypto.randomBytes(9));
    await pool.query('insert into relatorios (id, html, criado_em) values ($1, $2, now())', [id, html]);
    pool.query("delete from relatorios where criado_em < now() - interval '30 days'").catch(() => {});
    res.json({ ok: true, id });
  } catch (e) {
    console.error('Erro no /relatorio (post):', e);
    res.status(500).json({ ok: false, erro: e.message });
  }
});
app.get('/relatorio/:id', async (req, res) => {
  try {
    const r = await pool.query('select html from relatorios where id = $1', [req.params.id]);
    if (!r.rows.length) return res.status(404).type('text/html').send('<!doctype html><meta charset="utf-8"><body style="font-family:sans-serif;padding:40px;text-align:center;color:#333"><h2>Relatório não encontrado</h2><p>O link pode ter expirado (relatórios ficam disponíveis por 30 dias).</p></body>');
    res.type('text/html').send(r.rows[0].html);
  } catch (e) {
    console.error('Erro no /relatorio/:id (get):', e);
    res.status(500).type('text/html').send('<!doctype html><meta charset="utf-8"><body style="font-family:sans-serif;padding:40px;text-align:center;color:#333"><h2>Erro ao carregar o relatório</h2></body>');
  }
});
app.get('/loading-video.mp4', (req, res) => {
  res.sendFile(path.join(__dirname, 'loading-video.mp4'), {
    maxAge: 0,
    headers: { 'Content-Type': 'video/mp4', 'Cache-Control': 'no-cache' }
  }, (err) => {
    if (err) { console.error('Erro ao servir loading-video.mp4:', err.message); if (!res.headersSent) res.status(404).send('Video nao encontrado no servidor.'); }
  });
});
process.on('unhandledRejection', (e) => console.error('unhandledRejection:', e));
app.listen(PORT, () => console.log(`Doca ML sync backend rodando na porta ${PORT}`));
