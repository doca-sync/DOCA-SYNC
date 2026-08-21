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
const app = express();
app.use(express.json({ limit: '10mb' })); // o estado inteiro do Doca (produtos, envios, historico) pode passar de 100kb (limite padrao)
const allowedOrigins = ALLOWED_ORIGIN.split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: allowedOrigins.includes('*') ? true : allowedOrigins,
  methods: ['GET', 'POST']
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
    const { topic, user_id } = req.body || {};
    if (topic && String(topic).toLowerCase().includes('claim') && user_id) {
      const r = await pool.query('select loja from ml_accounts where ml_user_id = $1', [String(user_id)]);
      const loja = r.rows[0] && r.rows[0].loja;
      if (loja) {
        processarReclamacoesDaLoja(loja).catch(e => console.error('[webhook claims] falha ao processar', loja, e.message));
      }
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

/* determina se o frete desse pedido foi absorvido pelo vendedor (custo em senders[].cost em
   /shipments/{id}/costs > 0) - MESMO metodo ja usado e validado em todo o resto do arquivo
   (Resumo Financeiro, Auditoria) pra calcular o "Frete vendedor". */
async function freteFoiDoVendedor(accessToken, shippingId) {
  if (!shippingId) return { absorvidoPeloVendedor: null, valor: null };
  try {
    const j = await fetchMLDebug(`https://api.mercadolibre.com/shipments/${shippingId}/costs`, { headers: { Authorization: `Bearer ${accessToken}` } });
    const valor = (j.senders || []).reduce((s, r) => s + (Number(r.cost) || 0), 0);
    return { absorvidoPeloVendedor: valor > 0, valor };
  } catch (e) {
    return { absorvidoPeloVendedor: null, valor: null, erro: e.message };
  }
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
  let shippingId = null;
  try {
    const pedido = await fetchMLDebug(`https://api.mercadolibre.com/orders/${orderId}`, { headers: { Authorization: `Bearer ${accessToken}` } });
    shippingId = pedido.shipping && pedido.shipping.id;
  } catch (e) {
    await salvarLogReclamacao(loja, claimId, { orderId, reasonId: claim.reason_id, sucesso: false, motivo: 'falha ao buscar o pedido: ' + e.message });
    return { claimId, erro: e.message };
  }
  const { absorvidoPeloVendedor, valor, erro: erroFrete } = await freteFoiDoVendedor(accessToken, shippingId);
  if (absorvidoPeloVendedor === null) {
    await salvarLogReclamacao(loja, claimId, { orderId, reasonId: claim.reason_id, sucesso: false, motivo: 'nao foi possivel determinar o frete desse pedido' + (erroFrete ? ': ' + erroFrete : '') });
    return { claimId, erro: 'sem frete' };
  }
  const respondent = (claim.players || []).find(p => p.role === 'respondent') || {};
  const acoes = (respondent.available_actions || []).map(a => a.action);
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
    /* texto da mensagem depende de qual regra caiu: se o frete foi do vendedor a regra pedia
       devolucao (so' nao rolou por falta de botao), entao a mensagem tem que OFERECER devolucao
       junto com o reembolso - "sem devolucao" so' vale quando o frete nao era do vendedor (regra 2).
       Corrigido em 20/08 a pedido do Felipe - antes mandava sempre "sem devolucao", errado pro caso
       de frete gratis pro vendedor. */
    const textoMensagem = absorvidoPeloVendedor ? 'Reembolso de 100% com devolução.' : 'Reembolso de 100% sem devolução.';
    const disponiveis = candidatos.filter(c => acoes.includes(c.acao));
    if (!disponiveis.length) {
      await salvarLogReclamacao(loja, claimId, { orderId, reasonId: claim.reason_id, freteVendedor: absorvidoPeloVendedor, valorFreteVendedor: valor, sucesso: false, motivo: motivoAcaoIndisponivel + ` - e nem mensagem pro comprador/mediador esta disponivel nessa reclamacao (estagio: ${claim.stage || '?'}) - precisa revisao manual` });
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
        await salvarLogReclamacao(loja, claimId, { orderId, reasonId: claim.reason_id, freteVendedor: absorvidoPeloVendedor, valorFreteVendedor: valor, acaoTomada: `mensagem pro ${c.role === 'mediator' ? 'mediador' : 'comprador'}: ${textoMensagem} (sem botão de ação formal disponível)`, sucesso: true, motivo: motivoAcaoIndisponivel + ` - mandada mensagem (estagio: ${claim.stage || '?'}): "${textoMensagem}", no lugar da ação formal` });
        return { claimId, ok: true, acao: 'mensagem-reembolso' };
      } catch (e) {
        ultimoErro = e;
      }
    }
    await salvarLogReclamacao(loja, claimId, { orderId, reasonId: claim.reason_id, freteVendedor: absorvidoPeloVendedor, valorFreteVendedor: valor, sucesso: false, motivo: motivoAcaoIndisponivel + ' - falha ao mandar a mensagem de reembolso: ' + (ultimoErro && ultimoErro.message) });
    return { claimId, erro: ultimoErro && ultimoErro.message };
  }
  if (absorvidoPeloVendedor) {
    // regra 1: frete gratis pro vendedor -> devolucao
    if (!acoes.includes('allow_return') && !acoes.includes('allow_return_label')) {
      return tentarFallbackMensagem('frete foi do vendedor (deveria virar devolucao), mas a acao "allow_return"/"allow_return_label" ainda nao esta disponivel nessa reclamacao');
    }
    try {
      await fetchMLDebug(`https://api.mercadolibre.com/post-purchase/v1/claims/${claimId}/expected-resolutions/allow-return`, {
        method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' }
      });
      await salvarLogReclamacao(loja, claimId, { orderId, reasonId: claim.reason_id, freteVendedor: true, valorFreteVendedor: valor, acaoTomada: 'devolucao (allow-return)', sucesso: true, motivo: 'frete gratis pro vendedor - devolucao oferecida automaticamente' });
      return { claimId, ok: true, acao: 'devolucao' };
    } catch (e) {
      await salvarLogReclamacao(loja, claimId, { orderId, reasonId: claim.reason_id, freteVendedor: true, valorFreteVendedor: valor, sucesso: false, motivo: 'falha ao oferecer devolucao: ' + e.message });
      return { claimId, erro: e.message };
    }
  } else {
    // regra 2: frete NAO foi do vendedor -> reembolso 100% sem devolucao
    if (!acoes.includes('refund')) {
      return tentarFallbackMensagem('frete nao foi do vendedor (deveria virar reembolso 100%), mas a acao "refund" ainda nao esta disponivel nessa reclamacao');
    }
    try {
      await fetchMLDebug(`https://api.mercadolibre.com/post-purchase/v1/claims/${claimId}/expected-resolutions/refund`, {
        method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' }
      });
      await salvarLogReclamacao(loja, claimId, { orderId, reasonId: claim.reason_id, freteVendedor: false, valorFreteVendedor: valor, acaoTomada: 'reembolso 100% (refund)', sucesso: true, motivo: 'frete nao era do vendedor - reembolso 100% aplicado automaticamente, sem devolucao' });
      return { claimId, ok: true, acao: 'reembolso' };
    } catch (e) {
      await salvarLogReclamacao(loja, claimId, { orderId, reasonId: claim.reason_id, freteVendedor: false, valorFreteVendedor: valor, sucesso: false, motivo: 'falha ao aplicar reembolso: ' + e.message });
      return { claimId, erro: e.message };
    }
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
    let shippingId = null, orderErro = null;
    try {
      const pedido = await fetchMLDebug(`https://api.mercadolibre.com/orders/${claim.resource_id}`, { headers: { Authorization: `Bearer ${accessToken}` } });
      shippingId = pedido.shipping && pedido.shipping.id;
    } catch (e) { orderErro = e.message; }
    const frete = await freteFoiDoVendedor(accessToken, shippingId);
    const respondent = (claim.players || []).find(p => p.role === 'respondent') || {};
    const acoes = (respondent.available_actions || []).map(a => a.action);
    let regraAplicavel = null;
    // dado real (20/08): reclamacao em mediacao (stage "dispute") so' oferece send_message_to_mediator,
    // nao send_message_to_complainant (que so' existe no estagio "claim") - simula os dois certinho
    const papelFallback = claim.stage === 'dispute' ? 'mediator' : 'complainant';
    const acaoFallback = claim.stage === 'dispute' ? 'send_message_to_mediator' : 'send_message_to_complainant';
    const temFallbackMensagem = acoes.includes(acaoFallback) || acoes.includes('send_message_to_complainant') || acoes.includes('send_message_to_mediator');
    // texto do fallback depende do frete: gratis pro vendedor -> oferece devolucao junto; senao -> sem devolucao
    // (mesma logica de tentarFallbackMensagem la' embaixo, corrigido em 20/08)
    const textoFallbackSimulado = frete.absorvidoPeloVendedor ? 'reembolso 100% com devolucao' : 'reembolso 100% sem devolucao';
    const fallbackTxt = temFallbackMensagem ? `cairia no fallback: mensagem pro ${papelFallback === 'mediator' ? 'mediador' : 'comprador'} "${textoFallbackSimulado}" (estagio: ${claim.stage || '?'})` : `fallback de mensagem tambem indisponivel (estagio: ${claim.stage || '?'}) - ficaria pendente`;
    if (claim.resource !== 'order') regraAplicavel = 'fora da regra (resource != order)';
    else if (frete.absorvidoPeloVendedor === true) regraAplicavel = (acoes.includes('allow_return') || acoes.includes('allow_return_label')) ? 'devolucao (acao disponivel)' : `devolucao indisponivel - ${fallbackTxt}`;
    else if (frete.absorvidoPeloVendedor === false) regraAplicavel = acoes.includes('refund') ? 'reembolso 100% (acao disponivel)' : `reembolso indisponivel - ${fallbackTxt}`;
    else regraAplicavel = 'nao foi possivel determinar o frete';
    res.json({ ok: true, loja, claimId, resource: claim.resource, reasonId: claim.reason_id, orderId: claim.resource_id, stage: claim.stage, orderErro, shippingId, frete, acoesDisponiveisVendedor: acoes, regraAplicavel, claim });
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
    const dias = Math.max(1, Math.min(90, parseInt(req.query.dias || '14', 10)));
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const r = await pool.query(
      `select claim_id, order_id, reason_id, frete_vendedor, valor_frete_vendedor, acao_tomada, sucesso, motivo, tentativas, criado_em, atualizado_em
       from ml_reclamacoes_log where loja = $1 and atualizado_em > now() - interval '${dias} days'
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
   Os jobs ficam guardados em memoria (somem se o servidor reiniciar/dormir - normal no Render
   free tier apos inatividade) - por isso é pra rodar e acompanhar na hora, não é histórico. */
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
    let tarifaAssumida = 0, tarifaReal = 0, freteViaShipments = 0;
    let pedidosPendentesRepasse = 0, valorPendenteRepasse = 0;
    const anomalias = [];
    const agora = Date.now();
    const pagamentosContados = new Set();
    const shipmentsContados = new Set();
    let pedidosMesmoCarrinho = 0;
    for (const p of auditaveis) {
      const cancelado = p.status === 'cancelled';
      const totalPedido = Number(p.total_amount) || 0;
      if (cancelado) cancelamentosValor += totalPedido; else faturamento += totalPedido;
      let saleFeeDoPedido = 0;
      for (const oi of (p.order_items || [])) saleFeeDoPedido += (Number(oi.sale_fee) || 0) * (oi.quantity || 1);
      tarifaAssumida += saleFeeDoPedido;
      if (p.shipping && p.shipping.id && !shipmentsContados.has(p.shipping.id)) {
        shipmentsContados.add(p.shipping.id);
        try {
          const j = await fetchMLDebug(`https://api.mercadolibre.com/shipments/${p.shipping.id}/costs`, { headers: { Authorization: `Bearer ${accessToken}` } });
          freteViaShipments += (j.senders || []).reduce((s, r) => s + (Number(r.cost) || 0), 0);
        } catch (e) { /* ignora falha pontual - mesmo comportamento tolerante do dia a dia */ }
      }
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
        const cobrancas = (jp.charges_details || []).filter(c => c.accounts && c.accounts.from === 'collector');
        const temComissaoReal = cobrancas.some(c => c.name === 'ml_sale_fee' || c.name === 'mp_processing_fee');
        const valorComissaoReal = cobrancas.filter(c => c.name === 'ml_sale_fee' || c.name === 'mp_processing_fee').reduce((s, c) => s + ((c.amounts && c.amounts.original) || 0), 0);
        tarifaReal += valorComissaoReal;
        if (cancelado && !temComissaoReal && saleFeeDoPedido > 0.009) {
          anomalias.push({ pedido_id: p.id, motivo: 'Pedido cancelado: comissao NAO foi cobrada de verdade (devolvida) - o calculo do dia a dia estava contando indevidamente', total: totalPedido, sale_fee_assumido: round2(saleFeeDoPedido) });
        } else if (!cancelado && Math.abs(valorComissaoReal - saleFeeDoPedido) > 1) {
          anomalias.push({ pedido_id: p.id, motivo: 'Comissao cobrada de verdade veio diferente do sale_fee declarado no pedido (diferenca > R$1 - pode ser cupom, financiamento etc)', total: totalPedido, sale_fee_assumido: round2(saleFeeDoPedido), sale_fee_real: round2(valorComissaoReal) });
        }
        if (!cancelado) {
          const dataAprovacao = pgAprovado.date_approved ? new Date(pgAprovado.date_approved).getTime() : null;
          const diasDesde = dataAprovacao ? (agora - dataAprovacao) / 86400000 : null;
          const statusRepasse = jp.money_release_status;
          if (diasDesde != null && diasDesde > DIAS_LIMITE_REPASSE && statusRepasse && statusRepasse !== 'released') {
            pedidosPendentesRepasse++; valorPendenteRepasse += totalPedido;
            anomalias.push({ pedido_id: p.id, motivo: `Vendeu e foi cobrado ha ${Math.round(diasDesde)} dias mas o dinheiro AINDA NAO foi liberado pro vendedor (status: ${statusRepasse})`, total: totalPedido });
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
      frete_real: round2(freteViaShipments),
      pedidos_pendentes_repasse: pedidosPendentesRepasse,
      valor_pendente_repasse: round2(valorPendenteRepasse),
      anomalias,
      avisos: log.avisos
    };
    job.status = 'concluido';
  } catch (e) {
    job.status = 'erro';
    job.erro = e.message;
  }
}
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
        a_receber, a_receber_atualizado_em, areceber_report_id, areceber_pedido_em)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
     on conflict (loja) do update set
       saldo_disponivel = excluded.saldo_disponivel,
       saldo_atualizado_em = excluded.saldo_atualizado_em,
       saldo_report_id = excluded.saldo_report_id,
       saldo_pedido_em = excluded.saldo_pedido_em,
       a_receber = excluded.a_receber,
       a_receber_atualizado_em = excluded.a_receber_atualizado_em,
       areceber_report_id = excluded.areceber_report_id,
       areceber_pedido_em = excluded.areceber_pedido_em`,
    [loja, linha.saldo_disponivel ?? null, linha.saldo_atualizado_em ?? null, linha.saldo_report_id ?? null,
     linha.saldo_pedido_em ?? null, linha.a_receber ?? null, linha.a_receber_atualizado_em ?? null,
     linha.areceber_report_id ?? null, linha.areceber_pedido_em ?? null]
  );
}
async function passoSaldoMp(loja, row) {
  const JANELA_FRESCOR_MS = 8 * 60 * 60 * 1000;
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
          await upsertFinanceiroMp(loja, {
            saldo_disponivel: saldo,
            saldo_atualizado_em: new Date(),
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
          await upsertFinanceiroMp(loja, {
            a_receber: aReceber, a_receber_atualizado_em: new Date(),
            areceber_report_id: null, areceber_pedido_em: null
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
      aReceberAtualizadoEm: row ? row.a_receber_atualizado_em : null
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
  res.sendFile(path.join(__dirname, 'doca.html'), (err) => {
    if (err) res.status(404).send('doca.html nao encontrado no servidor - salve o arquivo do Doca na raiz do projeto (ao lado do server.js) com esse nome exato.');
  });
});
async function pegarEstadoNuvem() {
  const r = await pool.query('select dados, atualizado_em from doca_estado where id = 1');
  return r.rows[0] || null;
}
app.get('/estado', exigirLogin, async (req, res) => {
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
     'diario'   -> uma copia por dia, guardada por mais tempo */
const NUM_ROTATIVOS = 30;
const DIAS_GUARDAR_DIARIO = 180;
async function fazerBackupAntesDeGravar(dadosAntigos, atualizadoEmAntigo) {
  if (!dadosAntigos) return;
  await pool.query(
    `insert into doca_estado_hist (tipo, dados, criado_em) values ('rotativo', $1, coalesce($2, now()))`,
    [JSON.stringify(dadosAntigos), atualizadoEmAntigo || null]
  );
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
    `delete from doca_estado_hist where tipo = 'diario' and criado_em < now() - interval '${DIAS_GUARDAR_DIARIO} days'`
  );
}
app.post('/estado', exigirLogin, async (req, res) => {
  try {
    const dados = req.body && req.body.dados;
    if (!dados || typeof dados !== 'object') return res.status(400).json({ ok: false, erro: 'Corpo precisa ter { dados: {...} }.' });
    const anterior = await pegarEstadoNuvem();
    if (anterior && anterior.dados) {
      await fazerBackupAntesDeGravar(anterior.dados, anterior.atualizado_em);
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
    const r = await pool.query(
      `select id, tipo, criado_em, jsonb_array_length(coalesce(dados->'produtos','[]'::jsonb)) as produtos
       from doca_estado_hist order by criado_em desc limit 80`
    );
    res.json({ ok: true, backups: r.rows.map(x => ({ id: x.id, tipo: x.tipo, criadoEm: x.criado_em, produtos: x.produtos })) });
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
  const j = await r.json();
  if (!r.ok) {
    const rateLimited = r.status === 429 || j.error === 'local_rate_limited' || j.message === 'local_rate_limited';
    if (rateLimited && tentativa < 5) {
      const espera = 800 * Math.pow(2, tentativa);
      if (log) log.avisos.push(`rate limit (429) na busca de pedidos - tentativa ${tentativa + 1}/5, esperando ${espera}ms`);
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
async function buscarFaturaMl(loja) {
  const accessToken = await tokenValido(loja);
  const url = 'https://api.mercadolibre.com/billing/integration/monthly/periods?group=ML&document_type=BILL&limit=1';
  const j = await fetchMLDebug(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  const p = (j.results || [])[0];
  if (!p) return null;
  let itens = [];
  let itensAviso = null;
  if (p.key) {
    try {
      const urlResumo = `https://api.mercadolibre.com/billing/integration/periods/key/${p.key}/summary?group=ML&document_type=BILL`;
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
        do {
          const urlDetalhes = `https://api.mercadolibre.com/billing/integration/periods/key/${p.key}/group/ML/details?document_type=BILL&limit=${limite}&offset=${offset}`;
          const jDetalhes = await fetchMLDebug(urlDetalhes, { headers: { Authorization: `Bearer ${accessToken}` } });
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
  let vencimento = p.debt_expiration_date || p.expiration_date || null;
  if (vencimento && !anoRazoavel(vencimento)) vencimento = null;
  if (!vencimento && p.period && p.period.date_to && anoRazoavel(p.period.date_to)) vencimento = p.period.date_to;
  return {
    key: p.key || null,
    valor: typeof p.unpaid_amount === 'number' ? p.unpaid_amount : (typeof p.amount === 'number' ? p.amount : null),
    valorTotal: typeof p.amount === 'number' ? p.amount : null,
    valorPendente: typeof p.unpaid_amount === 'number' ? p.unpaid_amount : null,
    dataInicio: (p.period && p.period.date_from) || null,
    dataFim: (p.period && p.period.date_to && anoRazoavel(p.period.date_to)) ? p.period.date_to : null,
    vencimento,
    status: p.period_status || null,
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
    const { de, ate } = calcularPeriodoResumo('mes_corrente');
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
/* ================= Mensagens pos-venda (mensagem privada apos a compra) =================
   Diferente de Perguntas (publicas, antes da venda), essas sao mensagens privadas trocadas
   DEPOIS da compra (duvida de uso, problema, etc). Felipe (20/08) pediu: responde MANUAL (nao
   automatico), mas com sugestao de resposta pronta pra so' clicar Responder. Mostrada logo
   abaixo de Perguntas no Doca. */
async function buscarMensagensPendentes(loja) {
  const accessToken = await tokenValido(loja);
  const conta = await pegarConta(loja);
  const sellerId = conta.ml_user_id;
  const j = await fetchMLDebug(`https://api.mercadolibre.com/marketplace/messages/unread?role=seller&tag=post_sale&user_id=${sellerId}`, { headers: { Authorization: `Bearer ${accessToken}` } });
  const packs = (j.results || []).slice(0, 25); // limite de seguranca - nao processa uma avalanche de packs de uma vez
  // (25 packs x ~2 chamadas cada + pausa = pode levar uns 20-30s; acima disso arrisca estourar o
  // timeout do proxy do Render/navegador e o card de Mensagens pos-venda no Doca fica "carregando"
  // pra sempre - reduzido de 60 pra 25 por causa disso, 20/08)
  const resultado = [];
  for (const p of packs) {
    const packId = String(p.resource || '').replace('/packs/', '');
    if (!packId) continue;
    try {
      // mark_as_read=false: nao consome o "nao lido" oficial do ML so' por ter mostrado no Doca -
      // so' fica "lido" de verdade quando o Felipe manda uma resposta (ou olha direto no ML).
      const thread = await fetchMLDebug(`https://api.mercadolibre.com/messages/packs/${packId}/sellers/${sellerId}?tag=post_sale&mark_as_read=false&limit=5&offset=0`, { headers: { Authorization: `Bearer ${accessToken}` } });
      const mensagens = (thread.messages || []).slice().sort((a, b) => new Date(a.message_date?.received || 0) - new Date(b.message_date?.received || 0));
      const ultima = mensagens[mensagens.length - 1];
      const buyerId = ultima && ultima.from && String(ultima.from.user_id) !== String(sellerId) ? ultima.from.user_id : null;
      let titulo = null;
      try {
        const rOrd = await fetch(`https://api.mercadolibre.com/orders/search?seller=${sellerId}&pack_id=${packId}`, { headers: { Authorization: `Bearer ${accessToken}` } });
        const jOrd = await rOrd.json();
        const pedido = (jOrd.results || [])[0];
        const oi = pedido && pedido.order_items && pedido.order_items[0];
        titulo = (oi && oi.item && oi.item.title) || null;
      } catch (e) { /* segue sem titulo do produto - nao e' bloqueante */ }
      resultado.push({
        packId, count: p.count, buyerId,
        ultimaMensagem: ultima ? { texto: ultima.text, data: ultima.message_date && ultima.message_date.received } : null,
        titulo
      });
    } catch (e) {
      resultado.push({ packId, count: p.count, erro: e.message });
    }
    await sleep(120);
  }
  return resultado;
}
app.get('/mensagens', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const mensagens = await buscarMensagensPendentes(loja);
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
      const vendas = mapaVendas.get(it.id) || { v7: 0, v15: 0, v30: 0 };
      console.log(`[sync-item] id=${it.id} sku=${extrairSku(it)} titulo="${(it.title||'').slice(0,30)}" vendas=${JSON.stringify(vendas)}`);
      await pool.query(
        `insert into ml_produtos (loja, ml_item_id, sku, titulo, quantidade_disponivel, preco, status, catalog_listing, concorrencia_status, concorrencia_preco, perguntas_sem_resposta, vendas_7d, vendas_15d, vendas_30d, transferencia_full, atualizado_em)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15, now())
         on conflict (loja, ml_item_id) do update set
           sku = excluded.sku, titulo = excluded.titulo,
           quantidade_disponivel = excluded.quantidade_disponivel,
           preco = excluded.preco, status = excluded.status,
           catalog_listing = excluded.catalog_listing,
           concorrencia_status = excluded.concorrencia_status,
           concorrencia_preco = excluded.concorrencia_preco,
           perguntas_sem_resposta = excluded.perguntas_sem_resposta,
           vendas_7d = excluded.vendas_7d, vendas_15d = excluded.vendas_15d, vendas_30d = excluded.vendas_30d,
           transferencia_full = excluded.transferencia_full, atualizado_em = now()`,
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
          transferenciaFull
        ]
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
      'select ml_item_id, sku, titulo, quantidade_disponivel, preco, status, catalog_listing, concorrencia_status, concorrencia_preco, perguntas_sem_resposta, vendas_7d, vendas_15d, vendas_30d, transferencia_full, atualizado_em from ml_produtos where loja = $1 order by titulo',
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
