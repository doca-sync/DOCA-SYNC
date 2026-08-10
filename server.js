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
const { Pool } = require('pg');
const {
  PORT = 3000,
  DATABASE_URL,
  ML_CLIENT_ID,
  ML_CLIENT_SECRET,
  ML_REDIRECT_URI,
  ML_AUTH_DOMAIN = 'https://auth.mercadolivre.com.br',
  ALLOWED_ORIGIN = '*'
} = process.env;
if (!DATABASE_URL) { console.error('Faltou DATABASE_URL no .env'); process.exit(1); }
if (!ML_CLIENT_ID || !ML_CLIENT_SECRET || !ML_REDIRECT_URI) {
  console.error('Faltou ML_CLIENT_ID / ML_CLIENT_SECRET / ML_REDIRECT_URI no .env');
  process.exit(1);
}
const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
const app = express();
app.use(express.json());
const allowedOrigins = ALLOWED_ORIGIN.split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: allowedOrigins.includes('*') ? true : allowedOrigins,
  methods: ['GET', 'POST']
}));
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
app.post('/ml/webhook', (_req, res) => res.sendStatus(200));
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
/* rota de diagnostico - busca UM pedido especifico direto na API (GET /orders/{id}), pra
   auditar pedido que aparece no painel "Vendas" do ML mas nao aparece no /orders/search.
   Devolve o objeto completo (status, status_detail, tags, pack_id, date_last_updated, etc). Ex.:
   /debug/pedido?loja=TorvShop&id=2000012345678901 */
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
/* rota de auditoria - roda o MESMO calculo que o /sync usa de verdade (reusa
   processarVendas(), a mesma funcao) restrito a 1 item, e devolve TODOS os pedidos
   encontrados pra esse item na janela de 30d, cada um marcado com contado:true/false
   e o motivo da exclusao quando nao contado (em vez de simplesmente descartar). Isso
   garante que o numero mostrado aqui e' EXATAMENTE o que entra no vendas_7d/15d/30d
   gravado no banco - zero risco de a auditoria olhar pra uma janela diferente da real. Ex.:
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
    const pedidos = await buscarPedidosNoIntervalo(accessToken, conta.ml_user_id, de, ate, log, 'order.date_closed');
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
      pedidos: detalhe.sort((a, b) => (a.date_closed || '').localeCompare(b.date_closed || ''))
    });
  } catch (e) {
    res.status(500).json({ ok: false, erro: e.message });
  }
});
/* ---- Mercado Pago: saldo / reconciliacao financeira (v16) ----
   Diferente do Mercado Livre, aqui NAO precisa de OAuth com redirect/callback: cada loja usa
   direto o Access Token de PRODUCAO da propria conta Mercado Pago (gerado em "Credenciais de
   producao", dentro do aplicativo criado no painel de desenvolvedores do MP) - e' um segredo
   estatico tipo chave de API, nao um token que expira e precisa refresh feito pelo backend.
   Guardado como variavel de ambiente MP_ACCESS_TOKEN_<LOJA> (mesma normalizacao de nome que
   normalizarChaveLoja ja usa pro Mercado Livre - ver credenciaisDaLoja). */
function tokenMpDaLoja(loja) {
  const chave = normalizarChaveLoja(loja);
  return process.env[`MP_ACCESS_TOKEN_${chave}`] || process.env.MP_ACCESS_TOKEN || null;
}
/* rota de diagnostico - a documentacao oficial do Mercado Pago nao deixa 100% claro qual
   endpoint devolve o saldo (disponivel / a liberar) numa consulta direta e simples; ela so
   documenta com detalhe o relatorio de "Liberacoes", que e assincrono (voce pede, ele gera um
   CSV, avisa por webhook). Em vez de codar em cima de um chute, essa rota testa de uma vez os
   candidatos mais provaveis de endpoint de saldo/conta e devolve a resposta CRUA de cada um -
   decide com dado real qual usar (e quais campos ele tem) antes de ligar isso no /financeiro
   de verdade. Ex.: /debug/mp?loja=TorvShop */
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
/* ---- Mercado Pago: relatorio de Liberacoes (v17) ----
   O /debug/mp (acima) ja provou que nao existe consulta direta de saldo pra apps de terceiros -
   o unico caminho documentado e' esse relatorio assincrono de 3 passos:
     1) POST /v1/account/release_report {begin_date, end_date} -> pede a geracao (responde 202,
        arquivo ainda NAO fica pronto na hora)
     2) GET  /v1/account/release_report/list -> lista os relatorios ja pedidos, cada um com
        "status" (fica "processed" quando pronto pra baixar)
     3) GET  /v1/account/release_report/:file_name -> baixa o CSV do relatorio pronto
   As 3 rotas de debug abaixo testam cada passo manualmente (o nome exato do campo usado como
   "file_name" no passo 3, e as colunas do CSV, so vao ficar 100% confirmados com um relatorio
   real - por isso debug primeiro, automatizar depois). */
async function mpFetch(loja, path, opts) {
  const token = tokenMpDaLoja(loja);
  if (!token) throw new Error(`Faltou a variavel de ambiente MP_ACCESS_TOKEN_${normalizarChaveLoja(loja)} (ou MP_ACCESS_TOKEN) no Render.`);
  return fetch(`https://api.mercadopago.com${path}`, {
    ...opts,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json', ...((opts && opts.headers) || {}) }
  });
}
/* Passo 1: pede a geracao do relatorio pro intervalo dos ultimos N dias (maximo 60, limite do
   proprio Mercado Pago). Ex.: POST /debug/mp/relatorio/pedir?loja=TorvShop&dias=7 */
app.post('/debug/mp/relatorio/pedir', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const dias = Math.min(60, Math.max(1, parseInt(req.query.dias || '7', 10)));
    /* formato EXATO do exemplo oficial: "2019-05-01T00:00:00Z" - sem milissegundos, e em
       fronteira de dia (meia-noite UTC). O 1o teste real mandando toISOString() puro (que
       inclui milissegundos, tipo "...820Z") voltou erro 400 "invalid_begin_date" - por isso
       aqui zera hora/minuto/segundo/ms explicitamente antes de formatar. */
    const diaUTC = (d) => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
    const fmtSemMs = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');
    const fim = diaUTC(new Date());
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
/* Passo 2: lista os relatorios ja pedidos pra essa conta, com o status de cada um. Ex.:
   GET /debug/mp/relatorio/listar?loja=TorvShop */
app.get('/debug/mp/relatorio/listar', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const r = await mpFetch(loja, '/v1/account/release_report/list', { method: 'GET' });
    let corpo; try { corpo = await r.json(); } catch (e) { corpo = { aviso: 'resposta sem JSON' }; }
    res.status(200).json({ ok: r.ok, http_status: r.status, corpo });
  } catch (e) { res.status(500).json({ ok: false, erro: e.message }); }
});
/* Passo 3: baixa o conteudo (CSV) de um relatorio ja processado, usando o identificador que
   aparecer no passo 2 (campo file_name, ou id/report_id se file_name nao vier - testar com
   dado real). Devolve so os primeiros 20000 caracteres, o bastante pra ver o cabecalho e
   algumas linhas sem lotar a resposta. Ex.: GET /debug/mp/relatorio/baixar?loja=TorvShop&arquivo=XXX */
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
/* le um CSV separado por ";" (formato dos relatorios do Mercado Pago) e devolve como lista de
   objetos {coluna: valor}, usando a 1a linha como cabecalho. Ignora linhas vazias no fim. */
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
/* baixa e ja LE o relatorio de Liberacoes, devolvendo so o que interessa pro /financeiro: o
   saldo disponivel = BALANCE_AMOUNT da ULTIMA linha (o extrato roda o saldo linha a linha, a
   ultima e' o saldo mais atual dentro da janela pedida). Ex.:
   /debug/mp/relatorio/saldo?loja=TorvShop&arquivo=reserve-release-....csv */
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
    /* a ultima linha literal do CSV costuma ser uma linha de TOTAIS (DATE vazio, sem saldo
       corrente de verdade) - o saldo real e' o BALANCE_AMOUNT da ultima linha que tem DATE
       preenchido (uma transacao de verdade). */
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
   Mesmo fluxo de 3 passos do /debug/mp/relatorio/*, mas outro relatorio (a API chama de
   "settlement_report"). Esse tem 2 colunas que a Liberacoes NAO tem: IS_RELEASED (TRUE/FALSE -
   se o dinheiro dessa operacao ja foi liberado) e SETTLEMENT_NET_AMOUNT (valor liquido que
   entrou/vai entrar na conta). Somando SETTLEMENT_NET_AMOUNT de toda linha com IS_RELEASED=FALSE
   dentro da janela pedida, da exatamente o "A Receber" (dinheiro ainda pendente de liberacao) -
   o mesmo numero que a tela do Mercado Pago chama de "Disponivel para antecipacao" /
   "Lancamentos futuros". */
app.post('/debug/mp/dinheiro/pedir', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    const dias = Math.min(60, Math.max(1, parseInt(req.query.dias || '30', 10)));
    const diaUTC = (d) => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
    const fmtSemMs = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');
    const fim = diaUTC(new Date());
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
/* configura o relatorio "Dinheiro em conta" pela 1a vez - ao contrario do release_report
   (Liberacoes), que funciona direto, o settlement_report parece exigir essa configuracao
   antes (testado: POST /settlement_report direto sem isso deu 404). So' precisa rodar 1 vez
   por loja. Ex.: POST /debug/mp/dinheiro/config?loja=TorvShop */
/* colunas que a gente realmente usa pra calcular o "A Receber" (SETTLEMENT_NET_AMOUNT +
   IS_RELEASED) mais um minimo de contexto pra conferir visualmente - a config exige "columns"
   e "frequency" mesmo sem agendar nada de verdade (frequency so' importa se o agendamento
   automatico for ligado, o que a gente nao esta fazendo aqui). */
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
/* baixa e ja LE o relatorio "Dinheiro em conta", somando SETTLEMENT_NET_AMOUNT de toda linha
   com IS_RELEASED=FALSE - isso e' o "A Receber". Ex.:
   /debug/mp/dinheiro/areceber?loja=TorvShop&arquivo=settlement-....csv */
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
   As rotas /debug/mp/* acima provaram, com dado real, que da pra calcular:
     - saldo disponivel = BALANCE_AMOUNT da ultima linha COM DATA do relatorio de Liberacoes
     - a receber = soma de SETTLEMENT_NET_AMOUNT de toda linha com IS_RELEASED=FALSE no
       relatorio "Dinheiro em conta" (settlement_report)
   O problema e' que os dois relatorios sao ASSINCRONOS (pede agora, fica pronto so' minutos
   depois) - nao da pra fazer tudo numa unica chamada HTTP sem estourar o timeout do Render.
   Por isso funciona em 2 passadas, guardadas na tabela mp_financeiro:
     - se ja tem um relatorio pendente pra essa loja, tenta TERMINAR ele (ver se ja processou,
       baixar, ler, salvar o valor) em vez de pedir outro
     - se nao tem nenhum pendente, PEDE um novo e guarda o id pra proxima vez
   Isso e' chamado toda vez que o Doca sincroniza (ao abrir e no botao Atualizar) - em geral um
   pedido feito numa sincronizacao e' finalizado na proxima (alguns minutos depois), entao o
   valor mostrado no Doca fica sempre "atualizado ha pouco", nunca "ao vivo" mas tambem nunca
   preso - e sempre com o horario de quando foi lido de verdade, sem fingir que e' instantaneo. */
async function pegarFinanceiroMp(loja) {
  const r = await pool.query('select * from mp_financeiro where loja = $1', [loja]);
  return r.rows[0] || null;
}
/* rota de diagnostico - mostra a linha CRUA da tabela mp_financeiro pra essa loja, sem
   nenhum tratamento. Serve pra ver de verdade o que esta gravado (saldo_report_id pendente,
   quando foi pedido, etc) quando o valor nao aparece no Doca mas o relatorio parece pronto -
   em vez de tentar adivinhar pelo comportamento de fora. Ex.: /debug/mp/financeiro?loja=TorvShop */
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
/* termina o relatorio de Liberacoes pendente (se estiver pronto) ou pede um novo - so' pede
   7 dias porque a gente so' quer o PONTO mais recente do saldo, nao o historico. */
async function passoSaldoMp(loja, row) {
  /* se o relatorio pendente foi pedido ha muito tempo e nunca terminou (pode acontecer do lado
     do Mercado Pago, sem aviso nenhum), fica preso esperando pra sempre - o nosso teste real
     demorou uns 35min pra ficar pronto, entao 45min de folga e' um limite seguro pra desistir
     e comecar de novo em vez de travar o campo indefinidamente. */
  const LIMITE_ESPERA_MS = 45 * 60 * 1000;
  const pedidoExpirou = !!(row && row.saldo_pedido_em && (Date.now() - new Date(row.saldo_pedido_em).getTime() > LIMITE_ESPERA_MS));
  if (pedidoExpirou) console.warn(`[financeiro-mp] saldo: relatorio ${row.saldo_report_id} da loja ${loja} pedido em ${row.saldo_pedido_em} expirou sem terminar - pedindo um novo.`);
  if (row && row.saldo_report_id && !pedidoExpirou) {
    const rList = await mpFetch(loja, '/v1/account/release_report/list', { method: 'GET' });
    const jList = await rList.json().catch(() => null);
    const item = Array.isArray(jList) ? jList.find(x => String(x.id) === String(row.saldo_report_id)) : null;
    if (item && item.file_name) {
      const rDown = await mpFetch(loja, `/v1/account/release_report/${encodeURIComponent(item.file_name)}`, { method: 'GET' });
      const texto = await rDown.text();
      const { linhas } = parseCsvPontoEVirgula(texto);
      const comData = linhas.filter(l => (l.DATE || '').trim().length > 0);
      const ultima = comData.length ? comData[comData.length - 1] : null;
      const saldo = ultima ? parseFloat(ultima.BALANCE_AMOUNT) : NaN;
      /* a MP ja devolve o file_name assim que o relatorio e' criado, mesmo antes do CSV estar
         pronto de verdade pra baixar - entao um download vazio/sem linhas nao significa que o
         relatorio falhou, so' que ainda nao terminou de processar. Nesse caso mantem o
         saldo_report_id pra tentar de novo (baixar o MESMO relatorio) na proxima sincronizacao,
         em vez de abandonar e pedir um relatorio novo toda vez (o que nunca convergia). */
      if (isNaN(saldo)) return;
      await upsertFinanceiroMp(loja, {
        saldo_disponivel: saldo,
        saldo_atualizado_em: new Date(),
        saldo_report_id: null, saldo_pedido_em: null
      });
      return;
    }
    return; // ainda pendente - tenta de novo na proxima sincronizacao
  }
  const dias = 7;
  const diaUTC = (d) => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const fmtSemMs = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');
  const fim = diaUTC(new Date());
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
/* termina o relatorio "Dinheiro em conta" pendente ou pede um novo - usa 60 dias (teto da API)
   pra ter certeza de pegar TODO dinheiro ainda nao liberado, mesmo o que demorar mais pra cair. */
async function passoAReceberMp(loja, row) {
  const LIMITE_ESPERA_MS = 45 * 60 * 1000;
  const pedidoExpirou = !!(row && row.areceber_pedido_em && (Date.now() - new Date(row.areceber_pedido_em).getTime() > LIMITE_ESPERA_MS));
  if (pedidoExpirou) console.warn(`[financeiro-mp] a-receber: relatorio ${row.areceber_report_id} da loja ${loja} pedido em ${row.areceber_pedido_em} expirou sem terminar - pedindo um novo.`);
  if (row && row.areceber_report_id && !pedidoExpirou) {
    const rList = await mpFetch(loja, '/v1/account/settlement_report/list', { method: 'GET' });
    const jList = await rList.json().catch(() => null);
    const item = Array.isArray(jList) ? jList.find(x => String(x.id) === String(row.areceber_report_id)) : null;
    if (item && item.file_name) {
      const rDown = await mpFetch(loja, `/v1/account/settlement_report/${encodeURIComponent(item.file_name)}`, { method: 'GET' });
      const texto = await rDown.text();
      const { linhas } = parseCsvPontoEVirgula(texto);
      /* mesma cautela do saldo: se por algum motivo o download vier vazio (sem nenhuma linha
         com IS_RELEASED), nao abandona o relatorio pedido - tenta de novo no proximo sync. */
      if (!linhas.length) return;
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
    return;
  }
  const dias = 60;
  const diaUTC = (d) => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const fmtSemMs = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');
  const fim = diaUTC(new Date());
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
/* chamada pelo Doca (ao abrir e no botao Atualizar) - sempre tenta terminar o que ja estava
   pendente e/ou comecar um pedido novo, e devolve o estado atual (melhor valor conhecido +
   quando foi lido de verdade). Se a loja nao tem MP_ACCESS_TOKEN configurado, devolve
   configurado:false sem erro - o Doca so' ignora e mantem os campos manuais nessa loja. */
app.post('/financeiro/mp/sincronizar', async (req, res) => {
  try {
    const loja = req.query.loja;
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!tokenMpDaLoja(loja)) return res.json({ ok: true, loja, configurado: false });
    let row = await pegarFinanceiroMp(loja);
    try { await passoSaldoMp(loja, row); } catch (e) { console.error('[financeiro-mp] falha no passo saldo:', loja, e.message); }
    try { await passoAReceberMp(loja, row); } catch (e) { console.error('[financeiro-mp] falha no passo a receber:', loja, e.message); }
    row = await pegarFinanceiroMp(loja);
    /* node-postgres devolve colunas "numeric" como STRING (pra nao perder precisao) - sem
       converter pra Number aqui, o Doca recebe tipo "2716.3" como texto e, ao somar com outros
       valores em dinheiro, o JavaScript faz concatenacao de string em vez de soma. */
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
   e devolve quantas tem por item_id. Se o vendedor nao tiver nenhuma pergunta o ML pode
   responder 404 - tratamos isso como "zero perguntas" em vez de erro. */
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
/* dia calendario (AAAA-MM-DD) na hora de Brasilia, pra bater com o jeito que o painel de
   metricas do ML conta "dias" (dia civil, nao janela corrida de 24h*N a partir de "agora"). */
function diaBR(dataIso) {
  return new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Sao_Paulo' }).format(new Date(dataIso));
}
function diffDiasCivis(diaA, diaB) {
  return Math.round((Date.parse(diaA + 'T00:00:00Z') - Date.parse(diaB + 'T00:00:00Z')) / 864e5);
}
/* busca todos os pedidos de um intervalo, paginando. A API do /orders/search tem um teto de
   offset+limit = 1000 (documentado) - se o intervalo tiver mais pedidos que isso, os mais
   antigos ficam de fora silenciosamente. Pra nao perder pedido em lojas com bastante volume,
   se o total bater perto do teto o intervalo e' dividido em dois e cada metade e' buscada
   separado (recursivo) - e a soma das duas metades nunca esbarra no teto de novo. */
async function buscarPedidosNoIntervalo(accessToken, sellerId, deIso, ateIso, log, campoData) {
  campoData = campoData || 'order.date_created';
  const limit = 50;
  let offset = 0;
  let total = null;
  const pedidos = [];
  while (true) {
    const url = `https://api.mercadolibre.com/orders/search?seller=${sellerId}&${campoData}.from=${encodeURIComponent(deIso)}&${campoData}.to=${encodeURIComponent(ateIso)}&offset=${offset}&limit=${limit}`;
    const r = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
    const j = await r.json();
    if (!r.ok) throw new Error('Falha ao buscar pedidos: ' + JSON.stringify(j));
    total = (j.paging && j.paging.total) || 0;
    const pagina = j.results || [];
    pedidos.push(...pagina);
    offset += limit;
    if (pagina.length < limit || offset >= total) break;
    if (offset >= 950) {
      // perto do teto de 1000 da API - divide o intervalo restante em duas metades e busca cada uma
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
/* soma as vendas dos ultimos 30 dias por item, ja divididas em janelas de 7/15/30 dias
   (cada janela acumula a anterior - mesmo modelo que a Previsao do FULL ja usa). E 1 busca
   paginada so pra loja inteira, nao e 1 chamada por item.
   Historico dessa funcao (pra nao repetir os mesmos erros):
   1) Filtrava por order.status=paid direto na API - contava ~7-8% a menos de unidades do
      que o painel de metricas do ML mostra.
   2) Tirou o filtro de status (so exclui cancelled/invalid) - melhorou mas ainda ficou uns
      9-13% abaixo do painel do ML.
   3) Trocou janela corrida de 24h*N por dia civil (fuso America/Sao_Paulo) e blindou contra o
      teto de 1000 pedidos da API - melhorou o 30d (foi pra ~5% de diferenca) mas o 7d/15d
      pioraram (18%/22%) - padrao classico de bucketar pela data errada: janela curta é muito
      mais sensivel a um pedido cair no dia errado do que uma janela de 30 dias.
   4) Trocou pra bucketar por order.date_closed em vez de order.date_created - testado e
      CONFIRMADO que nao mudou nada (numeros identicos antes/depois), ou seja, nessa loja
      date_created e date_closed sao praticamente o mesmo dia (pagamento instantaneo, sem
      atraso de boleto). Descartada como causa.
   5) Comparação ao vivo com o painel real do vendedor (sc-metrics-publications-fe) confirmou
      que o Doca fica abaixo ate da contagem de PEDIDOS (nao so unidades) do ML pro mesmo
      anuncio - ou seja, nao e' diferenca de unidades vs pedidos, sao pedidos inteiros faltando.
   6) Investigado direto na tela "Vendas" do vendedor (que filtra por order.date_closed - mesmo
      campo que a gente ja usava, confirmado pela URL startPeriod=WITH_DATE_CLOSED_7D_OLD): o
      "Ultimos 7 dias" da ML NAO e' um corte por dia civil (00h-23h59) - e' uma JANELA CORRIDA
      de 7*24h a partir de agora (prova: "Ultimas 24 horas" mostra "7 ago a 8 ago", ou seja
      cruza 2 dias civis, so' faz sentido como janela corrida). O passo 3) tinha trocado pra
      dia civil achando que batia com o rotulo "9 jul a 8 ago" do 30d, mas isso tambem e'
      compativel com janela corrida (30*24h a partir de agora cai por volta do mesmo dia).
      Trocou pra janela corrida (mantendo date_closed, paginacao segura, exclusao de
      cancelled/invalid) - melhorou bastante (~6% de diferenca do que a tela Vendas mostrava
      pro mesmo SKU/periodo), mas ainda sobrava um resto.
   7) O resto que sobrou (passo 6) era o dia de HOJE entrando pela metade na janela corrida:
      "hoje" ainda esta em andamento (nao terminou de acumular vendas), entao a fatia de hoje
      que entra na janela tende a ficar abaixo da media do dia (o dia nao acabou), puxando o
      total pra baixo em relacao ao que o proprio ML mostra quando o dia fecha. Teste direto:
      pedindo pro usuario comparar manualmente "1 ago a 7 ago" (dias fechados, sem incluir
      hoje=8 ago) na tela Vendas do ML deu 114 pedidos/127 unidades - bem mais perto do que a
      janela corrida (108/120 no mesmo instante) e do numero de referencia da Metricas
      (116/128). Confirmado tambem batendo os MESMOS pedidos brutos: filtrando por dia civil
      fechado (meia-noite de hoje pra tras, America/Sao_Paulo) deu 110/123 vs 108/120 da janela
      corrida - melhora real, nao coincidencia.
      Troca final: janela de N dias civis FECHADOS terminando na meia-noite de hoje (exclui o
      dia corrente inteiro, que ainda esta acumulando vendas). America/Sao_Paulo nao tem mais
      horario de verao desde 2019 (fuso fixo -03:00), entao dá pra usar o offset fixo direto.
   8) Revisao externa (outra IA) apontou 2 problemas reais no v12: (a) o /debug/pedidos usava
      "agora - N*24h" quando chamado so' com "dias", DIFERENTE da janela de dias-fechados que
      o /sync de fato usa - ou seja, a auditoria podia estar olhando pra um conjunto de pedidos
      diferente do que realmente vira vendas_7d/15d/30d, sem a gente perceber. (b) o calculo
      usava "msAtras <= N*864e5" (matematicamente equivalente a um intervalo fechado-aberto,
      mas implicito) em vez de comparar contra os limites explicitos de cada janela - mais
      dificil de auditar/confiar de bater o olho no codigo.
      Corrigido: extraida a logica de contagem pra processarVendas(), reusada tanto pelo
      /sync quanto pela nova rota /debug/vendas (mesma funcao = impossivel divergir de novo),
      usando limites explicitos [inicioN, fim) por window. O /debug/pedidos tambem passou a
      usar inicioDoDiaBR() como base quando chamado so' com "dias" (sem de/ate explicito),
      pra sempre bater com a janela real do /sync por padrao. */
function inicioDoDiaBR(instanteMs) {
  const dia = diaBR(new Date(instanteMs).toISOString()); // "AAAA-MM-DD" no fuso de Brasilia
  return Date.parse(dia + 'T00:00:00-03:00'); // meia-noite local, como epoch ms UTC
}
/* logica de contagem de vendas, unica fonte de verdade usada tanto pelo /sync (buscarVendasPorItem,
   agregado pra loja inteira) quanto pela rota de auditoria /debug/vendas (1 item, com detalhe
   pedido a pedido). Recebe a lista crua de pedidos (ja buscada) e devolve:
   - porItem: Map item_id -> {v7,v15,v30} (unidades), so' dos pedidos elegiveis
   - detalhe: lista pedido-a-pedido (so' preenchida quando itemIdFiltro e' passado) com
     contado:true/false e motivo da exclusao quando nao contado - nada e' descartado
     silenciosamente, tudo fica visivel pra auditoria.
   Janelas sao dias civis FECHADOS (fuso America/Sao_Paulo), terminando na meia-noite de hoje -
   ver historico acima (passos 6, 7 e 8) pro raciocinio completo. */
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
    let closedMs = null;
    if (statusExcluidos.has(pedido.status)) {
      contado = false; motivo = `status=${pedido.status}`;
    } else if (!pedido.date_closed) {
      contado = false; motivo = 'sem date_closed (nunca fechou/pagou)';
    } else {
      closedMs = new Date(pedido.date_closed).getTime();
      if (closedMs < inicio30 || closedMs >= fim) {
        contado = false; motivo = 'date_closed fora da janela de 30d';
      }
    }
    for (const oi of (pedido.order_items || [])) {
      const itemId = oi.item && oi.item.id;
      if (!itemId) continue;
      if (itemIdFiltro && itemId !== itemIdFiltro) continue;
      const qtd = oi.quantity || 0;
      if (contado) {
        if (!porItem.has(itemId)) porItem.set(itemId, { v7: 0, v15: 0, v30: 0 });
        const acc = porItem.get(itemId);
        if (closedMs >= inicio30 && closedMs < fim) acc.v30 += qtd;
        if (closedMs >= inicio15 && closedMs < fim) acc.v15 += qtd;
        if (closedMs >= inicio7 && closedMs < fim) acc.v7 += qtd;
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
async function buscarVendasPorItem(accessToken, sellerId) {
  const fim = inicioDoDiaBR(Date.now());
  const de = new Date(fim - 31 * 864e5).toISOString();
  const ate = new Date(fim).toISOString();
  const log = { avisos: [] };
  const pedidos = await buscarPedidosNoIntervalo(accessToken, sellerId, de, ate, log, 'order.date_closed');
  const { porItem, porStatus } = processarVendas(pedidos);
  console.log(`[vendas] pedidos buscados=${pedidos.length} status=${JSON.stringify(porStatus)}${log.avisos.length ? ' avisos=' + JSON.stringify(log.avisos) : ''}`);
  // diagnostico: mostra os 5 itens com mais unidades em 30d e o item_id exato usado - serve pra
  // confirmar se o item_id que a API de pedidos devolve bate com o item_id que a /sync grava no
  // banco (se nao bater, o SKU fica "mudo": o /sync grava vendas=0 pra ele mesmo tendo pedidos).
  const top5 = [...porItem.entries()].sort((a, b) => b[1].v30 - a[1].v30).slice(0, 5)
    .map(([id, v]) => `${id}:v7=${v.v7}/v15=${v.v15}/v30=${v.v30}`).join(' | ');
  console.log(`[vendas][top5] ${top5}`);
  return porItem;
}
/* quantidade em transferencia entre depositos do Full, pro item que ja tem inventory_id
   (so anuncios com logistic_type "fulfillment" tem isso). Nao existe fonte confirmada pra
   "a caminho" (mercadoria enviada mas ainda nao recebida pelo Full) - fica de fora por ora. */
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
    res.json({ ok: true, loja, itensSincronizados: itens.length, atualizadoEm: new Date().toISOString() });
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
process.on('unhandledRejection', (e) => console.error('unhandledRejection:', e));
app.listen(PORT, () => console.log(`Doca ML sync backend rodando na porta ${PORT}`));
