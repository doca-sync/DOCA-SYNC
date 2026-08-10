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
function tokenMpDaLoja(loja) {
  const chave = normalizarChaveLoja(loja);
  return process.env[`MP_ACCESS_TOKEN_${chave}`] || process.env.MP_ACCESS_TOKEN || null;
}
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
    const ultima = linhas[linhas.length - 1];
    const saldo = parseFloat(ultima.BALANCE_AMOUNT);
    res.status(200).json({
      ok: true, loja, totalLinhas: linhas.length,
      saldoDisponivel: isNaN(saldo) ? null : saldo,
      dataUltimaLinha: ultima.DATE || null,
      ultimaLinha: ultima
    });
  } catch (e) { res.status(500).json({ ok: false, erro: e.message }); }
});
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
function diaBR(dataIso) {
  return new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Sao_Paulo' }).format(new Date(dataIso));
}
function diffDiasCivis(diaA, diaB) {
  return Math.round((Date.parse(diaA + 'T00:00:00Z') - Date.parse(diaB + 'T00:00:00Z')) / 864e5);
}
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
  const top5 = [...porItem.entries()].sort((a, b) => b[1].v30 - a[1].v30).slice(0, 5)
    .map(([id, v]) => `${id}:v7=${v.v7}/v15=${v.v15}/v30=${v.v30}`).join(' | ');
  console.log(`[vendas][top5] ${top5}`);
  return porItem;
}
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
