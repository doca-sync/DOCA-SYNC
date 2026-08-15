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

    // % de comissao da categoria - busca 1x por item unico da amostra (usa o preco ATUAL do
    // anuncio, igual o metodo v70 real usado no Resumo Financeiro - e' exatamente isso que
    // queremos comparar contra o preco de venda de cada pedido individual)
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
/* rota de diagnostico - a pessoa apontou (com razao) que buscar o pagamento de CADA pedido pra
   calcular Tarifa/Frete e' pesado demais (uma chamada extra por venda) - o jeito que ferramentas
   tipo Metrify parecem fazer e' mais leve: pra CADA PRODUTO (nao pedido), consultar de uma vez
   (1) a comissao que a categoria dele cobra (API de precificacao do ML) e (2) o custo de frete
   gratis que o vendedor absorve, calculado a partir do peso/dimensao do anuncio (API de opcoes de
   frete gratis do proprio vendedor) - e depois multiplicar isso pela quantidade vendida, sem
   precisar abrir pedido por pedido. Essa rota testa os 2 candidatos de endpoint mais prováveis
   pra um item especifico, devolvendo a resposta CRUA de cada um - decide com dado real quais
   campos usar antes de ligar isso no calculo de verdade. Ex.:
   /debug/custo-estimado?loja=TorvStore&itemId=MLB6574356166 */
app.get('/debug/custo-estimado', async (req, res) => {
  try {
    const loja = req.query.loja;
    const itemId = req.query.itemId;
    if (!LOJAS_VALIDAS.includes(loja)) {
      return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    }
    if (!itemId) return res.status(400).json({ ok: false, erro: 'Parametro "itemId" obrigatorio (ex: MLB6574356166).' });
    const accessToken = await tokenValido(loja);
    const conta = await pegarConta(loja);
    const resultado = { item: null, comissao: null, frete_gratis: null, opcoes_frete: null };
    // 1) dados basicos do anuncio (preco, categoria, tipo de listagem, site, peso/dimensao)
    const rItem = await fetch(`https://api.mercadolibre.com/items/${itemId}`, { headers: { Authorization: `Bearer ${accessToken}` } });
    const jItem = await rItem.json();
    resultado.item = {
      http_status: rItem.status,
      price: jItem.price, category_id: jItem.category_id, listing_type_id: jItem.listing_type_id,
      site_id: jItem.site_id, seller_id: jItem.seller_id,
      shipping: jItem.shipping || null,
      dados_completos: jItem
    };
    // 2) comissao pela categoria (API de precificacao) - devolve sale_fee_amount e o detalhamento
    try {
      const url = `https://api.mercadolibre.com/sites/${jItem.site_id}/listing_prices?price=${jItem.price}&category_id=${jItem.category_id}&listing_type_id=${jItem.listing_type_id}`;
      const rComissao = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
      resultado.comissao = { url, http_status: rComissao.status, corpo: await rComissao.json() };
    } catch (e) { resultado.comissao = { erro: e.message }; }
    // 3) custo de frete gratis que o VENDEDOR absorve (calculado pelo peso/dimensao do anuncio,
    //    nivel de reputacao e regiao do vendedor) - candidato mais provavel do que ferramentas
    //    tipo Metrify usam pra estimar frete sem abrir pedido por pedido
    try {
      const url = `https://api.mercadolibre.com/users/${jItem.seller_id}/shipping_options/free?item_id=${itemId}`;
      const rFrete = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
      resultado.frete_gratis = { url, http_status: rFrete.status, corpo: await rFrete.json() };
    } catch (e) { resultado.frete_gratis = { erro: e.message }; }
    // 4) opcoes de frete do proprio anuncio (o que aparece pro comprador) - so' pra comparar
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
/* rota de diagnostico - v67 testou a hipotese de que o rateio por VALOR (em vez de peso) explicava
   o Frete ML do Substrato ficar abaixo do painel do Mercado Livre - testado com dado real e a
   hipotese caiu (o numero quase nao mudou), porque a maioria dos pedidos do Substrato tem SO' ELE
   no envio (rateio nao faz diferenca quando so' tem 1 item). Entao o que falta nao e' erro de
   rateio - e' um tipo de cobranca INTEIRO que nunca aparece em /shipments/{id}/costs (que so' devolve
   o custo de TRANSPORTE de um envio especifico). Suspeita nova: tarifa de ARMAZENAGEM do Mercado
   Envios Full (cobrada periodicamente pelo estoque parado no CD deles, NAO ligada a nenhum envio
   especifico) ou alguma outra cobranca agregada. Em vez de abrir pedido por pedido (caro, ja
   descartado), essa rota reusa o relatorio de Liberacoes (JA' baixado via /debug/mp/relatorio/*)
   que tem TODA movimentacao da conta, e agrupa por DESCRICAO - revela de uma vez SO' quais tipos de
   cobranca existem na conta no periodo, sem chutar. Ex.:
   /debug/mp/relatorio/categorias?loja=TorvStore&arquivo=reserve-release-....csv */
app.get('/debug/mp/relatorio/categorias', async (req, res) => {
  try {
    const loja = req.query.loja;
    const arquivo = req.query.arquivo;
    const de = req.query.de, ate = req.query.ate; // opcional - filtra por DATE (AAAA-MM-DD) se vier
    if (!LOJAS_VALIDAS.includes(loja)) return res.status(400).json({ ok: false, erro: `Parametro "loja" invalido. Use um de: ${LOJAS_VALIDAS.join(', ')}` });
    if (!arquivo) return res.status(400).json({ ok: false, erro: 'Parametro "arquivo" obrigatorio (ver o campo do relatorio em /debug/mp/relatorio/listar).' });
    const r = await mpFetch(loja, `/v1/account/release_report/${encodeURIComponent(arquivo)}`, { method: 'GET' });
    const texto = await r.text();
    const { cabecalho, linhas } = parseCsvPontoEVirgula(texto);
    if (!linhas.length) return res.status(200).json({ ok: false, erro: 'Relatorio vazio ou nao processado ainda.', http_status: r.status, cabecalho });
    const filtradas = (de && ate)
      ? linhas.filter(l => { const d = (l.DATE || '').slice(0, 10); return d >= de && d <= ate; })
      : linhas;
    // acha uma coluna de valor plausivel (nomes variam entre relatorios do MP)
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
    // percentual de cada categoria sobre o total DEBITADO (soma so' dos valores negativos - o
    // que efetivamente saiu da conta) - e' a mesma logica que o painel do Mercado Livre usa pra
    // mostrar "R$ 4.410 (63,2%)" dentro de "Tarifas e investimentos", entao usar a mesma base
    // ajuda a comparar categoria por categoria com o que aparece la'.
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
/* rota de diagnostico - o /debug/mp/relatorio/categorias (acima) agrupou por DESCRIPTION usando
   NET_CREDIT_AMOUNT (dinheiro ENTRANDO), que nao serve pra achar o que foi DEDUZIDO. Dado real
   (3 linhas de amostra da categoria "payment") mostrou que cada linha de pagamento tem
   GROSS_AMOUNT (valor bruto da venda), MP_FEE_AMOUNT (taxa do Mercado Pago) e NET_CREDIT_AMOUNT
   (o que realmente caiu na conta) - a diferenca entre eles e' TUDO que foi deduzido daquela
   venda (comissao do ML + frete + financiamento + imposto retido, o que for), sem precisar abrir
   pedido por pedido - e' o extrato real, ja' agregado. Essa rota soma isso pra TODAS as linhas
   "payment" do periodo, pra comparar com o que o Doca calcula. Ex.:
   /debug/mp/relatorio/pagamentos-resumo?loja=TorvStore&arquivo=reserve-release-....csv&de=2026-07-01&ate=2026-07-31 */
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
    // tudo que foi deduzido do bruto ALEM da taxa do Mercado Pago e do imposto retido -
    // comissao do Mercado Livre + frete (Full/free shipping) + financiamento, o que for, tudo
    // junto (esse extrato nao separa por tipo dentro de cada linha de pagamento).
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
/* rota de diagnostico - achado importante no /pagamentos-resumo: MP_FEE_AMOUNT sozinho ja' da'
   ~12% do bruto (perto da comissao de categoria + taxa do Mercado Pago somadas), e sobra mais
   ~8,75% em "outras_deducoes" sem rotulo nenhum nesse relatorio. ISSO LEVANTA UMA DUVIDA sobre o
   fix da taxa de financiamento (v64): no pagamento de teste examinado antes (170621591243), o
   charges_details mostrava financing_transfer (+2,05, do comprador pro vendedor) E financing_fee
   (-2,05, do vendedor pro Mercado Pago) - SE esses dois se cancelam na conta do vendedor, a taxa
   de financiamento NAO seria um custo real (seria so' dinheiro passando), e o que foi somado na
   Tarifa em v64 estaria ERRADO (inflando artificialmente). Essa rota acha, no MESMO relatorio real
   ja' baixado, TODAS as linhas ligadas a um SOURCE_ID especifico (pode aparecer em mais de uma
   linha/categoria) - usando o pagamento 170621591243 (ja' investigado antes) da' pra confirmar
   com dado real se o GROSS/NET dele reflete ou nao esse cancelamento. Ex.:
   /debug/mp/relatorio/busca?loja=TorvStore&arquivo=reserve-release-....csv&source_id=170621591243 */
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
  /* v23: descoberto (com dado real) que o "id" devolvido pelo POST /release_report NAO e' o
     mesmo "id" que aparece depois em GET /release_report/list (ex.: POST devolveu 888109832,
     mas na listagem so' apareciam ids tipo 64025074) - sao espacos de numeracao diferentes
     dentro do Mercado Pago. Por causa disso o codigo anterior (que tentava casar os dois ids)
     nunca encontrava o relatorio pronto, mesmo com ele 100% processado e baixavel havia horas.
     Troca de estrategia: em vez de perseguir 1 id especifico, usa sempre o relatorio PRONTO
     mais recente que a conta tiver (a listagem e' sempre so' dos relatorios dessa loja/token).
     Isso funciona porque o saldo e' um razao sequencial UNICO da conta inteira - qualquer
     relatorio processado e recente da o saldo atual correto, nao importa qual pedido exato
     o gerou.
     v37: dado real (GET /release_report/list de 13/08) mostrou que o relatorio em si fica
     pronto ("enabled") quase na hora - o que varia MUITO (de 14min a mais de 6h, no mesmo dia)
     e' QUANDO o Doca teve a chance de ir la' buscar ele, porque o Doca so' sincroniza quando a
     aba esta aberta (sem sincronizacao periodica em segundo plano). Com janela de frescor de
     so' 2h, um relatorio que ficou pronto mas so' foi "visto" pelo Doca 3h depois (pq ninguem
     abriu o app nesse meio tempo) era descartado como "velho demais" e o saldo ficava preso no
     valor anterior ate' o PROXIMO relatorio por sorte cair dentro da janela de 2h de alguma
     abertura do app - explicando os saltos longos e aparentemente aleatorios que a pessoa via.
     Aumentado pra 8h (o saldo de ate' 8h atras ainda e' bem mais util que nenhuma atualizacao) -
     ver tambem o re-sync periodico em segundo plano no front-end, que ataca a causa raiz
     (poucas chances de sincronizar) em vez de so' alargar a janela. */
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
  /* nao achou relatorio pronto e fresco pra usar - so' pede um novo se o ultimo pedido ja
     tiver passado de 10min (evita spammar pedido novo a cada sincronizacao). */
  const PAUSA_ENTRE_PEDIDOS_MS = 10 * 60 * 1000;
  if (row && row.saldo_pedido_em && (Date.now() - new Date(row.saldo_pedido_em).getTime() < PAUSA_ENTRE_PEDIDOS_MS)) return;
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
  /* v23: mesma estrategia do saldo (ver comentario em passoSaldoMp) - usa o relatorio "Dinheiro
     em conta" PRONTO mais recente da conta, em vez de tentar casar o id devolvido no POST com
     o id da listagem (o a-receber ate' vinha funcionando com o casamento por id, mas nao ha'
     garantia disso - mais seguro usar a mesma logica robusta dos dois lados). Janela de frescor
     maior (6h) porque "a receber" muda bem mais devagar que o saldo disponivel. */
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
/* ---- app hospedado + dados na nuvem (v25) ----
   Serve o proprio Doca (arquivo estatico doca.html, salvo na raiz do projeto ao lado do
   server.js) numa URL fixa, protegida por login, pra poder abrir em qualquer navegador
   (celular incluso) - sem isso, o app so' existia como arquivo local no computador. E guarda
   o "estado" inteiro do Doca (produtos, envios, financeiro, etc - o mesmo JSON que hoje vai
   pro arquivo estoque-dados.json de quem usa a opcao de pasta) numa tabela de UMA linha so'
   (doca_estado, id sempre 1) - nao precisa de usuario/multi-tenant, e' um negocio so' usando
   isso. O Doca manda esse JSON pra ca via /estado em vez de escrever num arquivo, o que
   funciona em qualquer navegador (o "conectar pasta" so funciona em Chrome/Edge desktop). */
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
/* backup automatico (equivalente aos "backups" da pasta local): antes de CADA gravacao,
   guarda o estado ANTERIOR (o que estava valendo ate agora) numa tabela de historico -
   nunca sobrescreve sem antes salvar uma copia do que tinha. Guarda dois tipos:
     'rotativo' -> uma copia a cada gravacao, mantendo so as ultimas NUM_ROTATIVOS
     'diario'   -> uma copia por dia (a primeira gravacao de cada dia), guardada por mais tempo
   Isso reproduz o que a pasta local fazia com PASTA_BACKUP (versoes rotativas + 1/dia). */
const NUM_ROTATIVOS = 30;
const DIAS_GUARDAR_DIARIO = 180;
async function fazerBackupAntesDeGravar(dadosAntigos, atualizadoEmAntigo) {
  if (!dadosAntigos) return; // nao tem nada ainda pra guardar copia
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
function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
/* chama o /orders/search com retry+backoff em 429 ("local_rate_limited") - o ML aplica um
   teto de chamadas por segundo por app/token, e lojas de volume alto (muitas paginas, ainda
   mais com 2 buscas rodando - ver buscarPedidosComPendentes) estouram esse teto com facilidade.
   Sem isso, a PRIMEIRA pagina que tomar 429 derrubava a sincronizacao inteira. */
async function buscarPaginaComRetry(url, accessToken, log, tentativa) {
  tentativa = tentativa || 0;
  const r = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  const j = await r.json();
  if (!r.ok) {
    const rateLimited = r.status === 429 || j.error === 'local_rate_limited' || j.message === 'local_rate_limited';
    if (rateLimited && tentativa < 5) {
      const espera = 800 * Math.pow(2, tentativa); // 0.8s, 1.6s, 3.2s, 6.4s, 12.8s
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
    await sleep(120); // pausa curta entre paginas pra nao rajar chamadas
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
    let dataUsada = null;   // data usada pra bucketar esse pedido na janela 7/15/30d
    let fonteData = null;   // so' informativo, pra auditoria
    if (statusExcluidos.has(pedido.status)) {
      contado = false; motivo = `status=${pedido.status}`;
    } else if (pedido.date_closed) {
      dataUsada = new Date(pedido.date_closed).getTime();
      fonteData = 'date_closed';
    } else if (pedido.date_created) {
      /* pedido ainda nao fechou o pagamento (sem date_closed), mas conta pra previsao de
         reposicao do FULL mesmo assim - a pessoa quer enxergar a demanda mesmo antes do
         pagamento confirmar, entao usa a data de CRIACAO do pedido como base no lugar (e' a
         unica data que todo pedido sempre tem). */
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
/* busca pedidos por date_closed E por date_created, juntando sem duplicar - so' por
   date_closed deixa de fora todo pedido que ainda nao fechou o pagamento (a API de busca do ML
   nao devolve pedido nenhum quando o campo do filtro esta vazio nele), e a pessoa quer contar
   esses tambem na previsao de reposicao (mesmo sem pagamento confirmado ainda). */
async function buscarPedidosComPendentes(accessToken, sellerId, de, ate, log) {
  /* sequencial (nao Promise.all) de proposito - rodar as 2 buscas em paralelo dobra o pico de
     chamadas por segundo no /orders/search e foi o que estava estourando o rate limit (429
     local_rate_limited) em lojas de volume alto. Com retry+backoff (buscarPaginaComRetry) e
     pausa entre paginas, sequencial fica mais lento mas nao quebra mais. */
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
/* rota de diagnostico - mostra o retorno CRU e COMPLETO do endpoint de estoque do Full pro
   item (achado pelo SKU salvo em ml_produtos), sem nenhum filtro - inclusive o detalhe do
   item (pra ver o inventory_id usado) e o array not_available_detail inteiro, nao so' a
   quantidade da status "transfer" que buscarTransferenciaFull usa hoje. Serve pra confirmar
   se tem algum campo/status que reflete "entrada pendente" de verdade que o codigo atual nao
   esta capturando. Ex.: /debug/full/estoque?loja=Orbix%20Brasil&sku=canetadetectora */
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
/* ---------- Mercado Ads (Product Ads) ----------
   API separada da de estoque/pedidos - o token OAuth e' o mesmo de sempre (a URL de login nao
   pede nenhum escopo especial), mas se o aplicativo (client_id) da loja nao tiver o produto
   "Advertising API" habilitado no painel de developers do Mercado Livre, a API devolve 403 -
   nesse caso precisa habilitar isso no app antes de funcionar. Fluxo: 1) descobre o
   advertiser_id do vendedor (1x por loja), 2) usa esse id pra puxar campanhas + metricas por
   periodo (ate 90 dias pra tras). Doc: developers.mercadolivre.com.br/pt_br/product-ads-leitura */
/* lista "otimista" com tudo que a documentacao menciona - buscarCampanhasAds() tira sozinho
   qualquer campo que a API recusar (400 "Field X not allowed"), entao nao tem problema pedir
   mais do que esse endpoint aceita */
const ADS_METRICAS = [
  'clicks', 'prints', 'ctr', 'cost', 'cpc', 'acos', 'organic_units_quantity', 'organic_units_amount',
  'organic_items_quantity', 'direct_items_quantity', 'indirect_items_quantity', 'advertising_items_quantity',
  'cvr', 'roas', 'sov', 'direct_units_quantity', 'indirect_units_quantity', 'units_quantity', 'direct_amount',
  'indirect_amount', 'total_amount', 'impression_share', 'top_impression_share',
  'lost_impression_share_by_budget', 'lost_impression_share_by_ad_rank', 'acos_benchmark'
].join(',');
/* fetch defensivo: le a resposta como TEXTO primeiro (nunca chama r.json() direto), porque
   uma API pode devolver corpo vazio ou HTML de erro em vez de JSON (ex.: bloqueio de gateway
   por falta de permissao) - isso travava com "Unexpected end of JSON input" sem mostrar o
   status/corpo real que ajudaria a diagnosticar. */
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
/* endpoint legado (/advertising/advertisers/{id}/product_ads/campaigns) foi desativado em
   27/05/2026 (dava 404) - o novo caminho tem o site_id no meio e termina em /search */
/* se a API recusar algum campo de metrics (400 "Field X not allowed"), tira esse campo e
   tenta de novo sozinho - assim nao precisamos descobrir na mao, um por um, quais campos esse
   endpoint aceita (o corpo do erro ja diz o nome exato do campo problematico) */
async function buscarCampanhasAds(loja, siteId, advertiserId, dias, deAteCustom) {
  const accessToken = await tokenValido(loja);
  const de = (deAteCustom && deAteCustom.de) || dataYMD(Date.now() - (dias - 1) * 864e5);
  const ate = (deAteCustom && deAteCustom.ate) || dataYMD(Date.now());
  let metricas = ADS_METRICAS.split(',');
  const removidas = [];
  const LIMIT = 50;
  // v77: antes buscava so' a 1a pagina (limit=50&offset=0 fixo) - lojas com mais de 50 campanhas
  // no periodo perdiam o resto em silencio. Agora pagina ate' cobrir "paging.total" da API, igual
  // o padrao ja usado em buscarItensDoVendedor. v77b: se uma pagina seguinte (2a em diante) falhar
  // (ex.: rate limit), NAO derruba a busca inteira - fica com o que ja tinha conseguido ate' ali,
  // porque a 1a versao desse fix estava jogando fora TUDO (inclusive a pagina 1, que antes
  // funcionava sozinha) quando uma pagina extra dava erro.
  // v77c: cada pagina extra (2a em diante) e' uma chamada a mais na MESMA rajada de chamadas que
  // o resto do /financas/resumo ja faz (pedidos, comissao por item, etc.) - period que sobra pouca
  // "cota" e a API devolve 429 (rate limit) bem mais nas paginas 2+. Antes so' retentava em 400
  // "Field X not allowed"; agora tambem retenta em 429/5xx com espera crescente (backoff), pra nao
  // desistir de paginas que passariam numa 2a tentativa alguns segundos depois.
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
      // pequena pausa entre paginas pra dar folga na cota de rate limit da API
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
/* v78: achado no /debug/ads/itens-campanha - o endpoint /product_ads/ads/search (mesmo exigindo um
   campaign_id no parametro) devolve os ANUNCIOS de TODAS as campanhas do advertiser, com metrics
   (cost/clicks/prints) JA' calculado por item individual, nao por campanha. Isso resolve de vez o
   problema de casar Ads com produto pelo NOME da campanha (que falha toda vez que o nome nao tem o
   SKU dentro, tipo a campanha "ALHO VALECOM" pro produto Amassadoralho): agora da' pra casar direto
   pelo item_id do Mercado Livre, que o Doca ja tem salvo em cada produto (mlItemId) - sem depender
   de nome de campanha nenhum. */
async function buscarItensAdsPeriodo(loja, siteId, advertiserId, de, ate, campaignIdSugerido) {
  const accessToken = await tokenValido(loja);
  const LIMIT = 50;
  // a API parece exigir um campaign_id no parametro mesmo devolvendo itens de todas as campanhas -
  // pega qualquer campanha valida do periodo pra preencher esse parametro. v78b: se quem chamou ja
  // tem uma campanha em maos (ex.: calcularResumoFinanceiroCompleto ja buscou as campanhas do
  // periodo um pouco acima), usa ela direto em vez de buscar de novo - evitava uma 2a chamada
  // paginada inteira (com backoff e sleep entre paginas) só pra pegar 1 id, que deixava o
  // /financas/resumo bem mais lento (a aba Amauri ficava "Buscando..." por muito mais tempo).
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
  // agrega por item_id (soma, caso o mesmo item apareca mais de uma vez - ex.: mais de 1 anuncio ativo pro mesmo item)
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
/* rotas de diagnostico - mostram o retorno CRU da API antes de decidir como guardar/mostrar no
   Doca. Testar assim: /debug/ads/advertiser?loja=TorvStore
                        /debug/ads/campanhas?loja=TorvStore&dias=30 */
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
/* rota de diagnostico - tenta buscar impression_share/top_impression_share/
   lost_impression_share_by_budget/lost_impression_share_by_ad_rank ("ganho de leiloes") por
   uma campanha especifica, num endpoint diferente (por campanha, sem passar por advertiser/
   site_id) - o endpoint de lista/search recusou esses campos com 400, entao testando se esse
   outro formato aceita. Ex.: /debug/ads/leiloes?loja=TorvStore&campanhaId=353016528&dias=30 */
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
    /* nenhum desses formatos foi confirmado ainda - vai tentando um por um ate um funcionar
       (ou devolve todos os erros, se nenhum funcionar) */
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
/* rota de diagnostico - a pessoa apontou (com razao) que o jeito certo de achar o gasto de Ads
   de um produto NAO e' adivinhar pelo nome da campanha (frágil, so' funciona se o SKU aparecer
   no nome) - a API de Ads deve deixar ver quais anuncios (item_id) estao DENTRO de cada campanha,
   o que permite casar direto pelo mesmo item_id que o Doca ja usa em todo o resto do app (produto
   -> mlItemId). Essa rota testa os candidatos mais prováveis de endpoint pra listar os itens de
   uma campanha (mesmo estilo dos outros /debug/ads/* que ja' funcionaram testando variacoes),
   devolvendo a resposta CRUA de quem funcionar primeiro. Ex.:
   /debug/ads/itens-campanha?loja=TorvStore&campanhaId=357022681 */
app.get('/debug/ads/itens-campanha', async (req, res) => {
  try {
    const loja = req.query.loja;
    let campanhaId = req.query.campanhaId;
    const nome = req.query.nome; // alternativa a campanhaId: acha a campanha pelo nome (ex.: "ALHO VALECOM")
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
/* rota de diagnostico - testa campo por campo (um de cada vez) no endpoint que JA FUNCIONA
   (o /search com campaign_ids filtrando 1 campanha), pra descobrir exatamente qual desses
   campos de "perda por leilao/orcamento" a API aceita e qual ela recusa - em vez de mandar
   todos juntos e so' saber que "algum" foi recusado.
   Ex.: /debug/ads/metrica?loja=TorvStore&campanhaId=357022681&dias=7
   Ex. escolhendo os campos: /debug/ads/metrica?loja=TorvStore&campanhaId=357022681&campos=lost_impression_share_by_budget,top_impression_share */
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
/* rota de diagnostico - tenta pegar custo/impressoes DIA A DIA (aggregation_type=DAILY, achado
   via doc) em vez de agregado no periodo inteiro. Nao devolve "perda por orcamento" pronta (isso
   ja confirmamos que a API nao libera de jeito nenhum), mas se vier o custo de cada dia dá pra
   comparar com o orcamento da campanha e ver em quantos dias ela bateu no teto (indicio forte de
   que perdeu leilao por falta de orcamento naquele dia) - um jeito de estimar automaticamente,
   sem precisar copiar nada na mao do painel.
   Ex.: /debug/ads/diario?loja=TorvStore&campanhaId=357022681&dias=7 */
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
    let metricas = ['cost', 'clicks', 'prints', 'sov'];
    const removidas = [];
    for (let tentativa = 0; tentativa < 6; tentativa++) {
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
/* ---------- sincronizacao "de verdade" de Ads (grava no banco, pro Doca so' ler) ----------
   Guarda o retorno CRU de cada periodo (7/15/30 dias) por loja, sem normalizar ou calcular nada
   aqui - isso fica pro Doca decidir depois, conforme formos definindo filtros/calculos. Uma
   linha por loja+periodo, sempre sobrescrita na sincronizacao seguinte (nao guarda historico
   por enquanto). Precisa da tabela ml_ads_campanhas (ver SQL de migracao). */
async function sincronizarAdsLoja(loja) {
  const { primeiro } = await buscarAdvertiserId(loja);
  if (!primeiro) throw new Error('Nenhum advertiser_id encontrado pra essa loja.');
  const { advertiser_id, site_id } = primeiro;
  // dias:1 -> "hoje" (de==ate==hoje) - guardado com a mesma chave "dN" das outras janelas
  // (vira "d1"), o front-end so' precisa saber traduzir esse valor pro rotulo "Hoje".
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
/* periodo PERSONALIZADO de Ads (De/Ate escolhido a dedo) - ao contrario de d7/d15/d30 (que ficam
   guardados no banco pelo /ads/sync), esse busca direto na hora, sem gravar nada - o intervalo
   muda toda hora conforme a pessoa digita, nao faz sentido cachear. Reusa a mesma buscarCampanhasAds
   (com deAteCustom) que ja usada em /financas/resumo. Ex.:
   /ads/campanhas-periodo?loja=TorvStore&de=2026-07-01&ate=2026-07-31 */
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

/* ================= Finanças: fatura (cobrança mensal) do Mercado Livre =================
   Usa a API oficial de Billing Reports do ML (nao tem bloqueio, diferente do /sites/search que
   foi testado e recusado em 2026 - essa e' documentada e liberada normalmente). group=ML traz o
   que o Mercado Livre cobra do vendedor (comissao de venda, anuncio, Full etc) - e' DIFERENTE do
   saldo do Mercado Pago que ja e' sincronizado em outro lugar (aquele e' quanto dinheiro voce TEM
   la', isso aqui e' quanto voce DEVE de taxa no periodo). Só pega o periodo mais recente. */
function anoRazoavel(dataIso) {
  // descarta datas-sentinela tipo "9999-12-31" que o ML usa pra período ainda em aberto
  const ano = Number(String(dataIso || '').slice(0, 4));
  return ano && ano <= 2100 ? true : false;
}
async function buscarFaturaMl(loja) {
  const accessToken = await tokenValido(loja);
  const url = 'https://api.mercadolibre.com/billing/integration/monthly/periods?group=ML&document_type=BILL&limit=1';
  const j = await fetchMLDebug(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  const p = (j.results || [])[0];
  if (!p) return null;

  // detalhamento por categoria (tarifas de envio, publicidade, venda, parcelamento, Full etc) -
  // o mesmo resumo que aparece na tela "Resumo da fatura" do Mercado Livre, pra poder discriminar
  // no corpo da DRE de onde vem o valor, e nao so' mostrar um numero unico
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
      // /summary deu 404 ao vivo (testado em 15/08) - a documentacao e' de 2023 e esse projeto ja'
      // achou OUTRO endpoint de Ads desativado em 2026, entao e' bem provavel que /summary tambem
      // tenha saido do ar. Cai pro /group/ML/details, que e' linha-a-linha (cada cobranca
      // individual) em vez de ja' vir agrupado - agrega por transaction_detail aqui mesmo pra
      // chegar no mesmo formato {label, valor}. So' registra o aviso se essa 2a tentativa TAMBEM
      // falhar (nao quer dizer "sem detalhamento" so' porque o 1o formato caiu).
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
        } while (offset < total && offset < 2000); // teto de seguranca pra nao paginar pra sempre numa loja gigante
        itens = [...porLabel.entries()].map(([label, valor]) => ({ label, valor }));
      } catch (eDetalhes) {
        // as duas tentativas falharam - guarda o motivo (em vez de engolir silencioso) pra dar pra
        // ver na propria tela de Financas PORQUE o botao "detalhar" nao apareceu
        itensAviso = `Detalhamento indisponível: /summary respondeu ${eResumo.http_status || '?'}, /details respondeu ${eDetalhes.http_status || '?'} (${eDetalhes.message})`;
      }
    }
  }

  // vencimento: o ML so' preenche expiration_date quando o periodo ja' fechou. Enquanto esta'
  // em andamento, usa a data de vencimento da divida projetada; se nada disso vier com uma data
  // real (a API manda sentinela tipo 9999 pra periodo ainda aberto), fica sem data em vez de
  // mostrar uma data absurda
  let vencimento = p.debt_expiration_date || p.expiration_date || null;
  if (vencimento && !anoRazoavel(vencimento)) vencimento = null;
  if (!vencimento && p.period && p.period.date_to && anoRazoavel(p.period.date_to)) vencimento = p.period.date_to;

  return {
    key: p.key || null,
    // valor = o que realmente falta pagar (unpaid_amount), nao o total bruto do periodo -
    // parte do total ja' pode ter sido descontada automaticamente (do saldo do Mercado Pago, por
    // exemplo), entao o "total da fatura" e o "quanto eu ainda devo" sao numeros diferentes
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

/* ================= Financas: Resumo Financeiro (faturamento, margem, deducoes por periodo) =================
   Responde as mesmas perguntas que ferramentas tipo Metrify respondem: faturamento, tarifas
   (comissao), frete (comprador vs vendedor), Ads, cancelamentos/reembolsos, com filtro de periodo
   (7/15/30 dias, mes fechado ou intervalo personalizado). O CMV NAO e' calculado aqui - o custo
   unitario (produto.custo) so' existe no estado salvo no navegador (a pessoa digita na aba
   Produtos, o backend/banco nao guarda isso de forma estruturada) - entao essa rota devolve os
   itens vendidos agregados por item_id+qtd, e quem calcula o CMV (juntando com o custo local) e'
   o proprio Doca no navegador. */
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
/* versao "leve" do resumo - so' soma o faturamento (pedidos validos no periodo), sem chamar
   /shipments/.../costs nem a API de Ads (que sao os dois passos lentos do resumo completo). Usada
   pra atualizar o campo "Imposto" da Visao Geral automaticamente toda vez que o Doca abre, sem
   pesar a sincronizacao com dezenas de chamadas extras so' pra isso. */
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
async function buscarResumoFinanceiro(loja, de, ate) {
  const accessToken = await tokenValido(loja);
  const conta = await pegarConta(loja);
  const log = { avisos: [] };
  const deIso = `${de}T00:00:00-03:00`;
  const ateIso = `${ate}T23:59:59-03:00`;
  const pedidos = await buscarPedidosNoIntervalo(accessToken, conta.ml_user_id, deIso, ateIso, log, 'order.date_closed');

  let faturamento = 0, tarifas = 0, cancelamentosValor = 0, reembolsosValor = 0;
  let pedidosValidos = 0, pedidosCancelados = 0;
  const itensVendidos = new Map(); // itemId -> { qtd, valor, pedidos, tarifa, freteMl, faturamentoTotal, tarifaDeclarada }
  const shippingIds = new Set();
  // pra cada shipment, guarda os itens (e a QUANTIDADE de cada um) que vieram naquele envio -
  // depois de buscar o custo de frete DO SHIPMENT (nao existe custo de frete por item na API do
  // ML, so' por envio), rateia esse custo entre os itens.
  // v67: o rateio ERA proporcional ao VALOR (receita) de cada item dentro do envio - descoberto
  // (comparando Substrato com o painel do proprio Mercado Livre: 527 unid. deviam custar
  // 527 x R$6,95 = R$3.662,65 pelo peso, mas o painel mostra R$4.410) que isso rateia ERRADO
  // quando um produto PESADO e BARATO (caso do Substrato, ~1kg, R$27,75) divide envio com um
  // produto LEVE e mais CARO - o rateio por receita "rouba" frete do produto pesado pra dar pro
  // mais caro, mesmo o frete do Mercado Livre sendo cobrado por PESO, nao por preco. Trocado pra
  // ratear por PESO (peso do pacote x quantidade) - muito mais fiel a como o Mercado Envios cobra
  // de verdade. O peso de cada item e' buscado em lote ANTES do rateio (ver pesosPorItem abaixo).
  const itensPorShipping = new Map(); // shippingId -> [{ itemId, qtd }]

  // tarifa (sale_fee) e frete de pedido CANCELADO: confirmado comparando com o painel do Mercado
  // Livre (aviso de diagnostico de uma versao anterior) que o ML normalmente NAO devolve a tarifa
  // nem o frete de um cancelamento que ja tinha sido cobrado (comum quando cancela depois do
  // produto despachado) - o "Tarifas e investimentos" do painel deles inclui esse valor mesmo a
  // venda tendo sido cancelada. Por isso tarifa/frete SEMPRE contam (cancelado ou nao), so'
  // faturamento/qtd/pedidos (vendas de verdade) que so' contam pedido NAO cancelado.
  let tarifaCancelados = 0;

  // taxa de parcelamento (financing_fee): confirmado com dado real (GET /v1/payments/{id} no
  // Mercado Pago) que quando a venda e' parcelada, o Mercado Pago cobra uma "financing_fee"
  // SEPARADA da comissao de venda (sale_fee) - ela NAO aparece em lugar nenhum na API do
  // Mercado Livre (nem no pedido, nem no order_item), so' no objeto de pagamento completo do
  // Mercado Pago, dentro de fee_details: [{type:'financing_fee', fee_payer:'collector', amount}].
  // So' conta quando fee_payer==='collector' (o VENDEDOR que absorveu - quando fee_payer e'
  // 'payer', foi o COMPRADOR que pagou o juro, isso nao e' custo nenhum pra loja). Essa e' a
  // causa da Tarifa do Doca ficar ~13% abaixo do painel do Mercado Livre numa loja com venda
  // parcelada. Igual sale_fee/frete, conta pra pedido cancelado tambem (mesmo raciocinio: o ML
  // normalmente nao devolve essa taxa so' por causa do cancelamento).
  const itensPorPagamento = new Map(); // paymentId -> [{ itemId, valor }]
  for (const pedido of pedidos) {
    if (pedido.status === 'invalid') continue; // nunca chegou a valer nada
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
      // v70: o sale_fee DECLARADO no pedido nem sempre bate com o que o Mercado Livre de fato
      // debita da conta (confirmado com dado real - GET /v1/payments/{id} - varios pedidos com
      // sale_fee bem diferente da cobranca real "ml_sale_fee"). Fonte mais confiavel: a % de
      // comissao da CATEGORIA do produto (API /sites/{site}/listing_prices), aplicada sobre o
      // faturamento do produto - bate muito mais perto do painel do Mercado Livre (testado no
      // Substrato: 14.624,25 x 11,5% = 1.681,79, quase igual ao R$1.683,75 do painel, contra
      // R$1.511,73 que a soma de sale_fee dava). Por isso agora so' ACUMULA sale_fee aqui pra
      // guardar de FALLBACK (caso a API de comissao falhe pra algum item) - o total real de
      // Tarifa e' recalculado por produto mais abaixo, depois de buscar o percentual de cada um.
      const saleFee = Number(oi.sale_fee) || 0;
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
        // faturamentoTotal conta CANCELADO tambem - a comissao por percentual incide sobre toda
        // venda faturada, cancelada ou nao (mesmo raciocinio que ja' valia pro sale_fee antes).
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
    // reembolso parcial/total detectado via status do pagamento - conta separado de "cancelado".
    // IMPORTANTE: so' verifica isso pra pedido NAO cancelado - um pedido cancelado quase sempre
    // tem o pagamento com status "refunded" tambem (o cancelamento em si dispara o estorno), e
    // esse valor ja' foi contado em cancelamentosValor acima. Sem esse cuidado, todo pedido
    // cancelado era contado 2x (uma vez como cancelamento, outra como reembolso) - bug real
    // encontrado comparando com o Metrify em 15/08 (reembolsos aparecia ~140x maior que o valor
    // real, quase identico ao total de cancelamentos - sinal claro de duplicacao).
    if (!cancelado) {
      for (const pg of (pedido.payments || [])) {
        if (pg.status === 'refunded' || pg.status === 'partially_refunded') {
          reembolsosValor += Number(pg.transaction_amount) || 0;
        }
      }
    }
  }

  // peso de cada item (em gramas) - usado pra ratear o custo de um envio com VARIOS produtos
  // diferentes proporcional ao PESO (o que o Mercado Envios realmente cobra), nao ao valor.
  // Busca em lote (ate 20 por chamada, igual o lote de titulos mais abaixo), lendo o atributo
  // SELLER_PACKAGE_WEIGHT (peso que o proprio vendedor declarou pro pacote) e, se nao tiver, cai
  // pro PACKAGE_WEIGHT (peso "de fabrica" cadastrado no catalogo). Item sem nenhum peso cadastrado
  // fica de fora do mapa - o rateio usa 1g como peso minimo pra ele (evita dividir por zero e nao
  // deixa ele ficar de fora do rateio, so' com peso desprezível).
  const pesosPorItem = new Map(); // itemId -> gramas
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

  // Tarifa (comissao) por PRODUTO - v70: em vez de somar sale_fee (declarado no pedido, que
  // confirmado com dado real as vezes NAO bate com o que o Mercado Livre de fato cobra), busca a
  // % de comissao da CATEGORIA de cada produto (API /sites/{site}/listing_prices) e aplica sobre
  // o faturamento total do produto no periodo (cancelado incluso, mesmo raciocinio de antes).
  // So' 1 chamada extra POR PRODUTO (nao por pedido) - leve mesmo numa loja com milhares de
  // vendas. Se a API falhar pra algum item especifico, cai pro sale_fee somado (tarifaDeclarada)
  // como fallback, em vez de zerar a tarifa dele.
  let itensSemComissao = 0;
  try {
    const idsParaComissao = [...itensVendidos.keys()];
    const dadosItem = new Map(); // itemId -> { price, category_id, listing_type_id }
    for (let i = 0; i < idsParaComissao.length; i += 20) {
      const lote = idsParaComissao.slice(i, i + 20).join(',');
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
            atual.tarifa = atual.tarifaDeclarada; // fallback
            itensSemComissao++;
          }
        } catch (e) {
          atual.tarifa = atual.tarifaDeclarada; // fallback
          itensSemComissao++;
        }
      }
    }
    await Promise.all(Array.from({ length: Math.min(CONCORRENCIA_COMISSAO, idsComDados.length) }, workerComissao));
  } catch (e) {
    log.avisos.push('Nao foi possivel buscar a comissao por categoria dos produtos - a Tarifa caiu pro sale_fee declarado no pedido (menos preciso): ' + e.message);
    itensVendidos.forEach(atual => { atual.tarifa = atual.tarifaDeclarada; });
  }
  if (itensSemComissao) log.avisos.push(`${itensSemComissao} produto(s) sem comissao por categoria disponivel - Tarifa desses ficou no sale_fee declarado no pedido (fallback, menos preciso).`);
  // tarifas (total da loja) agora e' a SOMA da tarifa por produto ja calculada acima (por
  // percentual de categoria, com fallback pro sale_fee declarado quando a API falha)
  tarifas = [...itensVendidos.values()].reduce((s, v) => s + v.tarifa, 0);

  // frete: comprador (o que o cliente pagou) vs vendedor (o que saiu do seu bolso) - via
  // /shipments/{id}/costs, que da' exatamente essa separacao. ANTES rodava sequencial com um
  // limite de seguranca de so' 400 envios - numa loja de volume real (ex: 2786 envios em 15 dias)
  // isso truncava o calculo em ~14% do total, deixando o frete (e a margem) BEM errados (achado
  // comparando com o Metrify em 15/08 - frete vendedor apareceu 7x menor que o real). Trocado por
  // um pool de chamadas em paralelo (concorrencia limitada, nao tudo de uma vez) com retry+backoff
  // em 429 igual buscarPaginaComRetry, e o limite de seguranca subiu bem mais alto - agora e' so'
  // uma protecao contra loja com volume absurdo, nao o caminho normal.
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
  const CONCORRENCIA_FRETE = 10;
  let cursorFrete = 0;
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
          // rateia por PESO (peso do item x quantidade), nao por valor - ver comentario acima de
          // pesosPorItem sobre o achado real que motivou essa troca (v67)
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
    }
  }
  await Promise.all(Array.from({ length: Math.min(CONCORRENCIA_FRETE, idsParaBuscar.length) }, workerFrete));
  if (freteFalhas) log.avisos.push(`${freteFalhas} de ${idsParaBuscar.length} envio(s) nao respondeu(ram) o custo de frete (ignorados no total - pode subestimar levemente o frete).`);
  if (pedidosCancelados > 0) log.avisos.push(`${pedidosCancelados} pedido(s) cancelado(s) no periodo - o faturamento deles continua entrando na base de calculo da Tarifa (confirmado que o Mercado Livre normalmente nao devolve a comissao so' por causa do cancelamento).`);

  // taxa de parcelamento (financing_fee) - v73: REVERTIDO. O fix da v64 somava essa taxa na
  // Tarifa (achando, via fee_details, que o vendedor absorvia ela). Confirmado com dado real do
  // extrato de Liberacoes (release_report) que isso estava ERRADO: pro pagamento de teste
  // 170621591243, a conta bate certinho SEM contar financing_fee (R$19,00 venda - R$2,18 comissao
  // - R$6,85 frete real = R$9,97, quase identico ao net_received_amount real de R$10,27) - ou
  // seja, o financing_transfer (dinheiro que entra do comprador) e o financing_fee (que sai pro
  // Mercado Pago) SE CANCELAM na conta do vendedor, nao sobra como custo de verdade. Fica so' o
  // mapa itensPorPagamento (construido acima, sem custo nenhum de chamada extra) sem uso por
  // enquanto - se precisar reativar essa investigacao um dia, os dados ja estao ali.

  // Ads: reusa o mesmo endpoint de campanhas ja' confirmado funcionando, so' com o intervalo
  // personalizado no lugar do preset de 7/15/30 dias. Guarda tambem o gasto POR CAMPANHA (nao so'
  // o total da loja) - usado pelo fechamento do Amauri pra achar o gasto exato de cada produto
  // nesse MESMO periodo personalizado (antes so' tinha as janelas fixas de 7/15/30 dias, que nao
  // batiam com um periodo escolhido a dedo como "1 a 31 de julho").
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
      // v78: gasto por ITEM (item_id), casado direto com o produto - nao depende do nome da
      // campanha ter o SKU dentro (ver comentario em buscarItensAdsPeriodo)
      try {
        const campanhaIdJaConhecida = (campanhas.results && campanhas.results[0] && campanhas.results[0].id) || null;
        adsItens = await buscarItensAdsPeriodo(loja, primeiro.site_id, primeiro.advertiser_id, de, ate, campanhaIdJaConhecida);
      } catch (e) { log.avisos.push('Nao foi possivel buscar o custo de Ads por item do periodo (ficou so o casamento por nome de campanha): ' + e.message); }
    }
  } catch (e) { log.avisos.push('Nao foi possivel buscar o custo de Ads do periodo: ' + e.message); }

  // vendas de hoje - sempre calculado, independente do periodo escolhido acima
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

  // titulo de cada item vendido (pro ranking de produtos mostrar o nome, nao so' o item_id cru) -
  // em lotes de 20 (teto da API pra /items?ids=), tolerante a item que nao respondeu (ex.: anuncio
  // ja' apagado) - nesse caso o Doca mostra so' o item_id no lugar do titulo
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

/* ================= Perguntas sem resposta (completas, pra ler e responder) =================
   O /sync ja guarda so' a CONTAGEM de perguntas sem resposta por item (perguntas_sem_resposta,
   usado no card da Visao Geral). Essas rotas aqui buscam o TEXTO de cada pergunta (sob demanda,
   so' quando a pessoa abre o card - nao roda em todo sync porque e' mais pesado) e permitem
   responder direto, usando a API oficial de perguntas e respostas do ML. */
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
