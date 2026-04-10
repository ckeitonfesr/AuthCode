const cors = require('../_cors');
const { checkIpRateLimit, extractIp } = require('../_rate-limit');

const SUPABASE_URL  = 'https://sineixguxvlmatnyvtdw.supabase.co';
const ANON_KEY      = process.env.SUPABASE_ANON_KEY;
const PROXY_TOKEN   = 'proxy-anon';
const ALLOWED_ORIGIN = 'https://24hrs-central.site';

// Tabelas/paths que o proxy anônimo pode acessar (leitura pública)
const ANON_WHITELIST = new Set([
  'products', 'categories', 'profiles', 'favorites',
  'cart_items', 'orders', 'order_items', 'addresses',
]);

// Rate limit: max 60 req/min por IP no proxy
const PROXY_RATE = 60;

const STRIP_REQ = new Set([
  'host', 'connection', 'transfer-encoding', 'content-length',
  'apikey', 'x-client-info', 'accept-encoding',
]);

const STRIP_RES = new Set([
  'sb-project-ref', 'sb-gateway-version', 'sb-request-id',
  'x-envoy-attempt-count', 'x-envoy-upstream-service-time',
  'set-cookie', 'content-encoding', 'transfer-encoding',
]);

module.exports = async function handler(req, res) {
  if (cors(req, res)) return;

  // Bloqueia acesso direto sem Origin/Referer do site (bots, curl, scrapers)
  const origin  = req.headers['origin']  || '';
  const referer = req.headers['referer'] || '';
  const hasValidSource =
    origin.startsWith(ALLOWED_ORIGIN) ||
    referer.startsWith(ALLOWED_ORIGIN);

  if (!hasValidSource) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  // Rate limiting por IP
  const ip = extractIp(req);
  const rl = checkIpRateLimit(ip, PROXY_RATE);
  if (!rl.allowed) {
    return res.status(429).json({
      error: `Too many requests. Try again in ${rl.retryAfterSec}s.`,
    });
  }

  // Constrói path a partir do catch-all — req.query.path pode ser array ou string
  const pathParts = Array.isArray(req.query.path)
    ? req.query.path
    : (req.query.path || '').split('/').filter(Boolean);

  // Whitelist de tabelas para requests anônimos (proxy-anon) — só para REST, não para auth
  const authHeader = req.headers['authorization'] || '';
  const isAnonRequest = !authHeader || authHeader === `Bearer ${PROXY_TOKEN}`;
  const isRestPath = pathParts[0] === 'rest';

  if (isAnonRequest && isRestPath) {
    // pathParts: ['rest', 'v1', 'table_name', ...]
    const table = pathParts[2];
    if (table && !ANON_WHITELIST.has(table)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    // Bloqueia escrita anônima em tabelas do usuário (precisa estar logado)
    const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
    const USER_TABLES = new Set(['cart_items', 'favorites', 'orders', 'order_items', 'addresses', 'profiles']);
    if (WRITE_METHODS.has(req.method) && USER_TABLES.has(table)) {
      return res.status(401).json({ error: 'Autenticação necessária para esta operação.' });
    }
    // Bloqueia qualquer escrita em tabelas de catálogo — somente leitura via API
    const READONLY_TABLES = new Set(['products', 'categories', 'store_settings']);
    if (WRITE_METHODS.has(req.method) && READONLY_TABLES.has(table)) {
      return res.status(403).json({ error: 'Tabela somente leitura.' });
    }
  }

  // Remove o param 'path' injetado pelo Vercel rewrite da query string
  const parsedUrl = new URL(req.url, 'http://x');
  parsedUrl.searchParams.delete('path');
  const qs   = parsedUrl.search;
  const slug = '/' + pathParts.join('/') + qs;
  const target = `${SUPABASE_URL}${slug}`;

  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (STRIP_REQ.has(k.toLowerCase())) continue;
    headers[k] = v;
  }

  // Troca token fictício pela chave real (requests não autenticados)
  if (!headers['authorization'] || headers['authorization'] === `Bearer ${PROXY_TOKEN}`) {
    headers['authorization'] = `Bearer ${ANON_KEY}`;
  }
  headers['apikey'] = ANON_KEY;
  headers['host']   = new URL(SUPABASE_URL).host;

  // ── Extrai user ID do JWT para validação de ownership ──
  let jwtUserId = null;
  if (headers['authorization'] && headers['authorization'] !== `Bearer ${ANON_KEY}`) {
    try {
      const token = headers['authorization'].replace('Bearer ', '');
      const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
      jwtUserId = payload.sub || null;
    } catch {}
  }

  // ── Limites de negócio no proxy (backend) ──
  if (isRestPath && req.body?.user_id) {
    const table = pathParts[2];

    // Valida que o user_id no body pertence ao usuário autenticado (anti-spoofing)
    if (jwtUserId && req.body.user_id !== jwtUserId) {
      return res.status(403).json({ error: 'user_id não corresponde ao usuário autenticado.' });
    }

    // Max 3 endereços por usuário
    if (table === 'addresses' && req.method === 'POST') {
      const countRes = await fetch(
        `${SUPABASE_URL}/rest/v1/addresses?user_id=eq.${req.body.user_id}&select=id`,
        { headers: { apikey: ANON_KEY, authorization: headers['authorization'] } }
      );
      const existing = await countRes.json();
      if (Array.isArray(existing) && existing.length >= 3) {
        return res.status(400).json({ error: 'Máximo de 3 endereços por usuário.' });
      }
    }

    // Favoritos: max 50 por usuário
    if (table === 'favorites' && req.method === 'POST') {
      const countRes = await fetch(
        `${SUPABASE_URL}/rest/v1/favorites?user_id=eq.${req.body.user_id}&select=id`,
        { headers: { apikey: ANON_KEY, authorization: headers['authorization'] } }
      );
      const existing = await countRes.json();
      if (Array.isArray(existing) && existing.length >= 50) {
        return res.status(400).json({ error: 'Máximo de 50 favoritos.' });
      }
    }

    // Cart: max 20 produtos distintos, quantidade 1-10 por produto
    if (table === 'cart_items') {
      const qty = req.body.quantity;
      if (qty !== undefined && (!Number.isInteger(qty) || qty < 1 || qty > 10)) {
        return res.status(400).json({ error: 'Quantidade inválida (1–10 por produto).' });
      }

      if (req.method === 'POST') {
        const countRes = await fetch(
          `${SUPABASE_URL}/rest/v1/cart_items?user_id=eq.${req.body.user_id}&select=product_id`,
          { headers: { apikey: ANON_KEY, authorization: headers['authorization'] } }
        );
        const existing = await countRes.json();
        if (Array.isArray(existing) && existing.length >= 20) {
          return res.status(400).json({ error: 'Máximo de 20 produtos no carrinho.' });
        }
      }
    }
  }

  let body;
  if (!['GET', 'HEAD'].includes(req.method) && req.body) {
    body = JSON.stringify(req.body);
    headers['content-type'] = 'application/json';
    // Não força content-length — deixa o fetch calcular para evitar mismatch
    delete headers['content-length'];
  }

  const upstream = await fetch(target, { method: req.method, headers, body });

  for (const [k, v] of upstream.headers.entries()) {
    if (STRIP_RES.has(k.toLowerCase())) continue;
    res.setHeader(k, v);
  }

  res.status(upstream.status);
  const buf = await upstream.arrayBuffer();
  res.end(Buffer.from(buf));
};
