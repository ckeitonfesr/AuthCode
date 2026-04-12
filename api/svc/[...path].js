const cors = require('../_cors');
const { checkIpRateLimit, extractIp } = require('../_rate-limit');

const SUPABASE_URL   = 'https://sineixguxvlmatnyvtdw.supabase.co';
const ANON_KEY       = process.env.SUPABASE_ANON_KEY;
const PROXY_TOKEN    = 'proxy-anon';
const ALLOWED_ORIGIN = 'https://24hrs-central.site';

const ANON_WHITELIST = new Set([
  'products', 'categories', 'profiles', 'favorites',
  'cart_items', 'orders', 'order_items', 'addresses',
]);

// Tabelas internas nunca acessíveis via proxy (independente de auth)
const BLOCKED_TABLES = new Set([
  'auth_codes', 'api_tokens', 'otp_verified',
  'security_events', 'rate_limit_counters',
]);

// Tabelas somente-leitura para TODOS os usuários via proxy.
// Writes só via endpoints dedicados (create-order, admin panel com service role).
const READONLY_TABLES = new Set([
  'products', 'categories', 'store_settings',
  'orders', 'order_items',
]);

const PROXY_RATE = 45;

const STRIP_REQ = new Set([
  'host', 'connection', 'transfer-encoding', 'content-length',
  'apikey', 'x-client-info', 'accept-encoding',
]);

const STRIP_RES = new Set([
  'sb-project-ref', 'sb-gateway-version', 'sb-request-id',
  'x-envoy-attempt-count', 'x-envoy-upstream-service-time',
  'set-cookie', 'content-encoding', 'transfer-encoding',
]);

// Decodifica payload JWT sem verificar assinatura (apenas para inspeção de claims)
function decodeJwtPayload(token) {
  try {
    const part = token.split('.')[1];
    return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
  } catch { return null; }
}

module.exports = async function handler(req, res) {
  if (cors(req, res)) return;

  // Proteção primária: CORS do browser bloqueia outras origens.
  // Origin/Referer check impede chamadas diretas não-browser básicas.
  // A proteção real de dados vem do Supabase RLS em cada tabela.
  // [S8] Usa igualdade exata ou startsWith com '/' para evitar bypass via
  // subdomínio malicioso (ex: "https://24hrs-central.site.evil.com").
  const isAllowedSource = (v) =>
    v === ALLOWED_ORIGIN || v.startsWith(ALLOWED_ORIGIN + '/');
  const origin  = req.headers['origin']  || '';
  const referer = req.headers['referer'] || '';
  if (!isAllowedSource(origin) && !isAllowedSource(referer)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const ip = extractIp(req);
  const rl = checkIpRateLimit(ip, PROXY_RATE);
  if (!rl.allowed) {
    return res.status(429).json({
      error: `Too many requests. Try again in ${rl.retryAfterSec}s.`,
    });
  }

  const pathParts = Array.isArray(req.query.path)
    ? req.query.path
    : (req.query.path || '').split('/').filter(Boolean);

  const authHeader    = req.headers['authorization'] || '';
  const isAnonRequest = !authHeader || authHeader === `Bearer ${PROXY_TOKEN}`;
  const isRestPath    = pathParts[0] === 'rest';
  const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

  // [S1] Bloqueia JWTs com role=admin: operações admin devem ir pelo painel,
  // não pelo proxy cliente. Impede escalação via RLS admin policies.
  if (!isAnonRequest && isRestPath) {
    const rawJwt = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    const payload = rawJwt ? decodeJwtPayload(rawJwt) : null;
    if (payload?.app_metadata?.role === 'admin') {
      return res.status(403).json({ error: 'Operações administrativas devem usar o painel admin.' });
    }
  }

  if (isRestPath) {
    const table = pathParts[2];

    // [S2] Tabelas internas nunca expostas pelo proxy
    if (table && BLOCKED_TABLES.has(table)) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    // [S3] Writes em tabelas somente-leitura bloqueados para TODOS (anon e autenticado)
    if (WRITE_METHODS.has(req.method) && READONLY_TABLES.has(table)) {
      return res.status(403).json({ error: 'Tabela somente leitura.' });
    }
  }

  if (isAnonRequest && isRestPath) {
    const table = pathParts[2];
    if (table && !ANON_WHITELIST.has(table)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const USER_TABLES = new Set(['cart_items', 'favorites', 'orders', 'order_items', 'addresses', 'profiles']);
    if (WRITE_METHODS.has(req.method) && USER_TABLES.has(table)) {
      return res.status(401).json({ error: 'Autenticação necessária para esta operação.' });
    }
  }

  const parsedUrl = new URL(req.url, 'http://x');
  parsedUrl.searchParams.delete('path');
  const qs    = parsedUrl.search;
  const slug  = '/' + pathParts.join('/') + qs;
  const target = `${SUPABASE_URL}${slug}`;

  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (STRIP_REQ.has(k.toLowerCase())) continue;
    // não repassar x-app-key para o Supabase
    if (k.toLowerCase() === 'x-app-key') continue;
    headers[k] = v;
  }

  if (!headers['authorization'] || headers['authorization'] === `Bearer ${PROXY_TOKEN}`) {
    headers['authorization'] = `Bearer ${ANON_KEY}`;
  }
  headers['apikey'] = ANON_KEY;
  headers['host']   = new URL(SUPABASE_URL).host;

  // [C3] Removido: check de user_id via JWT não-verificado (decode sem validação
  // de assinatura dava false confidence). O Supabase verifica o JWT e o RLS
  // garante que cada usuário só acessa os próprios dados.

  // Limites de negócio para operações autenticadas
  if (isRestPath && req.body?.user_id) {
    const table = pathParts[2];

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
