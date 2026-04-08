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
  'otp_verified',
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

  // Whitelist de tabelas para requests anônimos (proxy-anon)
  const authHeader = req.headers['authorization'] || '';
  const isAnonRequest = !authHeader || authHeader === `Bearer ${PROXY_TOKEN}`;

  if (isAnonRequest) {
    // pathParts: ['rest', 'v1', 'table_name', ...]
    const table = pathParts[2]; // rest/v1/{table}
    if (table && !ANON_WHITELIST.has(table)) {
      return res.status(403).json({ error: 'Forbidden' });
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
