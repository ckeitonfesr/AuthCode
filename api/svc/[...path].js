const cors = require('../_cors');

const SUPABASE_URL = 'https://sineixguxvlmatnyvtdw.supabase.co';
const ANON_KEY     = process.env.SUPABASE_ANON_KEY;
const PROXY_TOKEN  = 'proxy-anon';

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

  // Constrói path a partir do catch-all — req.query.path pode ser array ou string
  const pathParts = Array.isArray(req.query.path)
    ? req.query.path
    : (req.query.path || '').split('/').filter(Boolean);

  // Remove o param 'path' injetado pelo Vercel rewrite da query string
  const parsedUrl = new URL(req.url, 'http://x');
  parsedUrl.searchParams.delete('path');
  const qs   = parsedUrl.search; // '?select=*&user_id=eq.xxx' ou ''
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
    headers['content-type']   = 'application/json';
    headers['content-length'] = Buffer.byteLength(body).toString();
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
