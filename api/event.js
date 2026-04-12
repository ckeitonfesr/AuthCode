const supabase   = require('./_supabase');
const cors       = require('./_cors');
const { validateToken } = require('./_token');
const { extractIp, checkIpRateLimit } = require('./_rate-limit');
const { supabaseAdmin } = require('./_auth');

module.exports = async function handler(req, res) {
  if (cors(req, res)) return;
  if (req.method !== 'POST') return res.status(405).end();

  const ip = extractIp(req);
  const rl = checkIpRateLimit(ip, 30);
  if (!rl.allowed) return res.status(429).end();

  const token    = req.headers['x-request-token'];
  const deviceId = req.headers['x-device-id'];
  const isValid  = await validateToken(token, deviceId, req);
  if (!isValid)  return res.status(401).json({ error: 'Token inválido.' });

  const { event_type, severity = 'info', path, details, fingerprint } = req.body || {};
  if (!event_type) return res.status(400).json({ error: 'event_type obrigatório.' });

  const ALLOWED_SEVERITIES = ['info', 'warning', 'critical'];
  const safeSeverity = ALLOWED_SEVERITIES.includes(severity) ? severity : 'info';

  // [H1] user_id vem do JWT verificado pelo Supabase, não do body.
  // Isso impede que qualquer cliente injete eventos com user_id de outra pessoa.
  let verifiedUserId = null;
  const userJwt = req.headers['x-user-token'];
  if (userJwt) {
    const { data: { user } } = await supabaseAdmin.auth.getUser(userJwt);
    verifiedUserId = user?.id || null;
  }

  await supabase.from('security_events').insert({
    event_type:  String(event_type).slice(0, 64),
    severity:    safeSeverity,
    ip,
    device_id:   deviceId || null,
    user_id:     verifiedUserId,
    path:        path ? String(path).slice(0, 256) : null,
    details:     details     || {},
    fingerprint: fingerprint || {},
  });

  return res.status(200).json({ ok: true });
};
