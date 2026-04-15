const supabase   = require('./_supabase');
const cors       = require('./_cors');
const { validateToken } = require('./_token');
const { extractIp, checkIpRateLimit } = require('./_rate-limit');
const { checkRateLimit } = require('./_rate-limit-db');
const { supabaseAdmin } = require('./_auth');
module.exports = async function handler(req, res) {
  if (cors(req, res)) return;

  if (req.query._hpfp === '1') {
    const hitId = req.query._id || '';
    const fp = req.body || {};
    const safe = {
      tz:    typeof fp.tz    === 'string'  ? fp.tz.slice(0, 64)    : null,
      lang:  typeof fp.lang  === 'string'  ? fp.lang.slice(0, 32)  : null,
      scr:   typeof fp.scr   === 'string'  ? fp.scr.slice(0, 16)   : null,
      dpr:   typeof fp.dpr   === 'number'  ? fp.dpr                 : null,
      pl:    typeof fp.pl    === 'string'  ? fp.pl.slice(0, 64)    : null,
      cpu:   typeof fp.cpu   === 'number'  ? fp.cpu                 : null,
      mem:   typeof fp.mem   === 'number'  ? fp.mem                 : null,
      touch: typeof fp.touch === 'boolean' ? fp.touch               : null,
    };
    if (hitId) {
      supabase.from('honeypot_hits').update({ fingerprint: safe }).eq('id', hitId)
        .then(() => {}).catch(() => {});
    }
    return res.status(200).json({ ok: true });
  }

  if (req.method !== 'POST') return res.status(405).end();
  const ip = extractIp(req);
  const [rlDb, rlMem] = await Promise.all([
    checkRateLimit(`ip:${ip}:ev`, 30),
    Promise.resolve(checkIpRateLimit(ip, 30)),
  ]);
  const rl = rlDb.allowed ? rlMem : rlDb;
  if (!rl.allowed) return res.status(429).end();
  const token    = req.headers['x-request-token'];
  const deviceId = req.headers['x-device-id'];
  const isValid  = await validateToken(token, deviceId, req);
  if (!isValid)  return res.status(401).json({ error: 'Token inválido.' });
  const { event_type, severity = 'info', path, details, fingerprint } = req.body || {};
  if (!event_type) return res.status(400).json({ error: 'event_type obrigatório.' });
  const ALLOWED_SEVERITIES = ['info', 'warning', 'critical'];
  const safeSeverity = ALLOWED_SEVERITIES.includes(severity) ? severity : 'info';
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
  const cutoff = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();
  supabase.from('security_events').delete().lt('created_at', cutoff)
    .then(() => {}).catch(err => console.error('[event] cleanup error:', err));
  return res.status(200).json({ ok: true });
};
