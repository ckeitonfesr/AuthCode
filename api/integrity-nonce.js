const crypto   = require('crypto');
const supabase = require('./_supabase');
const { checkIpRateLimit, extractIp } = require('./_rate-limit');
const { checkRateLimit: checkRateLimitDb } = require('./_rate-limit-db');
const cors = require('./_cors');
const NONCE_RATE = 20;
const NONCE_TTL  = 90 * 1000;
module.exports = async function handler(req, res) {
  if (cors(req, res)) return;
  if (req.method !== 'POST') return res.status(405).end();
  const ip = extractIp(req);
  const [rlDb, rlMem] = await Promise.all([
    checkRateLimitDb(`ip:${ip}:in`, NONCE_RATE),
    Promise.resolve(checkIpRateLimit(ip, NONCE_RATE)),
  ]);
  const rl = rlDb.allowed ? rlMem : rlDb;
  if (!rl.allowed) {
    return res.status(429).json({ error: `Muitas requisições. Tente novamente em ${rl.retryAfterSec}s.` });
  }
  const timestamp = Date.now().toString();
  const random    = crypto.randomBytes(16).toString('hex');
  const message   = `${timestamp}:${random}`;
  const nonce = crypto
    .createHmac('sha256', process.env.APP_SECRET_KEY)
    .update(message)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\
    .replace(/=/g, '');
  const expiresAt = new Date(Date.now() + NONCE_TTL).toISOString();
  const { error } = await supabase.from('integrity_nonces').insert({ nonce, expires_at: expiresAt });
  if (error) {
    console.error('[integrity-nonce] erro ao salvar nonce:', error.message);
    return res.status(500).json({ error: 'Erro interno. Tente novamente.' });
  }
  supabase.from('integrity_nonces').delete().lt('expires_at', new Date().toISOString())
    .then(() => {}).catch(err => console.error('[integrity-nonce] cleanup error:', err));
  return res.status(200).json({ nonce, expiresIn: NONCE_TTL / 1000 });
};
