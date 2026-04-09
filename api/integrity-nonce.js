const crypto = require('crypto');
const { checkIpRateLimit, extractIp } = require('./_rate-limit');
const cors = require('./_cors');

const NONCE_RATE  = 20;             // max 20 nonces por IP por minuto
const NONCE_TTL   = 90 * 1000;      // nonce válido por 90 segundos
const USED_NONCES = new Map();      // cache em memória para evitar reuso

// Limpeza periódica dos nonces expirados (fire-and-forget)
function evictNonces() {
  const now = Date.now();
  for (const [nonce, exp] of USED_NONCES.entries()) {
    if (now > exp) USED_NONCES.delete(nonce);
  }
}

/**
 * Gera um nonce assinado com HMAC-SHA256 para uso no Play Integrity / App Attest.
 * Formato: base64url( HMAC-SHA256( timestamp:random, APP_SECRET_KEY ) )
 * O servidor pode verificar autenticidade + frescor sem armazenar estado no banco.
 */
module.exports = async function handler(req, res) {
  if (cors(req, res)) return;
  if (req.method !== 'POST') return res.status(405).end();

  const ip = extractIp(req);
  const rl = checkIpRateLimit(ip, NONCE_RATE);
  if (!rl.allowed) {
    return res.status(429).json({
      error: `Muitas requisições. Tente novamente em ${rl.retryAfterSec}s.`,
    });
  }

  evictNonces();

  const timestamp = Date.now().toString();
  const random    = crypto.randomBytes(16).toString('hex');
  const message   = `${timestamp}:${random}`;

  const nonce = crypto
    .createHmac('sha256', process.env.APP_SECRET_KEY)
    .update(message)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, ''); // base64url sem padding

  // Armazena para impedir reuso
  USED_NONCES.set(nonce, Date.now() + NONCE_TTL);

  return res.status(200).json({ nonce, expiresIn: NONCE_TTL / 1000 });
};
