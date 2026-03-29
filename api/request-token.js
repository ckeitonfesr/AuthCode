const crypto = require('crypto');
const { generateToken }      = require('./_token');
const { checkIpRateLimit, extractIp } = require('./_rate-limit');
const { verifyIntegrityToken } = require('./_integrity-verify');

const TOKEN_RATE_LIMIT = 10; // max 10 tokens por IP por minuto

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const ip = extractIp(req);

  // Rate limiting por IP antes de qualquer outra verificação
  const rl = checkIpRateLimit(ip, TOKEN_RATE_LIMIT);
  if (!rl.allowed) {
    return res.status(429).json({
      error: `Muitas requisições. Tente novamente em ${rl.retryAfterSec}s.`,
    });
  }

  const deviceId  = req.headers['x-device-id'];
  const appKey    = req.headers['x-app-key'];
  const timestamp = req.headers['x-timestamp'];
  const signature = req.headers['x-signature'];

  if (!appKey || appKey !== process.env.APP_SECRET_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  if (!deviceId || typeof deviceId !== 'string' || deviceId.length < 4) {
    return res.status(400).json({ error: 'Device ID required' });
  }

  // Rejeita requests com timestamp fora da janela de 10 segundos (replay attack)
  const now     = Date.now();
  const reqTime = parseInt(timestamp || '0', 10);
  if (!timestamp || isNaN(reqTime) || Math.abs(now - reqTime) > 10000) {
    return res.status(401).json({ error: 'Request expired' });
  }

  // Valida assinatura HMAC-SHA256: SHA256(deviceId:timestamp:APP_SECRET_KEY)
  const expectedSig = crypto
    .createHash('sha256')
    .update(`${deviceId}:${timestamp}:${process.env.APP_SECRET_KEY}`)
    .digest('hex');

  if (!signature || signature !== expectedSig) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  // Verifica integridade do app (Play Integrity no Android, App Attest no iOS)
  const integrityToken = req.headers['x-integrity-token'];
  const integrityNonce = req.headers['x-integrity-nonce'];
  const platform       = req.headers['x-app-platform'] || 'android';

  const integrityDisabled = process.env.INTEGRITY_DISABLED === 'true';

  if (!integrityDisabled) {
    if (integrityToken && integrityNonce) {
      const { valid, reason } = await verifyIntegrityToken(integrityToken, integrityNonce, platform);
      if (!valid) {
        console.warn(`[request-token] Integridade reprovada (${platform}): ${reason}`);
        return res.status(403).json({ error: 'Verificação de integridade falhou.' });
      }
    } else if (process.env.NODE_ENV === 'production') {
      return res.status(403).json({ error: 'Token de integridade obrigatório.' });
    }
  }

  const token = await generateToken(deviceId, ip);
  return res.status(200).json({ token });
};
