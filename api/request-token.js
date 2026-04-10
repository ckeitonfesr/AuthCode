const crypto = require('crypto');
const { generateToken }      = require('./_token');
const { checkIpRateLimit, extractIp } = require('./_rate-limit');
const { checkRateLimit } = require('./_rate-limit-db');
const { verifyIntegrityToken } = require('./_integrity-verify');
const cors = require('./_cors');

const TOKEN_RATE_LIMIT = 10; // max 10 tokens por IP por minuto

module.exports = async function handler(req, res) {
  if (cors(req, res)) return;
  if (req.method !== 'POST') return res.status(405).end();

  const ip = extractIp(req);

  // Rate limiting centralizado (Supabase) + in-memory como camada extra
  const [rlDb, rlMem] = await Promise.all([
    checkRateLimit(`ip:${ip}:rt`, TOKEN_RATE_LIMIT),
    Promise.resolve(checkIpRateLimit(ip, TOKEN_RATE_LIMIT)),
  ]);
  const rl = rlDb.allowed ? rlMem : rlDb;
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

  // Valida formato UUID v4 (gerado pelo crypto.randomUUID() do client)
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!deviceId || typeof deviceId !== 'string' || !UUID_RE.test(deviceId)) {
    return res.status(400).json({ error: 'Device ID inválido.' });
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

  if (!integrityDisabled && integrityToken && integrityNonce) {
    const { valid, reason } = await verifyIntegrityToken(integrityToken, integrityNonce, platform);
    if (!valid) {
      console.warn(`[request-token] Integridade reprovada (${platform}): ${reason}`);
      return res.status(403).json({ error: 'Verificação de integridade falhou.' });
    }
  }

  const token = await generateToken(deviceId, ip);
  return res.status(200).json({ token });
};
