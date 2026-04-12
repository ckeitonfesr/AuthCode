const crypto = require('crypto');
const { generateToken }      = require('./_token');
const { checkIpRateLimit, extractIp } = require('./_rate-limit');
const { checkRateLimit } = require('./_rate-limit-db');
const { verifyIntegrityToken } = require('./_integrity-verify');
const cors = require('./_cors');
const supabase = require('./_supabase');

function logEvent(event_type, severity, ip, device_id, details = {}) {
  supabase.from('security_events').insert({ event_type, severity, ip, device_id: device_id || null, path: '/api/rt', details }).then(() => {});
}

const TOKEN_RATE_LIMIT = 10; 

module.exports = async function handler(req, res) {
  if (cors(req, res)) return;
  if (req.method !== 'POST') return res.status(405).end();

  const ip = extractIp(req);

  
  const [rlDb, rlMem] = await Promise.all([
    checkRateLimit(`ip:${ip}:rt`, TOKEN_RATE_LIMIT),
    Promise.resolve(checkIpRateLimit(ip, TOKEN_RATE_LIMIT)),
  ]);
  const rl = rlDb.allowed ? rlMem : rlDb;
  if (!rl.allowed) {
    logEvent('rate_limit_hit', 'warning', ip, req.headers['x-device-id'], { retryAfterSec: rl.retryAfterSec, path: '/api/rt' });
    return res.status(429).json({
      error: `Muitas requisições. Tente novamente em ${rl.retryAfterSec}s.`,
    });
  }

  const deviceId  = req.headers['x-device-id'];
  const appKey    = req.headers['x-app-key'];
  const timestamp = req.headers['x-timestamp'];
  const signature = req.headers['x-signature'];

  if (!appKey || appKey !== process.env.APP_SECRET_KEY) {
    logEvent('invalid_app_key', 'critical', ip, deviceId, { provided_key: appKey ? appKey.slice(0, 8) + '…' : null });
    return res.status(401).json({ error: 'Unauthorized' });
  }

  
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!deviceId || typeof deviceId !== 'string' || !UUID_RE.test(deviceId)) {
    return res.status(400).json({ error: 'Device ID inválido.' });
  }

  
  const now     = Date.now();
  const reqTime = parseInt(timestamp || '0', 10);
  if (!timestamp || isNaN(reqTime) || Math.abs(now - reqTime) > 10000) {
    logEvent('replay_attack', 'warning', ip, deviceId, { skew_ms: Math.abs(now - reqTime), timestamp });
    return res.status(401).json({ error: 'Request expired' });
  }

  
  const expectedSig = crypto
    .createHash('sha256')
    .update(`${deviceId}:${timestamp}:${process.env.APP_SECRET_KEY}`)
    .digest('hex');

  if (!signature || signature !== expectedSig) {
    logEvent('invalid_signature', 'critical', ip, deviceId, { provided: signature ? signature.slice(0, 16) + '…' : null });
    return res.status(401).json({ error: 'Invalid signature' });
  }

  
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
