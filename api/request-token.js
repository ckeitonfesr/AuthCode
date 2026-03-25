const crypto = require('crypto');
const { generateToken } = require('./_token');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const deviceId  = req.headers['x-device-id'];
  const appKey    = req.headers['x-app-key'];
  const timestamp = req.headers['x-timestamp'];
  const signature = req.headers['x-signature'];
  const ip        = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!appKey || appKey !== process.env.APP_SECRET_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  if (!deviceId) {
    return res.status(400).json({ error: 'Device ID required' });
  }

  // Valida timestamp — rejeita requests com mais de 30 segundos
  const now = Date.now();
  const reqTime = parseInt(timestamp || '0', 10);
  if (Math.abs(now - reqTime) > 30000) {
    return res.status(401).json({ error: 'Request expired' });
  }

  // Valida assinatura HMAC-SHA256 — prova que veio do app
  const expectedSig = crypto
    .createHmac('sha256', process.env.APP_SECRET_KEY)
    .update(`${deviceId}:${timestamp}`)
    .digest('hex');

  if (!signature || signature !== expectedSig) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  const token = await generateToken(deviceId, ip);
  return res.status(200).json({ token });
};
