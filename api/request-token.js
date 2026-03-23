const { generateToken } = require('./_token');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const deviceId = req.headers['x-device-id'];
  const appKey   = req.headers['x-app-key'];
  const ip       = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!appKey || appKey !== process.env.APP_SECRET_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  if (!deviceId) {
    return res.status(400).json({ error: 'Device ID required' });
  }

  const token = await generateToken(deviceId, ip);
  return res.status(200).json({ token });
};
