const crypto = require('crypto');
const supabase = require('./_supabase');
const { validateToken } = require('./_token');
const { checkIpRateLimit, extractIp } = require('./_rate-limit');
const { checkRateLimit } = require('./_rate-limit-db');
const cors = require('./_cors');

const VERIFY_RATE = 10;
const SECRET_KEY = process.env.VERIFY_SECRET_KEY;

module.exports = async function handler(req, res) {
  if (cors(req, res)) return;
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'E00' });
  }

  const ip = extractIp(req);
  const [rlDb, rlMem] = await Promise.all([
    checkRateLimit(`ip:${ip}:vk`, VERIFY_RATE, { failSafe: false }),
    Promise.resolve(checkIpRateLimit(ip, VERIFY_RATE)),
  ]);
  const rl = rlDb.allowed ? rlMem : rlDb;
  if (!rl.allowed) {
    return res.status(429).json({ error: 'E01' });
  }

  const token = req.headers['x-request-token'];
  const deviceId = req.headers['x-device-id'];

  if (token) {
    const isValid = await validateToken(token, deviceId, req);
    if (!isValid) {
      return res.status(401).json({ error: 'E02' });
    }
  }

  const { key, hwid, nonce } = req.body ?? {};

  if (!key || typeof key !== 'string') {
    return res.status(400).json({ error: 'E03' });
  }

  if (!hwid || typeof hwid !== 'string') {
    return res.status(400).json({ error: 'E04' });
  }

  if (!nonce || typeof nonce !== 'string') {
    return res.status(400).json({ error: 'E05' });
  }

  // Gera o auth_hash com HMAC-SHA256 usando nonce + hwid
  const auth_hash = crypto.createHmac('sha256', SECRET_KEY)
                          .update(nonce + hwid)
                          .digest('hex');

  try {
    const { data: keyData, error: fetchError } = await supabase
      .from('cheat_keys')
      .select('*')
      .eq('key_value', key)
      .single();

    if (fetchError || !keyData) {
      return res.status(401).json({ error: 'E06' });
    }

    const now = new Date();

    // Primeiro login: ativa a key
    if (!keyData.first_login) {
      const expiresAt = new Date();
      expiresAt.setDate(now.getDate() + keyData.days);

      const { error: updateError } = await supabase
        .from('cheat_keys')
        .update({
          hwid: hwid,
          first_login: now.toISOString(),
          expires_at: expiresAt.toISOString(),
        })
        .eq('id', keyData.id);

      if (updateError) {
        return res.status(500).json({ error: 'E07' });
      }

      return res.status(200).json({
        success: true,
        expires_at: expiresAt.toISOString(),
        auth_hash: auth_hash,
      });
    }

    // Checa expiração
    const expirationDate = new Date(keyData.expires_at);
    if (now > expirationDate) {
      return res.status(403).json({ error: 'E08' });
    }

    // Checa HWID
    if (keyData.hwid !== hwid) {
      return res.status(403).json({ error: 'E09' });
    }

    return res.status(200).json({
      success: true,
      expires_at: keyData.expires_at,
      auth_hash: auth_hash,
    });
  } catch (err) {
    return res.status(500).json({ error: 'E10' });
  }
};
