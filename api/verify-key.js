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

  const { key, hwid, nonce } = req.body ?? {};
  if (!key || !hwid || !nonce) return res.status(400).json({ error: 'E03' });

  const auth_hash = crypto.createHmac('sha256', SECRET_KEY).update(nonce + hwid).digest('hex');

  try {
    const { data: keyData, error: fetchError } = await supabase
      .from('cheat_keys')
      .select('*')
      .eq('key_value', key)
      .single();

    if (fetchError || !keyData) return res.status(401).json({ error: 'E06' });

    const now = new Date();

    if (keyData.is_trial) {
      const { data: existingSession } = await supabase
        .from('key_sessions')
        .select('*')
        .eq('key_id', keyData.id)
        .eq('hwid', hwid)
        .single();

      if (!existingSession) {
        const { count } = await supabase
          .from('key_sessions')
          .select('*', { count: 'exact', head: true })
          .eq('key_id', keyData.id);

        if (count >= keyData.max_uses) return res.status(403).json({ error: 'E11' });

        const expiresAt = new Date(now.getTime() + (keyData.days * 86400000));
        await supabase.from('key_sessions').insert({
          key_id: keyData.id,
          hwid: hwid,
          expires_at: expiresAt.toISOString()
        });
        return res.status(200).json({ success: true, expires_at: expiresAt.toISOString(), auth_hash });
      }

      if (now > new Date(existingSession.expires_at)) return res.status(403).json({ error: 'E08' });
      return res.status(200).json({ success: true, expires_at: existingSession.expires_at, auth_hash });
    } else {
      if (!keyData.first_login) {
        const expiresAt = new Date(now.getTime() + (keyData.days * 86400000));
        await supabase.from('cheat_keys').update({ hwid, first_login: now.toISOString(), expires_at: expiresAt.toISOString() }).eq('id', keyData.id);
        return res.status(200).json({ success: true, expires_at: expiresAt.toISOString(), auth_hash });
      }
      if (now > new Date(keyData.expires_at)) return res.status(403).json({ error: 'E08' });
      if (keyData.hwid !== hwid) return res.status(403).json({ error: 'E09' });
      return res.status(200).json({ success: true, expires_at: keyData.expires_at, auth_hash });
    }
  } catch (err) {
    return res.status(500).json({ error: 'E10' });
  }
};
