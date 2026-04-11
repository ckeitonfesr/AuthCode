const crypto    = require('crypto');
const supabase  = require('./_supabase');
const { extractIp } = require('./_rate-limit');

const TOKEN_TTL_SEC   = 60;
const CLEANUP_OLDER_H = 2;

async function generateToken(deviceId, ip) {
  const token     = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + TOKEN_TTL_SEC * 1000).toISOString();

  
  await supabase
    .from('api_tokens')
    .update({ used: true })
    .eq('device_id', deviceId)
    .eq('used', false);

  await supabase.from('api_tokens').insert({
    token,
    device_id:  deviceId,
    ip,
    expires_at: expiresAt,
    used:       false,
    created_at: new Date().toISOString(),
  });

  
  const cutoff = new Date(Date.now() - CLEANUP_OLDER_H * 60 * 60 * 1000).toISOString();
  supabase.from('api_tokens').delete().lt('created_at', cutoff).then(() => {});

  return token;
}

async function validateToken(token, deviceId, req) {
  
  const ip = (req && typeof req === 'object') ? extractIp(req) : (req || 'unknown');

  const { data, error } = await supabase
    .from('api_tokens')
    .select('device_id, ip, expires_at, used')
    .eq('token', token)
    .eq('used', false)
    .single();

  if (error || !data)                         return false;
  if (new Date(data.expires_at) < new Date()) return false;
  if (data.device_id !== deviceId)            return false;

  
  
  
  

  
  
  const { data: updated, error: updateErr } = await supabase
    .from('api_tokens')
    .update({ used: true })
    .eq('token', token)
    .eq('used', false)
    .select('token');

  if (updateErr || !updated || updated.length === 0) return false;
  return true;
}

module.exports = { generateToken, validateToken };
