const crypto = require('crypto');
const supabase = require('./_supabase');

const TOKEN_TTL_SEC = 60;

async function generateToken(deviceId, ip) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + TOKEN_TTL_SEC * 1000).toISOString();

  // BAIXO 10 — Invalida tokens anteriores do mesmo device
  await supabase
    .from('api_tokens')
    .update({ used: true })
    .eq('device_id', deviceId)
    .eq('used', false);

  await supabase.from('api_tokens').insert({
    token,
    device_id: deviceId,
    ip,
    expires_at: expiresAt,
    used: false,
    created_at: new Date().toISOString(),
  });

  return token;
}

async function validateToken(token, deviceId, ip) {
  const { data, error } = await supabase
    .from('api_tokens')
    .select('*')
    .eq('token', token)
    .eq('used', false)
    .single();

  if (error || !data) return false;
  if (new Date(data.expires_at) < new Date()) return false;
  if (data.device_id !== deviceId) return false;
  // MÉDIO 8 — Valida IP do token
  if (data.ip && data.ip !== ip) return false;

  // Update condicional — só marca used=true se ainda estava false (evita uso paralelo)
  const { count } = await supabase
    .from('api_tokens')
    .update({ used: true })
    .eq('token', token)
    .eq('used', false)
    .select('token', { count: 'exact', head: true });

  if (!count) return false; // outra request já usou este token
  return true;
}

module.exports = { generateToken, validateToken };
