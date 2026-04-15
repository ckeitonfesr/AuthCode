const crypto  = require('crypto');
const supabase = require('./_supabase');
const { validateToken } = require('./_token');
const { checkIpRateLimit, extractIp } = require('./_rate-limit');
const { checkRateLimit } = require('./_rate-limit-db');
const cors = require('./_cors');
const { isValidEmail } = require('./_email-utils');
const MAX_ATTEMPTS   = 5;
const VERIFY_RATE    = 10;
function hashCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}
module.exports = async function handler(req, res) {
  if (cors(req, res)) return;
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
  const ip = extractIp(req);
  const [rlDb, rlMem] = await Promise.all([
    checkRateLimit(`ip:${ip}:vc`, VERIFY_RATE, { failSafe: false }),
    Promise.resolve(checkIpRateLimit(ip, VERIFY_RATE)),
  ]);
  const rl = rlDb.allowed ? rlMem : rlDb;
  if (!rl.allowed) {
    return res.status(429).json({
      error: `Muitas requisições. Tente novamente em ${rl.retryAfterSec}s.`,
    });
  }
  const token    = req.headers['x-request-token'];
  const deviceId = req.headers['x-device-id'];
  const isValid = await validateToken(token, deviceId, req);
  if (!isValid) {
    return res.status(401).json({ error: 'Token invalido ou expirado.' });
  }
  const { email, code } = req.body ?? {};
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Email inválido.' });
  }
  if (!code || typeof code !== 'string' || !/^\d{6}$/.test(code)) {
    return res.status(400).json({ error: 'Código deve ter 6 dígitos numéricos.' });
  }
  const normalizedEmail = email.trim().toLowerCase();
  const { data: entry, error: fetchError } = await supabase
    .from('auth_codes')
    .select('code_hash, expires_at, attempts')
    .eq('email', normalizedEmail)
    .single();
  if (fetchError || !entry) {
    return res.status(404).json({ error: 'Código não encontrado. Solicite um novo.' });
  }
  if (new Date(entry.expires_at) < new Date()) {
    await supabase.from('auth_codes').delete().eq('email', normalizedEmail);
    return res.status(410).json({ error: 'Código expirado. Solicite um novo.' });
  }
  if (entry.attempts >= MAX_ATTEMPTS) {
    await supabase.from('auth_codes').delete().eq('email', normalizedEmail);
    return res.status(429).json({ error: 'Muitas tentativas. Solicite um novo código.' });
  }
  const inputHash = hashCode(code);
  if (inputHash !== entry.code_hash) {
    const { data: updated } = await supabase
      .from('auth_codes')
      .update({ attempts: entry.attempts + 1 })
      .eq('email', normalizedEmail)
      .eq('attempts', entry.attempts)
      .select()
      .single();
    if (!updated) {
      return res.status(429).json({ error: 'Tente novamente.' });
    }
    const remaining = MAX_ATTEMPTS - (entry.attempts + 1);
    return res.status(401).json({
      error: `Código incorreto. ${remaining} tentativa(s) restante(s).`,
    });
  }
  await supabase.from('auth_codes').delete().eq('email', normalizedEmail);
  await supabase.from('otp_verified').upsert({
    email:       normalizedEmail,
    verified_at: new Date().toISOString(),
    expires_at:  new Date(Date.now() + 10 * 60 * 1000).toISOString(),
  });
  supabase
    .from('otp_verified')
    .delete()
    .lt('expires_at', new Date().toISOString())
    .neq('email', normalizedEmail)
    .then(() => {}).catch(err => console.error('[verify-code] otp_verified cleanup error:', err));
  return res.status(200).json({ success: true });
};
