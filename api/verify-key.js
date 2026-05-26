const supabase = require('./_supabase');
const { validateToken } = require('./_token');
const { checkIpRateLimit, extractIp } = require('./_rate-limit');
const { checkRateLimit } = require('./_rate-limit-db');
const cors = require('./_cors');

const VERIFY_RATE = 10;

module.exports = async function handler(req, res) {
  // CORS do seu projeto
  if (cors(req, res)) return;
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const ip = extractIp(req);
  const [rlDb, rlMem] = await Promise.all([
    checkRateLimit(`ip:${ip}:vk`, VERIFY_RATE, { failSafe: false }),
    Promise.resolve(checkIpRateLimit(ip, VERIFY_RATE)),
  ]);
  const rl = rlDb.allowed ? rlMem : rlDb;
  if (!rl.allowed) {
    return res.status(429).json({
      error: `Muitas requisições. Tente novamente em ${rl.retryAfterSec}s.`,
    });
  }

  // Validação do Token e Device ID do AuthCode
  const token = req.headers['x-request-token'];
  const deviceId = req.headers['x-device-id'];
  
  if (token) {
    // Se quiser validar o token, pode descomentar a linha abaixo. 
    // Como a checagem é silenciosa pelo app Android, o app terá que fazer 
    // o request-token primeiro para obter esse token.
    const isValid = await validateToken(token, deviceId, req);
    if (!isValid) {
      return res.status(401).json({ error: 'Token invalido ou expirado.' });
    }
  }

  const { key, hwid } = req.body ?? {};

  if (!key || typeof key !== 'string') {
    return res.status(400).json({ error: 'Faltando key' });
  }
  
  if (!hwid || typeof hwid !== 'string') {
    return res.status(400).json({ error: 'Faltando hwid do dispositivo' });
  }

  try {
    // Busca a key
    const { data: keyData, error: fetchError } = await supabase
      .from('cheat_keys')
      .select('*')
      .eq('key_value', key)
      .single();

    if (fetchError || !keyData) {
      return res.status(401).json({ error: 'Key Invalida' });
    }

    const now = new Date();

    // Primeiro login da key
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
        return res.status(500).json({ error: 'Erro ao ativar a key' });
      }

      return res.status(200).json({
        success: true,
        message: 'Key ativada',
        expires_at: expiresAt.toISOString(),
      });
    }

    // Se já ativou, checa expiração
    const expirationDate = new Date(keyData.expires_at);
    if (now > expirationDate) {
      return res.status(403).json({ error: 'Key expirada' });
    }

    // Checa o HWID (se tentou usar em outro aparelho)
    if (keyData.hwid !== hwid) {
      return res.status(403).json({ error: 'HWID Invalido (Dispositivo diferente)' });
    }

    return res.status(200).json({
      success: true,
      message: 'Login OK',
      expires_at: keyData.expires_at,
    });
  } catch (err) {
    console.error('[verify-key] Erro interno:', err);
    return res.status(500).json({ error: 'Erro no servidor' });
  }
};
