const supabase = require('./_supabase');
const { validateToken } = require('./_token');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const token    = req.headers['x-request-token'];
  const deviceId = req.headers['x-device-id'];
  const ip       = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  const isValid = await validateToken(token, deviceId, ip);
  if (!isValid) return res.status(401).json({ error: 'Token invalido ou expirado.' });

  const { email, password, phone, fullName, cpf } = req.body ?? {};

  if (!email || !password || !phone || !fullName) {
    return res.status(400).json({ error: 'Dados incompletos.' });
  }

  const normalizedEmail = email.trim().toLowerCase();

  const { data: userData, error: createError } = await supabase.auth.admin.createUser({
    email: normalizedEmail,
    password,
    email_confirm: true,
  });

  if (createError) {
    console.error('[complete-registration]', createError.message);
    if (createError.message?.toLowerCase().includes('already registered')) {
      return res.status(409).json({ error: 'Email ja cadastrado. Faca login.' });
    }
    return res.status(500).json({ error: createError.message });
  }

  const u = userData.user;
  const firstName = fullName.trim().split(' ')[0];

  await supabase.from('profiles').upsert({
    id: u.id,
    name: firstName,
    full_name: fullName,
    username: firstName.toLowerCase(),
    phone,
    cpf: cpf || null,
  });

  return res.status(200).json({ success: true });
};
