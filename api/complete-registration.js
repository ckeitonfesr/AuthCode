const supabase = require('./_supabase');
const { validateToken } = require('./_token');

function isValidCpf(digits) {
  if (/^(\d)\1{10}$/.test(digits)) return false; // ex: 111.111.111-11
  let sum = 0;
  for (let i = 0; i < 9; i++) sum += parseInt(digits[i]) * (10 - i);
  let rem = (sum * 10) % 11;
  if (rem === 10 || rem === 11) rem = 0;
  if (rem !== parseInt(digits[9])) return false;
  sum = 0;
  for (let i = 0; i < 10; i++) sum += parseInt(digits[i]) * (11 - i);
  rem = (sum * 10) % 11;
  if (rem === 10 || rem === 11) rem = 0;
  return rem === parseInt(digits[10]);
}

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

  // CRÍTICO 2 — Verifica se OTP foi confirmado antes de criar conta
  const { data: verified } = await supabase
    .from('otp_verified')
    .select('expires_at')
    .eq('email', normalizedEmail)
    .single();

  if (!verified || new Date(verified.expires_at) < new Date()) {
    return res.status(403).json({ error: 'OTP nao verificado.' });
  }

  // Remove o registro OTP após usar (uso único)
  await supabase.from('otp_verified').delete().eq('email', normalizedEmail);

  const { data: userData, error: createError } = await supabase.auth.admin.createUser({
    email: normalizedEmail,
    password,
    email_confirm: true,
  });

  if (createError) {
    // CRÍTICO 1 — Se email já existe retorna 409, nunca atualiza senha
    if (createError.message?.toLowerCase().includes('already registered')) {
      return res.status(409).json({ error: 'Email ja cadastrado. Faca login.' });
    }
    console.error('[complete-registration]', createError.message);
    return res.status(500).json({ error: 'Erro interno. Tente novamente.' });
  }

  const u = userData.user;
  const firstName = fullName.trim().split(' ')[0];

  // Gera username único com sufixo aleatório para evitar colisões
  const randomSuffix = Math.random().toString(36).slice(2, 6);
  const username = `${firstName.toLowerCase()}_${randomSuffix}`;

  // Valida CPF (dígitos verificadores) se fornecido
  let validatedCpf = null;
  if (cpf) {
    const digits = cpf.replace(/\D/g, '');
    if (digits.length === 11 && isValidCpf(digits)) {
      validatedCpf = digits;
    }
  }

  await supabase.from('profiles').upsert({
    id: u.id,
    name: firstName,
    full_name: fullName,
    username,
    phone,
    cpf: validatedCpf,
  });

  return res.status(200).json({ success: true });
};
