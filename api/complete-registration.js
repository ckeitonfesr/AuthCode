const crypto    = require('crypto');
const supabase  = require('./_supabase');
const { validateToken } = require('./_token');
const { checkIpRateLimit, extractIp } = require('./_rate-limit');
const cors = require('./_cors');

function isValidCpf(digits) {
  if (/^(\d)\1{10}$/.test(digits)) return false; 
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
  if (cors(req, res)) return;
  if (req.method !== 'POST') return res.status(405).end();

  const ip = extractIp(req);
  const rl = checkIpRateLimit(ip, 5); 
  if (!rl.allowed) {
    return res.status(429).json({ error: `Muitas requisições. Tente novamente em ${rl.retryAfterSec}s.` });
  }

  const token    = req.headers['x-request-token'];
  const deviceId = req.headers['x-device-id'];

  const isValid = await validateToken(token, deviceId, req);
  if (!isValid) return res.status(401).json({ error: 'Token invalido ou expirado.' });

  const { email, password, phone, fullName, cpf } = req.body ?? {};

  if (!email || !password || !phone || !fullName) {
    return res.status(400).json({ error: 'Dados incompletos.' });
  }

  
  if (typeof email !== 'string' || email.length > 254) {
    return res.status(400).json({ error: 'Email invalido.' });
  }
  if (typeof fullName !== 'string' || fullName.trim().length < 2 || fullName.length > 200) {
    return res.status(400).json({ error: 'Nome invalido.' });
  }
  if (typeof phone !== 'string' || phone.length > 20) {
    return res.status(400).json({ error: 'Telefone invalido.' });
  }

  
  
  
  if (
    typeof password !== 'string' ||
    password.length < 10 ||
    password.length > 128 ||
    !/[A-Z]/.test(password) ||
    !/[a-z]/.test(password) ||
    !/[0-9]/.test(password)
  ) {
    return res.status(400).json({ error: 'Senha invalida.' });
  }

  const normalizedEmail = email.trim().toLowerCase();

  
  const { data: verified } = await supabase
    .from('otp_verified')
    .select('expires_at')
    .eq('email', normalizedEmail)
    .single();

  if (!verified || new Date(verified.expires_at) < new Date()) {
    return res.status(403).json({ error: 'OTP nao verificado.' });
  }

  
  await supabase.from('otp_verified').delete().eq('email', normalizedEmail);

  const { data: userData, error: createError } = await supabase.auth.admin.createUser({
    email: normalizedEmail,
    password,
    email_confirm: true,
  });

  if (createError) {
    
    if (createError.message?.toLowerCase().includes('already registered')) {
      return res.status(409).json({ error: 'Email ja cadastrado. Faca login.' });
    }
    console.error('[complete-registration]', createError.message);
    return res.status(500).json({ error: 'Erro interno. Tente novamente.' });
  }

  const u = userData.user;
  const firstName = fullName.trim().split(' ')[0];

  
  const randomSuffix = crypto.randomBytes(3).toString('hex');
  const username = `${firstName.toLowerCase()}_${randomSuffix}`;

  
  let validatedCpf = null;
  if (cpf) {
    const digits = cpf.replace(/\D/g, '');
    if (digits.length === 11 && isValidCpf(digits)) {
      
      const { data: existing } = await supabase
        .from('profiles')
        .select('id')
        .eq('cpf', digits)
        .maybeSingle();
      if (existing) {
        return res.status(409).json({ error: 'CPF já cadastrado.' });
      }
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
