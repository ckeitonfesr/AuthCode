const supabase = require('./_supabase');

const MAX_ATTEMPTS = 5;

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { email, code } = req.body ?? {};

  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({ error: 'Email inválido.' });
  }
  if (!code || typeof code !== 'string' || !/^\d{6}$/.test(code)) {
    return res.status(400).json({ error: 'Código deve ter 6 dígitos numéricos.' });
  }

  const normalizedEmail = email.trim().toLowerCase();

  const { data: entry, error: fetchError } = await supabase
    .from('auth_codes')
    .select('code, expires_at, attempts')
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

  if (code !== entry.code) {
    await supabase
      .from('auth_codes')
      .update({ attempts: entry.attempts + 1 })
      .eq('email', normalizedEmail);

    const remaining = MAX_ATTEMPTS - (entry.attempts + 1);
    return res.status(401).json({
      error: `Código incorreto. ${remaining} tentativa(s) restante(s).`,
    });
  }

  await supabase.from('auth_codes').delete().eq('email', normalizedEmail);

  return res.status(200).json({ success: true, message: 'Código verificado com sucesso.' });
}
