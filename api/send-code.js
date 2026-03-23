// api/send-code.js
// POST /api/send-code
// Consulta o Supabase para checar throttle, salva o código e envia por email.

const { Resend } = require('resend');
const supabase = require('./_supabase');

const resend = new Resend(process.env.RESEND_API_KEY);

const CODE_TTL_SEC  = 60;  // código expira em 1 minuto
const THROTTLE_MS   = 60 * 1000; // 1 envio por minuto por email

/** Gera um código numérico aleatório de 6 dígitos. */
function generateCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { email } = req.body ?? {};

  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({ error: 'Email inválido.' });
  }

  const normalizedEmail = email.trim().toLowerCase();

  // ── 1. Consulta o Supabase: já existe um registro para este email? ──────────
  const { data: existing, error: fetchError } = await supabase
    .from('auth_codes')
    .select('created_at')
    .eq('email', normalizedEmail)
    .single();

  if (fetchError && fetchError.code !== 'PGRST116') {
    // PGRST116 = "row not found" — qualquer outro erro é inesperado
    console.error('[send-code] Erro ao consultar Supabase:', fetchError);
    return res.status(500).json({ error: 'Erro interno. Tente novamente.' });
  }

  // ── 2. Throttle: bloqueia se o último envio foi há menos de 1 minuto ────────
  if (existing) {
    const elapsed = Date.now() - new Date(existing.created_at).getTime();
    if (elapsed < THROTTLE_MS) {
      const waitSec = Math.ceil((THROTTLE_MS - elapsed) / 1000);
      return res.status(429).json({
        error: `Aguarde ${waitSec}s antes de solicitar um novo código.`,
      });
    }
  }

  // ── 3. Gera o novo código e salva (upsert) no Supabase ──────────────────────
  const code = generateCode();
  const expiresAt = new Date(Date.now() + CODE_TTL_SEC * 1000).toISOString();

  const { error: upsertError } = await supabase
    .from('auth_codes')
    .upsert({
      email: normalizedEmail,
      code,
      expires_at: expiresAt,
      attempts: 0,
      created_at: new Date().toISOString(),
    });

  if (upsertError) {
    console.error('[send-code] Erro ao salvar código:', upsertError);
    return res.status(500).json({ error: 'Erro interno. Tente novamente.' });
  }

  // ── 4. Envia o email via Resend ──────────────────────────────────────────────
  try {
    await resend.emails.send({
      from: '24horas-Central <onboarding@resend.dev>',
      to: normalizedEmail,
      subject: 'Seu código de verificação',
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px;">
          <img src="https://tse2.mm.bing.net/th/id/OIP.vbYCNbU7UNVQxmvkZe9_EQHaB-?rs=1&pid=ImgDetMain&o=7&rm=3.png" alt="Logo" width="120" style="margin-bottom:24px;" />
          <h2 style="margin:0 0 8px;">Verificação de email</h2>
          <p>Seu código de verificação é:</p>
          <div style="font-size:36px;font-weight:bold;letter-spacing:10px;padding:16px 0;">${code}</div>
          <p style="color:#666;">Este código expira em <strong>1 minuto</strong>.</p>
          <p style="color:#999;font-size:12px;">Se você não solicitou este código, ignore este email.</p>
        </div>
      `,
    });
  } catch (err) {
    // Remove o registro do Supabase se o envio falhar
    await supabase.from('auth_codes').delete().eq('email', normalizedEmail);
    console.error('[send-code] Erro ao enviar email:', err);
    return res.status(500).json({ error: 'Falha ao enviar o email. Tente novamente.' });
  }

  return res.status(200).json({ success: true, message: 'Código enviado para o email.' });
}
