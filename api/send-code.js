const { Resend }      = require('resend');
const { createClient } = require('@supabase/supabase-js');
const crypto           = require('crypto');
const supabase         = require('./_supabase');
const { validateToken } = require('./_token');
const { checkIpRateLimit, extractIp } = require('./_rate-limit');
const { checkRateLimit } = require('./_rate-limit-db');
const cors = require('./_cors');

// Cliente separado para consultar schema auth (service role necessário)
const supabaseAuth = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { db: { schema: 'auth' } }
);

const resend = new Resend(process.env.RESEND_API_KEY);

const CODE_TTL_SEC      = 60;        // 1 minuto
const THROTTLE_MS       = 60 * 1000; // reenvio só após 1 minuto
const SENDCODE_RATE     = 5;         // max 5 envios por IP por minuto
const MIN_RESPONSE_MS   = 800;       // tempo mínimo de resposta — evita timing oracle

// Regex RFC 5321 simplificado — rejeita formatos claramente inválidos
const EMAIL_RE = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

function generateCode() {
  return String(crypto.randomInt(100000, 1000000));
}

function hashCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

// Garante tempo mínimo de resposta para equalizar timing entre caminhos distintos
async function minDelay(startMs) {
  const remaining = MIN_RESPONSE_MS - (Date.now() - startMs);
  if (remaining > 0) await new Promise(r => setTimeout(r, remaining));
}

module.exports = async function handler(req, res) {
  if (cors(req, res)) return;
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const start = Date.now();
  const ip = extractIp(req);

  // Rate limiting centralizado (Supabase) + in-memory como camada extra
  const [rlDb, rlMem] = await Promise.all([
    checkRateLimit(`ip:${ip}:sc`, SENDCODE_RATE),
    Promise.resolve(checkIpRateLimit(ip, SENDCODE_RATE)),
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

  const { email } = req.body ?? {};

  if (!email || typeof email !== 'string' || !EMAIL_RE.test(email) || email.length > 254) {
    return res.status(400).json({ error: 'Email inválido.' });
  }

  const normalizedEmail = email.trim().toLowerCase();

  // Bloqueia email já cadastrado — retorna 200 (anti-enumeração)
  const { data: authUser } = await supabaseAuth
    .from('users')
    .select('id')
    .eq('email', normalizedEmail)
    .maybeSingle();

  if (authUser) {
    await minDelay(start);
    return res.status(200).json({ success: true, message: 'Codigo enviado para o email.' });
  }

  // Throttle por email
  const { data: existing, error: fetchError } = await supabase
    .from('auth_codes')
    .select('created_at')
    .eq('email', normalizedEmail)
    .single();

  if (fetchError && fetchError.code !== 'PGRST116') {
    console.error('[send-code] Erro ao consultar Supabase:', fetchError);
    return res.status(500).json({ error: 'Erro interno. Tente novamente.' });
  }

  if (existing) {
    const elapsed = Date.now() - new Date(existing.created_at).getTime();
    if (elapsed < THROTTLE_MS) {
      const waitSec = Math.ceil((THROTTLE_MS - elapsed) / 1000);
      return res.status(429).json({
        error: `Aguarde ${waitSec}s antes de solicitar um novo código.`,
      });
    }
  }

  const code      = generateCode();
  const codeHash  = hashCode(code);           // armazena hash, nunca o código em plaintext
  const expiresAt = new Date(Date.now() + CODE_TTL_SEC * 1000).toISOString();

  const { error: upsertError } = await supabase
    .from('auth_codes')
    .upsert({
      email:      normalizedEmail,
      code_hash:  codeHash,
      expires_at: expiresAt,
      attempts:   0,
      created_at: new Date().toISOString(),
    });

  if (upsertError) {
    console.error('[send-code] Erro ao salvar código:', upsertError);
    return res.status(500).json({ error: 'Erro interno. Tente novamente.' });
  }

  try {
    await resend.emails.send({
      from:    '24h Central <noreply@24hrs-central.site>',
      to:      normalizedEmail,
      subject: 'Seu código de acesso',
      html: `
        <table width="100%" cellpadding="0" cellspacing="0" style="background:#111111;font-family:'Segoe UI',Arial,sans-serif;">
          <tr><td align="center" style="padding:40px 16px;">
            <table width="520" cellpadding="0" cellspacing="0" style="background:#0a0a0a;border-radius:12px;overflow:hidden;border:1px solid #222;">
              <tr>
                <td style="background:#000000;padding:28px 40px;text-align:center;border-bottom:3px solid #f5c400;">
                  <div style="font-size:32px;font-weight:900;color:#f5c400;letter-spacing:-1px;line-height:1;">24h</div>
                  <div style="font-size:11px;font-weight:700;color:#ff6a00;letter-spacing:4px;text-transform:uppercase;margin-top:2px;">Conveniência Central</div>
                </td>
              </tr>
              <tr>
                <td style="padding:36px 40px 28px;">
                  <h2 style="margin:0 0 10px;font-size:20px;font-weight:700;color:#ffffff;">Seu código de acesso</h2>
                  <p style="margin:0 0 24px;font-size:15px;color:#9ca3af;line-height:1.6;">Use o código abaixo para acessar sua conta:</p>
                  <div style="background:#111111;border:1px solid #2a2a2a;border-radius:10px;padding:28px 20px;text-align:center;margin-bottom:24px;">
                    <div style="font-size:11px;font-weight:700;color:#f5c400;letter-spacing:3px;text-transform:uppercase;margin-bottom:12px;">Código de verificação</div>
                    <div style="font-size:42px;font-weight:900;letter-spacing:14px;color:#ffffff;">${code}</div>
                  </div>
                  <p style="margin:0;font-size:13px;color:#6b7280;">Se você não solicitou este código, ignore este e-mail. Nenhuma ação será tomada em sua conta.</p>
                </td>
              </tr>
              <tr>
                <td style="background:linear-gradient(90deg,#f5c400,#ff6a00);padding:4px 0;"></td>
              </tr>
            </table>
          </td></tr>
        </table>
      `,
    });
  } catch (err) {
    await supabase.from('auth_codes').delete().eq('email', normalizedEmail);
    console.error('[send-code] Erro ao enviar email:', err);
    return res.status(500).json({ error: 'Falha ao enviar o email. Tente novamente.' });
  }

  await minDelay(start);
  return res.status(200).json({ success: true, message: 'Código enviado para o email.' });
};
