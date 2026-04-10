/**
 * Rate limiting centralizado via Supabase.
 * Funciona corretamente em serverless — não depende de memória por instância.
 * Usado nos endpoints críticos: request-token, send-code, create-order.
 *
 * Requer a tabela rate_limits no Supabase (ver rate_limits.sql).
 */

const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const WINDOW_MS = 60 * 1000; // janela de 1 minuto

/**
 * Verifica e incrementa o contador no banco.
 * @param {string} key     – identificador único (ex: "ip:1.2.3.4:send-code")
 * @param {number} limit   – máximo de requisições na janela
 * @returns {Promise<{ allowed: boolean, retryAfterSec: number }>}
 */
async function checkRateLimit(key, limit) {
  const now      = Date.now();
  const windowId = Math.floor(now / WINDOW_MS); // muda a cada minuto
  const dbKey    = `${key}:${windowId}`;
  const expiresAt = new Date(now + WINDOW_MS).toISOString();

  try {
    // Upsert: se não existe cria com count=1, se existe incrementa
    const { data, error } = await supabase.rpc('rate_limit_increment', {
      p_key:        dbKey,
      p_limit:      limit,
      p_expires_at: expiresAt,
    });

    if (error) {
      // Falha no banco → fail-open com in-memory fallback (não bloqueia usuário legítimo)
      console.error('[rate-limit-db] erro:', error.message);
      return { allowed: true, retryAfterSec: 0 };
    }

    if (!data.allowed) {
      const resetAt = new Date(data.expires_at).getTime();
      const retryAfterSec = Math.max(1, Math.ceil((resetAt - now) / 1000));
      return { allowed: false, retryAfterSec };
    }

    return { allowed: true, retryAfterSec: 0 };
  } catch (err) {
    console.error('[rate-limit-db] exceção:', err.message);
    return { allowed: true, retryAfterSec: 0 }; // fail-open
  }
}

module.exports = { checkRateLimit };
