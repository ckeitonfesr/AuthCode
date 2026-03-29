/**
 * Rate limiting por IP — in-memory (best-effort em serverless).
 * Em ambientes serverless como Vercel cada instância tem seu próprio mapa,
 * então isto funciona como camada de defesa por instância quente.
 */

const ipStore = new Map();

const WINDOW_MS = 60 * 1000; // 1 minuto

function evict() {
  const now = Date.now();
  for (const [key, entry] of ipStore.entries()) {
    if (now > entry.resetAt) ipStore.delete(key);
  }
}

/**
 * @param {string} ip
 * @param {number} limit  – máximo de requisições por janela
 * @returns {{ allowed: boolean, retryAfterSec: number }}
 */
function checkIpRateLimit(ip, limit) {
  evict();
  const now  = Date.now();
  const key  = ip || 'unknown';
  let entry  = ipStore.get(key);

  if (!entry || now > entry.resetAt) {
    entry = { count: 1, resetAt: now + WINDOW_MS };
    ipStore.set(key, entry);
    return { allowed: true, retryAfterSec: 0 };
  }

  if (entry.count >= limit) {
    const retryAfterSec = Math.ceil((entry.resetAt - now) / 1000);
    return { allowed: false, retryAfterSec };
  }

  entry.count++;
  return { allowed: true, retryAfterSec: 0 };
}

/**
 * Extrai o IP real do cliente priorizando x-real-ip (setado pelo Vercel
 * antes que o cliente possa injetar) e caindo no primeiro valor de
 * x-forwarded-for, que no Vercel é o IP real na posição 0.
 */
function extractIp(req) {
  const realIp = req.headers['x-real-ip'];
  if (realIp) return realIp.split(',')[0].trim();

  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();

  return req.socket?.remoteAddress || 'unknown';
}

module.exports = { checkIpRateLimit, extractIp };
