const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const WINDOW_MS = 60 * 1000; 

async function checkRateLimit(key, limit) {
  const now      = Date.now();
  const windowId = Math.floor(now / WINDOW_MS); 
  const dbKey    = `${key}:${windowId}`;
  const expiresAt = new Date(now + WINDOW_MS).toISOString();

  try {
    
    const { data, error } = await supabase.rpc('rate_limit_increment', {
      p_key:        dbKey,
      p_limit:      limit,
      p_expires_at: expiresAt,
    });

    if (error) {
      
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
    return { allowed: true, retryAfterSec: 0 }; 
  }
}

module.exports = { checkRateLimit };
