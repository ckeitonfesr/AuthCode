const { createClient } = require('@supabase/supabase-js');

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

async function requireUser(req, res) {
  const userJwt = req.headers['x-user-token'];
  if (!userJwt) {
    res.status(401).json({ error: 'Autenticação necessária.' });
    return null;
  }
  const { data: { user }, error } = await supabaseAdmin.auth.getUser(userJwt);
  if (error || !user) {
    res.status(401).json({ error: 'Sessão inválida. Faça login novamente.' });
    return null;
  }
  return user;
}

module.exports = { supabaseAdmin, requireUser };
