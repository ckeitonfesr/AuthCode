// api/_supabase.js
// Cliente Supabase compartilhado entre as rotas.
// Usa a Service Role Key para operar sem restrições de RLS no servidor.

const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY // pode ser a anon key com RLS desabilitado
);

module.exports = supabase;
