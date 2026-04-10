const { supabaseAdmin, requireUser } = require('./_auth');
const cors = require('./_cors');

module.exports = async function handler(req, res) {
  if (cors(req, res)) return;
  if (req.method !== 'GET') return res.status(405).end();

  const user = await requireUser(req, res);
  if (!user) return;

  const { data } = await supabaseAdmin
    .from('profiles').select('name, full_name, username, phone')
    .eq('id', user.id).single();

  return res.status(200).json(data || {});
};
