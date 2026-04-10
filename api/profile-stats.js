const { supabaseAdmin, requireUser } = require('./_auth');
const cors = require('./_cors');

module.exports = async function handler(req, res) {
  if (cors(req, res)) return;
  if (req.method !== 'GET') return res.status(405).end();

  const user = await requireUser(req, res);
  if (!user) return;

  const [ordersRes, favsRes] = await Promise.all([
    supabaseAdmin.from('orders').select('*', { count: 'exact', head: true }).eq('user_id', user.id),
    supabaseAdmin.from('favorites').select('*', { count: 'exact', head: true }).eq('user_id', user.id),
  ]);

  return res.status(200).json({
    orderCount:    ordersRes.count || 0,
    favoriteCount: favsRes.count   || 0,
  });
};
