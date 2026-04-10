const { supabaseAdmin, requireUser } = require('./_auth');
const cors = require('./_cors');

module.exports = async function handler(req, res) {
  if (cors(req, res)) return;
  if (req.method !== 'GET') return res.status(405).end();

  const user = await requireUser(req, res);
  if (!user) return;

  const { id } = req.query;

  if (id) {
    const { data, error } = await supabaseAdmin
      .from('orders').select('*, order_items(*)')
      .eq('id', id).eq('user_id', user.id).single();
    if (error || !data) return res.status(404).json({ error: 'Pedido não encontrado.' });
    return res.status(200).json(data);
  }

  const { data, error } = await supabaseAdmin
    .from('orders').select('*, order_items(*)')
    .eq('user_id', user.id).order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: 'Erro ao buscar pedidos.' });
  return res.status(200).json(data || []);
};
