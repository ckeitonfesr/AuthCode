const { supabaseAdmin, requireUser } = require('./_auth');
const cors = require('./_cors');

module.exports = async function handler(req, res) {
  if (cors(req, res)) return;

  const user = await requireUser(req, res);
  if (!user) return;

  if (req.method === 'GET') {
    const { data, error } = await supabaseAdmin
      .from('favorites').select('product_id').eq('user_id', user.id);
    if (error) return res.status(500).json({ error: 'Erro ao buscar favoritos.' });
    return res.status(200).json((data || []).map(f => f.product_id));
  }

  if (req.method === 'POST') {
    const { productId } = req.body || {};
    if (!productId) return res.status(400).json({ error: 'productId obrigatório.' });
    const { error } = await supabaseAdmin
      .from('favorites').insert({ user_id: user.id, product_id: productId });
    if (error && error.code !== '23505') return res.status(500).json({ error: 'Erro ao adicionar favorito.' });
    return res.status(200).json({ ok: true });
  }

  if (req.method === 'DELETE') {
    const { productId } = req.query;
    if (!productId) return res.status(400).json({ error: 'productId obrigatório.' });
    const { error } = await supabaseAdmin
      .from('favorites').delete().eq('user_id', user.id).eq('product_id', productId);
    if (error) return res.status(500).json({ error: 'Erro ao remover favorito.' });
    return res.status(200).json({ ok: true });
  }

  res.status(405).end();
};
