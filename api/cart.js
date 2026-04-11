const { supabaseAdmin, requireUser } = require('./_auth');
const cors = require('./_cors');

const MAX_QTY = 10;
const MAX_ITEMS = 20;

async function handleCart(req, res, user) {
  if (req.method === 'GET') {
    const { data, error } = await supabaseAdmin
      .from('cart_items')
      .select('quantity, products(id, name, price, image_url)')
      .eq('user_id', user.id);
    if (error) return res.status(500).json({ error: 'Erro ao buscar carrinho.' });
    return res.status(200).json((data || [])
      .filter(i => i.products)
      .map(i => ({
        id: i.products.id, name: i.products.name,
        price: i.products.price, image: i.products.image_url,
        quantity: i.quantity,
      })));
  }

  if (req.method === 'POST') {
    const { productId, quantity = 1 } = req.body || {};
    if (!productId) return res.status(400).json({ error: 'productId obrigatório.' });
    if (!Number.isInteger(quantity) || quantity < 1 || quantity > MAX_QTY)
      return res.status(400).json({ error: 'Quantidade inválida.' });
    const { data: product } = await supabaseAdmin
      .from('products').select('id, active').eq('id', productId).single();
    if (!product || !product.active) return res.status(404).json({ error: 'Produto não encontrado.' });
    const { count } = await supabaseAdmin
      .from('cart_items').select('*', { count: 'exact', head: true }).eq('user_id', user.id);
    if ((count || 0) >= MAX_ITEMS) return res.status(400).json({ error: 'Carrinho cheio.' });
    const { error } = await supabaseAdmin.from('cart_items')
      .upsert({ user_id: user.id, product_id: productId, quantity }, { onConflict: 'user_id,product_id' });
    if (error) return res.status(500).json({ error: 'Erro ao atualizar carrinho.' });
    return res.status(200).json({ ok: true });
  }

  if (req.method === 'PATCH') {
    const { productId, quantity } = req.body || {};
    if (!productId) return res.status(400).json({ error: 'productId obrigatório.' });
    if (!Number.isInteger(quantity) || quantity < 1 || quantity > MAX_QTY)
      return res.status(400).json({ error: 'Quantidade inválida.' });
    const { error } = await supabaseAdmin.from('cart_items').update({ quantity })
      .eq('user_id', user.id).eq('product_id', productId);
    if (error) return res.status(500).json({ error: 'Erro ao atualizar carrinho.' });
    return res.status(200).json({ ok: true });
  }

  if (req.method === 'DELETE') {
    const { productId } = req.query;
    let query = supabaseAdmin.from('cart_items').delete().eq('user_id', user.id);
    if (productId) query = query.eq('product_id', productId);
    const { error } = await query;
    if (error) return res.status(500).json({ error: 'Erro ao remover item.' });
    return res.status(200).json({ ok: true });
  }

  res.status(405).end();
}

async function handleFavorites(req, res, user) {
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
}

module.exports = async function handler(req, res) {
  if (cors(req, res)) return;
  const user = await requireUser(req, res);
  if (!user) return;

  const { r } = req.query;
  if (r === 'favorites') return handleFavorites(req, res, user);
  return handleCart(req, res, user);
};
