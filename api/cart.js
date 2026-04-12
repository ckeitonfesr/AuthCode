const { supabaseAdmin, requireUser } = require('./_auth');
const cors = require('./_cors');
const { checkIpRateLimit, extractIp } = require('./_rate-limit');
const { checkRateLimit } = require('./_rate-limit-db');
const { isUuid, bodySize } = require('./_validate');

const MAX_QTY   = 10;
const MAX_ITEMS = 20;
const MAX_BODY  = 512; // bytes — cart body: productId(36) + quantity(2) + json overhead
const IP_RATE        = 120;  // req/min por IP (anti-flood/scanner, memória apenas)
const CART_RATE      = 120;  // req/min por usuário autenticado
const CART_RATE_HOUR = 500;  // req/hora por usuário autenticado

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
    if (bodySize(req) > MAX_BODY) return res.status(413).json({ error: 'Payload muito grande.' });
    const { productId, quantity = 1 } = req.body || {};
    if (!isUuid(productId)) return res.status(400).json({ error: 'productId inválido.' });
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
    if (bodySize(req) > MAX_BODY) return res.status(413).json({ error: 'Payload muito grande.' });
    const { productId, quantity } = req.body || {};
    if (!isUuid(productId)) return res.status(400).json({ error: 'productId inválido.' });
    if (!Number.isInteger(quantity) || quantity < 1 || quantity > MAX_QTY)
      return res.status(400).json({ error: 'Quantidade inválida.' });
    const { error } = await supabaseAdmin.from('cart_items').update({ quantity })
      .eq('user_id', user.id).eq('product_id', productId);
    if (error) return res.status(500).json({ error: 'Erro ao atualizar carrinho.' });
    return res.status(200).json({ ok: true });
  }

  if (req.method === 'DELETE') {
    const { productId } = req.query;
    if (productId && !isUuid(productId)) return res.status(400).json({ error: 'productId inválido.' });
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
    if (bodySize(req) > MAX_BODY) return res.status(413).json({ error: 'Payload muito grande.' });
    const { productId } = req.body || {};
    if (!isUuid(productId)) return res.status(400).json({ error: 'productId inválido.' });
    const { error } = await supabaseAdmin
      .from('favorites').insert({ user_id: user.id, product_id: productId });
    if (error && error.code !== '23505') return res.status(500).json({ error: 'Erro ao adicionar favorito.' });
    return res.status(200).json({ ok: true });
  }

  if (req.method === 'DELETE') {
    const { productId } = req.query;
    if (!isUuid(productId)) return res.status(400).json({ error: 'productId inválido.' });
    const { error } = await supabaseAdmin
      .from('favorites').delete().eq('user_id', user.id).eq('product_id', productId);
    if (error) return res.status(500).json({ error: 'Erro ao remover favorito.' });
    return res.status(200).json({ ok: true });
  }

  res.status(405).end();
}

module.exports = async function handler(req, res) {
  if (cors(req, res)) return;

  // Rejeita bodies grandes antes de qualquer processamento
  if (['POST', 'PATCH'].includes(req.method) && bodySize(req) > MAX_BODY)
    return res.status(413).json({ error: 'Payload muito grande.' });

  // 1) IP em memória: apenas anti-flood (não vai pro DB, não contamina entre usuários/testes)
  const ip = extractIp(req);
  const rlIp = checkIpRateLimit(ip, IP_RATE);
  if (!rlIp.allowed) {
    return res.status(429).json({ error: `Muitas requisições. Tente novamente em ${rlIp.retryAfterSec}s.` });
  }

  // 2) Auth: valida sessão
  const user = await requireUser(req, res);
  if (!user) return;

  // 3) User: limite persistente por usuário no DB
  const [rlUsrDb, rlUsrHour] = await Promise.all([
    checkRateLimit(`user:${user.id}:cart`, CART_RATE),
    checkRateLimit(`user:${user.id}:cart:h`, CART_RATE_HOUR, { windowMs: 3_600_000 }),
  ]);
  const rlUsr = !rlUsrDb.allowed ? rlUsrDb : rlUsrHour;
  if (!rlUsr.allowed) {
    return res.status(429).json({ error: `Muitas requisições. Tente novamente em ${rlUsr.retryAfterSec}s.` });
  }

  const { r } = req.query;
  if (r === 'favorites') return handleFavorites(req, res, user);
  return handleCart(req, res, user);
};
