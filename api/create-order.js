const { createClient } = require('@supabase/supabase-js');
const supabase          = require('./_supabase');
const { validateToken } = require('./_token');
const { checkIpRateLimit, extractIp } = require('./_rate-limit');
const { checkRateLimit } = require('./_rate-limit-db');
const cors = require('./_cors');

const ORDER_RATE_LIMIT      = 5; 
const ORDER_RATE_LIMIT_USER = 2; 
const MIN_ORDER_VALUE  = 30;  
const DELIVERY_FEE     = 5;   

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

module.exports = async function handler(req, res) {
  if (cors(req, res)) return;
  if (req.method !== 'POST') return res.status(405).end();

  const ip = extractIp(req);

  const [rlDb, rlMem] = await Promise.all([
    checkRateLimit(`ip:${ip}:co`, ORDER_RATE_LIMIT),
    Promise.resolve(checkIpRateLimit(ip, ORDER_RATE_LIMIT)),
  ]);
  const rl = rlDb.allowed ? rlMem : rlDb;
  if (!rl.allowed) {
    return res.status(429).json({
      error: `Muitas requisições. Tente novamente em ${rl.retryAfterSec}s.`,
    });
  }

  
  const token    = req.headers['x-request-token'];
  const deviceId = req.headers['x-device-id'];
  const isValid  = await validateToken(token, deviceId, req);
  if (!isValid) return res.status(401).json({ error: 'Token inválido ou expirado.' });

  
  const userJwt = req.headers['x-user-token'];
  if (!userJwt) return res.status(401).json({ error: 'Autenticação de usuário necessária.' });

  const { data: { user }, error: authErr } = await supabaseAdmin.auth.getUser(userJwt);
  if (authErr || !user) {
    return res.status(401).json({ error: 'Sessão inválida. Faça login novamente.' });
  }

  
  const rlUser = await checkRateLimit(`user:${user.id}:co`, ORDER_RATE_LIMIT_USER);
  if (!rlUser.allowed) {
    return res.status(429).json({
      error: `Muitas requisições. Tente novamente em ${rlUser.retryAfterSec}s.`,
    });
  }

  
  const since = new Date(Date.now() - 30_000).toISOString();
  const { data: recentOrders } = await supabaseAdmin
    .from('orders')
    .select('id, created_at')
    .eq('user_id', user.id)
    .gte('created_at', since)
    .limit(1);

  if (recentOrders && recentOrders.length > 0) {
    return res.status(429).json({
      error: 'Pedido recente detectado. Aguarde 30 segundos antes de tentar novamente.',
    });
  }

  
  const { items, paymentMethod, address } = req.body ?? {};

  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Carrinho vazio.' });
  }
  if (items.length > 20) {
    return res.status(400).json({ error: 'Máximo de 20 produtos por pedido.' });
  }
  if (!paymentMethod || !['pix', 'cash', 'card'].includes(paymentMethod)) {
    return res.status(400).json({ error: 'Forma de pagamento inválida.' });
  }
  if (!address || typeof address !== 'string' || address.trim().length < 5 || address.length > 500) {
    return res.status(400).json({ error: 'Endereço inválido.' });
  }

  
  for (const item of items) {
    if (!item.productId || typeof item.productId !== 'string') {
      return res.status(400).json({ error: 'Item inválido: productId ausente.' });
    }
    if (!Number.isInteger(item.quantity) || item.quantity < 1 || item.quantity > 10) {
      return res.status(400).json({ error: 'Quantidade inválida (1–10 por produto).' });
    }
  }

  
  const productIds = [...new Set(items.map(i => i.productId))];

  const { data: products, error: productsErr } = await supabase
    .from('products')
    .select('id, name, price, active')
    .in('id', productIds);

  if (productsErr || !products) {
    console.error('[create-order] Erro ao buscar produtos:', productsErr?.message);
    return res.status(500).json({ error: 'Erro ao validar produtos.' });
  }

  const productMap = {};
  for (const p of products) {
    if (!p.active) {
      return res.status(400).json({ error: `Produto indisponível: ${p.name}` });
    }
    productMap[p.id] = p;
  }

  for (const item of items) {
    if (!productMap[item.productId]) {
      return res.status(400).json({ error: 'Produto não encontrado.' });
    }
  }

  
  const subtotal = items.reduce((sum, item) => {
    return sum + productMap[item.productId].price * item.quantity;
  }, 0);
  const subtotalRounded = Math.round(subtotal * 100) / 100;

  
  const totalRounded = Math.round((subtotalRounded + DELIVERY_FEE) * 100) / 100;

  
  if (totalRounded < MIN_ORDER_VALUE) {
    return res.status(400).json({
      error: `Pedido mínimo de R$ ${MIN_ORDER_VALUE.toFixed(2)} (com taxa de entrega).`,
    });
  }

  
  const initialStatus = paymentMethod === 'pix' ? 'Aguardando pagamento' : 'Em andamento';

  
  const rpcItems = items.map(item => ({
    product_id: item.productId,
    name:       productMap[item.productId].name,
    quantity:   item.quantity,
    price:      productMap[item.productId].price,
  }));

  const { data: orderId, error: rpcErr } = await supabaseAdmin.rpc('create_order_with_items', {
    p_user_id:        user.id,
    p_status:         initialStatus,
    p_total:          totalRounded,
    p_payment_method: paymentMethod,
    p_address:        address.trim(),
    p_items:          rpcItems,
  });

  if (rpcErr || !orderId) {
    console.error('[create-order] Erro na transação:', rpcErr?.message);
    return res.status(500).json({ error: 'Erro ao criar pedido.' });
  }

  return res.status(200).json({
    success: true,
    orderId,
    subtotal:    subtotalRounded,
    deliveryFee: DELIVERY_FEE,
    total:       totalRounded,
    status:      initialStatus,
  });
};
