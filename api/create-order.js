const { createClient } = require('@supabase/supabase-js');
const supabase          = require('./_supabase');
const { validateToken } = require('./_token');
const { checkIpRateLimit, extractIp } = require('./_rate-limit');

const ORDER_RATE_LIMIT = 5; // max 5 pedidos por IP por minuto

// Cliente com service role para validar o JWT do usuário
const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const ip = extractIp(req);

  const rl = checkIpRateLimit(ip, ORDER_RATE_LIMIT);
  if (!rl.allowed) {
    return res.status(429).json({
      error: `Muitas requisições. Tente novamente em ${rl.retryAfterSec}s.`,
    });
  }

  // 1 — Valida o token de API (request-token flow)
  const token    = req.headers['x-request-token'];
  const deviceId = req.headers['x-device-id'];
  const isValid  = await validateToken(token, deviceId, req);
  if (!isValid) return res.status(401).json({ error: 'Token inválido ou expirado.' });

  // 2 — Valida o JWT do usuário Supabase (prova identidade do usuário autenticado)
  const userJwt = req.headers['x-user-token'];
  if (!userJwt) return res.status(401).json({ error: 'Autenticação de usuário necessária.' });

  const { data: { user }, error: authErr } = await supabaseAdmin.auth.getUser(userJwt);
  if (authErr || !user) {
    return res.status(401).json({ error: 'Sessão inválida. Faça login novamente.' });
  }

  // 3 — Valida corpo da requisição
  const { items, paymentMethod, address } = req.body ?? {};

  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Carrinho vazio.' });
  }
  if (!paymentMethod || !['pix', 'cash'].includes(paymentMethod)) {
    return res.status(400).json({ error: 'Forma de pagamento inválida.' });
  }
  if (!address || typeof address !== 'string' || address.trim().length < 5) {
    return res.status(400).json({ error: 'Endereço inválido.' });
  }

  // Valida estrutura dos itens antes de consultar o banco
  for (const item of items) {
    if (!item.productId || typeof item.productId !== 'string') {
      return res.status(400).json({ error: 'Item inválido: productId ausente.' });
    }
    if (!Number.isInteger(item.quantity) || item.quantity < 1 || item.quantity > 99) {
      return res.status(400).json({ error: 'Quantidade inválida (1–99).' });
    }
  }

  // 4 — Busca preços reais do banco (nunca confia nos preços do cliente)
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

  // 5 — Calcula total no servidor com preços do banco
  const total = items.reduce((sum, item) => {
    return sum + productMap[item.productId].price * item.quantity;
  }, 0);
  const totalRounded = Math.round(total * 100) / 100;

  // Status inicial depende da forma de pagamento
  const initialStatus = paymentMethod === 'pix' ? 'Aguardando pagamento' : 'Em andamento';

  // 6 — Cria pedido + itens + limpa carrinho em uma única transação (RPC)
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
    total:   totalRounded,
    status:  initialStatus,
  });
};
