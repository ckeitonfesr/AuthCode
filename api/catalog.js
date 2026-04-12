const supabase = require('./_supabase');
const cors     = require('./_cors');
const { checkIpRateLimit, extractIp } = require('./_rate-limit');
const { isUuid } = require('./_validate');

const CATALOG_RATE = 60; // req/min por IP (público — memória apenas)

function mapProduct(p) {
  return {
    id: p.id, name: p.name, description: p.description,
    price: p.price, originalPrice: p.original_price,
    category: p.category, image: p.image_url,
    rating: p.rating || 0, reviewCount: p.review_count || 0,
    soldCount: p.sold_count || 0,
  };
}

async function handleProducts(req, res) {
  const { id, ids, category } = req.query;

  if (id) {
    if (!isUuid(id)) return res.status(400).json({ error: 'id inválido.' });
    // [H2] Filtrar active=true para não expor produtos arquivados por ID direto
    const { data, error } = await supabase.from('products').select('*').eq('id', id).eq('active', true).single();
    if (error || !data) return res.status(404).json({ error: 'Produto não encontrado.' });
    return res.status(200).json(mapProduct(data));
  }

  if (ids) {
    // [H2] Mesma proteção na busca em lote — valida cada UUID
    const idList = ids.split(',').slice(0, 50).filter(isUuid);
    if (idList.length === 0) return res.status(400).json({ error: 'ids inválidos.' });
    const { data, error } = await supabase.from('products').select('*').in('id', idList).eq('active', true);
    if (error) return res.status(500).json({ error: 'Erro ao buscar produtos.' });
    return res.status(200).json((data || []).map(mapProduct));
  }

  let query = supabase.from('products').select('*').eq('active', true).order('sold_count', { ascending: false });
  if (category) {
    if (typeof category !== 'string' || category.length > 60)
      return res.status(400).json({ error: 'category inválida.' });
    query = query.eq('category', category);
  }
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: 'Erro ao buscar produtos.' });
  return res.status(200).json((data || []).map(mapProduct));
}

async function handleCategories(req, res) {
  const { data, error } = await supabase
    .from('categories').select('name').eq('active', true).order('order_index');
  if (error) return res.status(500).json({ error: 'Erro ao buscar categorias.' });
  return res.status(200).json((data || []).map(c => c.name));
}

module.exports = async function handler(req, res) {
  if (cors(req, res)) return;
  if (req.method !== 'GET') return res.status(405).end();

  const ip = extractIp(req);
  const rl = checkIpRateLimit(ip, CATALOG_RATE);
  if (!rl.allowed)
    return res.status(429).json({ error: `Muitas requisições. Tente novamente em ${rl.retryAfterSec}s.` });

  const { r } = req.query;
  if (r === 'categories') return handleCategories(req, res);
  return handleProducts(req, res);
};
