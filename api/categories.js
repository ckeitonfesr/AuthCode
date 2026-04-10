const supabase = require('./_supabase');
const cors     = require('./_cors');

module.exports = async function handler(req, res) {
  if (cors(req, res)) return;
  if (req.method !== 'GET') return res.status(405).end();

  const { data, error } = await supabase
    .from('categories').select('name').eq('active', true).order('order_index');
  if (error) return res.status(500).json({ error: 'Erro ao buscar categorias.' });
  return res.status(200).json((data || []).map(c => c.name));
};
