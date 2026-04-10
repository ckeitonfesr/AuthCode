const { supabaseAdmin, requireUser } = require('./_auth');
const cors = require('./_cors');

const MAX_ADDRESSES = 3;

function sanitize(s) { return (s || '').trim().slice(0, 200); }

module.exports = async function handler(req, res) {
  if (cors(req, res)) return;

  const user = await requireUser(req, res);
  if (!user) return;

  if (req.method === 'GET') {
    const { data, error } = await supabaseAdmin
      .from('addresses').select('*').eq('user_id', user.id)
      .order('is_default', { ascending: false });
    if (error) return res.status(500).json({ error: 'Erro ao buscar endereços.' });
    return res.status(200).json(data || []);
  }

  if (req.method === 'POST') {
    const { street, number, complement, neighborhood, city } = req.body || {};
    if (!street || !number) return res.status(400).json({ error: 'Rua e número obrigatórios.' });

    const { count } = await supabaseAdmin
      .from('addresses').select('*', { count: 'exact', head: true }).eq('user_id', user.id);
    if ((count || 0) >= MAX_ADDRESSES) return res.status(400).json({ error: 'Máximo de 3 endereços.' });

    const isDefault = (count || 0) === 0;
    const { data, error } = await supabaseAdmin.from('addresses').insert({
      user_id: user.id,
      street: sanitize(street), number: sanitize(number),
      complement: sanitize(complement), neighborhood: sanitize(neighborhood),
      city: sanitize(city), is_default: isDefault,
    }).select().single();
    if (error) return res.status(500).json({ error: 'Erro ao salvar endereço.' });
    return res.status(200).json(data);
  }

  if (req.method === 'PATCH') {
    const { id, setDefault, street, number, complement, neighborhood, city } = req.body || {};
    if (!id) return res.status(400).json({ error: 'id obrigatório.' });

    // verificar que o endereço pertence ao usuário
    const { data: existing } = await supabaseAdmin
      .from('addresses').select('id').eq('id', id).eq('user_id', user.id).single();
    if (!existing) return res.status(404).json({ error: 'Endereço não encontrado.' });

    if (setDefault) {
      await supabaseAdmin.from('addresses').update({ is_default: false }).eq('user_id', user.id);
      await supabaseAdmin.from('addresses').update({ is_default: true }).eq('id', id);
      return res.status(200).json({ ok: true });
    }

    const { error } = await supabaseAdmin.from('addresses').update({
      street: sanitize(street), number: sanitize(number),
      complement: sanitize(complement), neighborhood: sanitize(neighborhood),
      city: sanitize(city),
    }).eq('id', id);
    if (error) return res.status(500).json({ error: 'Erro ao atualizar endereço.' });
    return res.status(200).json({ ok: true });
  }

  if (req.method === 'DELETE') {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: 'id obrigatório.' });

    const { data: existing } = await supabaseAdmin
      .from('addresses').select('id, is_default').eq('id', id).eq('user_id', user.id).single();
    if (!existing) return res.status(404).json({ error: 'Endereço não encontrado.' });

    await supabaseAdmin.from('addresses').delete().eq('id', id);

    if (existing.is_default) {
      const { data: remaining } = await supabaseAdmin
        .from('addresses').select('id').eq('user_id', user.id).limit(1);
      if (remaining && remaining.length > 0)
        await supabaseAdmin.from('addresses').update({ is_default: true }).eq('id', remaining[0].id);
    }
    return res.status(200).json({ ok: true });
  }

  res.status(405).end();
};
