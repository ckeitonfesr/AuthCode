const { supabaseAdmin, requireUser } = require('./_auth');
const cors = require('./_cors');
const { checkIpRateLimit, extractIp } = require('./_rate-limit');
const { checkRateLimit } = require('./_rate-limit-db');
const { bodySize } = require('./_validate');
const { analyzeData } = require('./_ai-analyze');
const IP_RATE      = 120;  
const USER_RATE      = 120; 
const USER_RATE_HOUR = 500; 
const MAX_ADDRESSES = 3;
const MAX_BODY_ADDR = 2048; 
function sanitize(s, max = 200) {
  return (s || '').trim()
    .replace(/[<>"'`]/g, '')  // [S9] strip HTML/JS injection chars
    .slice(0, max);
}
async function handleAddresses(req, res, user) {
  if (req.method === 'GET') {
    const { data, error } = await supabaseAdmin
      .from('addresses').select('*').eq('user_id', user.id)
      .order('is_default', { ascending: false });
    if (error) return res.status(500).json({ error: 'Erro ao buscar endereços.' });
    return res.status(200).json(data || []);
  }
  if (req.method === 'POST') {
    if (bodySize(req) > MAX_BODY_ADDR) return res.status(413).json({ error: 'Payload muito grande.' });
    const { street, number, complement, neighborhood, city } = req.body || {};
    if (!street || !number) return res.status(400).json({ error: 'Rua e número obrigatórios.' });
    const { count } = await supabaseAdmin
      .from('addresses').select('*', { count: 'exact', head: true }).eq('user_id', user.id);
    if ((count || 0) >= MAX_ADDRESSES) return res.status(400).json({ error: 'Máximo de 3 endereços.' });
    const isDefault = (count || 0) === 0;
    const { data, error } = await supabaseAdmin.from('addresses').insert({
      user_id: user.id,
      street:       sanitize(street, 150),
      number:       sanitize(number, 20),
      complement:   sanitize(complement, 100),
      neighborhood: sanitize(neighborhood, 100),
      city:         sanitize(city, 100),
      is_default: isDefault,
    }).select().single();
    if (error) return res.status(500).json({ error: 'Erro ao salvar endereço.' });
    // Análise silenciosa do endereço — fire-and-forget
    analyzeData({
      userId: user.id,
      trigger: 'address_create',
      fields: {
        street:       sanitize(street, 150),
        number:       sanitize(number, 20),
        neighborhood: sanitize(neighborhood, 100),
        city:         sanitize(city, 100),
      },
    }).catch(() => {});
    return res.status(200).json(data);
  }
  if (req.method === 'PATCH') {
    if (bodySize(req) > MAX_BODY_ADDR) return res.status(413).json({ error: 'Payload muito grande.' });
    const { id, setDefault, street, number, complement, neighborhood, city } = req.body || {};
    if (!id || typeof id !== 'string' || id.length > 36) return res.status(400).json({ error: 'id obrigatório.' });
    const { data: existing } = await supabaseAdmin
      .from('addresses').select('id').eq('id', id).eq('user_id', user.id).single();
    if (!existing) return res.status(404).json({ error: 'Endereço não encontrado.' });
    if (setDefault) {
      await supabaseAdmin.from('addresses').update({ is_default: false }).eq('user_id', user.id);
      await supabaseAdmin.from('addresses').update({ is_default: true }).eq('id', id);
      return res.status(200).json({ ok: true });
    }
    const { error } = await supabaseAdmin.from('addresses').update({
      street:       sanitize(street, 150),
      number:       sanitize(number, 20),
      complement:   sanitize(complement, 100),
      neighborhood: sanitize(neighborhood, 100),
      city:         sanitize(city, 100),
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
}
const ORDERS_PAGE_SIZE = 20;
async function handleOrders(req, res, user) {
  if (req.method !== 'GET') return res.status(405).end();
  const { id } = req.query;
  if (id) {
    const { data, error } = await supabaseAdmin
      .from('orders').select('*, order_items(*, products(image_url))')
      .eq('id', id).eq('user_id', user.id).single();
    if (error || !data) return res.status(404).json({ error: 'Pedido não encontrado.' });
    return res.status(200).json(data);
  }
  const page  = Math.max(0, parseInt(req.query.page  || '0', 10));
  const limit = Math.min(50, Math.max(1, parseInt(req.query.limit || String(ORDERS_PAGE_SIZE), 10)));
  const from  = page * limit;
  const { data, error, count } = await supabaseAdmin
    .from('orders').select('*, order_items(*, products(image_url))', { count: 'exact' })
    .eq('user_id', user.id)
    .order('created_at', { ascending: false })
    .range(from, from + limit - 1);
  if (error) return res.status(500).json({ error: 'Erro ao buscar pedidos.' });
  return res.status(200).json({ data: data || [], total: count ?? 0, page, limit });
}
async function handleProfile(req, res, user) {
  if (req.method === 'GET') {
    const { data } = await supabaseAdmin
      .from('profiles').select('name, full_name, username, phone')
      .eq('id', user.id).single();
    return res.status(200).json(data || {});
  }
  if (req.method === 'PATCH') {
    if (bodySize(req) > MAX_BODY_ADDR) return res.status(413).json({ error: 'Payload muito grande.' });
    const { fullName, phone } = req.body || {};
    if (fullName !== undefined) {
      if (
        typeof fullName !== 'string' ||
        fullName.trim().length < 2 ||
        fullName.trim().length > 60 ||
        !/^[A-Za-zÀ-ÿ\s]+$/.test(fullName.trim()) ||
        fullName.trim().split(/\s+/).some(w => w.length > 15)
      ) return res.status(400).json({ error: 'Nome inválido. Use apenas letras.' });
    }
    if (phone !== undefined) {
      const phoneDigits = typeof phone === 'string' ? phone.replace(/\D/g, '') : '';
      if (phoneDigits.length !== 11 || phoneDigits[2] !== '9')
        return res.status(400).json({ error: 'Telefone inválido. Use um celular brasileiro (ex: 11 91234-5678).' });
    }
    if (fullName === undefined && phone === undefined)
      return res.status(400).json({ error: 'Nada para atualizar.' });
    // Busca valores atuais para comparar e checar cooldown
    const { data: current } = await supabaseAdmin
      .from('profiles').select('full_name, phone, profile_edited_at').eq('id', user.id).single();
    const newFullName = fullName !== undefined ? sanitize(fullName, 200) : null;
    const newPhone    = phone    !== undefined ? sanitize(phone, 20)    : null;
    const nameChanged  = newFullName !== null && newFullName !== (current?.full_name || '');
    const phoneChanged = newPhone    !== null && newPhone    !== (current?.phone    || '');
    // Nada mudou — retorna ok sem contar como edição
    if (!nameChanged && !phoneChanged) return res.status(200).json({ ok: true });
    // Checa cooldown de 24h — atômico: só atualiza se o cooldown passou
    const cooldownMs  = 24 * 60 * 60 * 1000;
    const cooldownAgo = new Date(Date.now() - cooldownMs).toISOString();
    const updates = {};
    if (nameChanged) {
      updates.full_name = newFullName;
      updates.name      = sanitize(fullName.trim().split(' ')[0], 100);
    }
    if (phoneChanged) updates.phone = newPhone;
    updates.profile_edited_at = new Date().toISOString();
    const { data: updated, error } = await supabaseAdmin
      .from('profiles')
      .update(updates)
      .eq('id', user.id)
      .or(`profile_edited_at.is.null,profile_edited_at.lt.${cooldownAgo}`)
      .select('id');
    if (error) return res.status(500).json({ error: 'Erro ao atualizar perfil.' });
    if (!updated || updated.length === 0)
      return res.status(429).json({ error: 'Tente novamente em 24h.' });
    // Análise silenciosa dos campos alterados — fire-and-forget
    analyzeData({
      userId: user.id,
      trigger: 'profile_edit',
      fields: {
        ...(nameChanged  ? { fullName: newFullName } : {}),
        ...(phoneChanged ? { phone: newPhone }       : {}),
      },
    }).catch(() => {});
    return res.status(200).json({ ok: true });
  }
  return res.status(405).end();
}
async function handleProfileStats(req, res, user) {
  if (req.method !== 'GET') return res.status(405).end();
  const [ordersRes, favsRes] = await Promise.all([
    supabaseAdmin.from('orders').select('*', { count: 'exact', head: true }).eq('user_id', user.id),
    supabaseAdmin.from('favorites').select('*', { count: 'exact', head: true }).eq('user_id', user.id),
  ]);
  return res.status(200).json({
    orderCount:    ordersRes.count || 0,
    favoriteCount: favsRes.count   || 0,
  });
}
module.exports = async function handler(req, res) {
  if (cors(req, res)) return;
  // Rejeita bodies grandes antes de qualquer processamento
  if (['POST', 'PATCH'].includes(req.method) && bodySize(req) > MAX_BODY_ADDR)
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
  // 3) User: limite persistente por usuário no DB (não afeta outros usuários do mesmo IP)
  const [rlUsrDb, rlUsrHour] = await Promise.all([
    checkRateLimit(`user:${user.id}:user`, USER_RATE),
    checkRateLimit(`user:${user.id}:user:h`, USER_RATE_HOUR, { windowMs: 3_600_000 }),
  ]);
  const rlUsr = !rlUsrDb.allowed ? rlUsrDb : rlUsrHour;
  if (!rlUsr.allowed) {
    return res.status(429).json({ error: `Muitas requisições. Tente novamente em ${rlUsr.retryAfterSec}s.` });
  }
  const { r } = req.query;
  if (r === 'addresses') return handleAddresses(req, res, user);
  if (r === 'orders')    return handleOrders(req, res, user);
  if (r === 'stats')     return handleProfileStats(req, res, user);
  return handleProfile(req, res, user);
};
