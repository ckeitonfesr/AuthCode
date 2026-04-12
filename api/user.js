const { supabaseAdmin, requireUser } = require('./_auth');
const cors = require('./_cors');
const { checkIpRateLimit, extractIp } = require('./_rate-limit');
const { checkRateLimit } = require('./_rate-limit-db');
const { bodySize } = require('./_validate');

// IP: proteção contra flood/scanner sem auth (limite alto — não penaliza NAT)
const IP_RATE      = 120;  // req/min por IP (anti-flood/scanner, memória apenas)
// User: limite real por usuário autenticado (mais justo e preciso)
const USER_RATE      = 120; // req/min por usuário
const USER_RATE_HOUR = 500; // req/hora por usuário

const MAX_ADDRESSES = 3;
const MAX_BODY_ADDR = 2048; // bytes

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

async function handleOrders(req, res, user) {
  if (req.method !== 'GET') return res.status(405).end();
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
}

async function handleProfile(req, res, user) {
  if (req.method !== 'GET') return res.status(405).end();
  const { data } = await supabaseAdmin
    .from('profiles').select('name, full_name, username, phone')
    .eq('id', user.id).single();
  return res.status(200).json(data || {});
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
