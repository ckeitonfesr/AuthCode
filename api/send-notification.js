const crypto        = require('crypto');
const supabaseAdmin = require('./_supabase');
const { extractIp, checkIpRateLimit } = require('./_rate-limit');
const STATUS_MESSAGES = {
  'Em preparo':           { title: 'Pedido em preparo',   body: 'Estamos preparando seu pedido.' },
  'Saiu para entrega':    { title: 'Saiu para entrega',   body: 'Seu pedido está a caminho.' },
  'Entregue':             { title: 'Pedido entregue',     body: 'Seu pedido foi entregue. Bom proveito!' },
  'Cancelado':            { title: 'Pedido cancelado',    body: 'Seu pedido foi cancelado. Entre em contato se precisar de ajuda.' },
  'Aguardando pagamento': { title: 'Pedido recebido',     body: 'Aguardando confirmação do pagamento.' },
  'Em andamento':         { title: 'Pedido confirmado',   body: 'Seu pedido foi confirmado e está sendo processado.' },
};
module.exports = async function handler(req, res) {
  try {
  if (req.method !== 'POST') return res.status(405).end();
  const webhookSecret = process.env.WEBHOOK_SECRET;
  const authHeader    = req.headers['x-webhook-secret'];
  const secretValid   = webhookSecret && authHeader &&
    authHeader.length === webhookSecret.length &&
    crypto.timingSafeEqual(Buffer.from(authHeader), Buffer.from(webhookSecret));
  if (!secretValid) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const ip = extractIp(req);
  const rl = checkIpRateLimit(ip, 60); 
  if (!rl.allowed) return res.status(429).json({ error: 'Too many requests' });
  const { record, old_record } = req.body ?? {};
  if (!record) return res.status(400).json({ error: 'No record' });
  const newStatus = record.status;
  const oldStatus = old_record?.status;
  if (newStatus === oldStatus) return res.status(200).json({ skipped: true });
  const message = STATUS_MESSAGES[newStatus];
  if (!message) return res.status(200).json({ skipped: 'unknown status' });
  const { data: profile, error: profileErr } = await supabaseAdmin
    .from('profiles')
    .select('push_token')
    .eq('id', record.user_id)
    .single();
  if (profileErr || !profile?.push_token) {
    return res.status(200).json({ skipped: 'no push token' });
  }
  const pushToken = profile.push_token;
  const payload = {
    to: pushToken,
    channelId: 'orders',
    title: message.title,
    body: message.body,
    data: { orderId: record.id, status: newStatus },
    sound: 'default',
    priority: 'high',
  };
  const expoRes = await fetch('https://exp.host/--/api/v2/push/send', {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });
  if (!expoRes.ok) {
    const err = await expoRes.text();
    console.error('[send-notification] Expo error:', err);
    return res.status(500).json({ error: 'Failed to send push' });
  }
  const result = await expoRes.json();
  return res.status(200).json({ ok: true, result });
  } catch (err) {
    console.error('[send-notification] erro:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};
