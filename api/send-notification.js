const supabaseAdmin = require('./_supabase');
const { extractIp, checkIpRateLimit } = require('./_rate-limit');

// Mensagens por status — espelhadas do app
const STATUS_MESSAGES = {
  'Em preparo':           { title: 'Pedido em preparo 🍳',   body: 'Estamos preparando seu pedido com carinho!' },
  'Saiu para entrega':    { title: 'Saiu para entrega! 🛵',  body: 'Seu pedido está a caminho. Fique de olho!' },
  'Entregue':             { title: 'Pedido entregue! ✅',     body: 'Bom proveito! Obrigado por pedir na 24h Conveniência.' },
  'Cancelado':            { title: 'Pedido cancelado ❌',     body: 'Seu pedido foi cancelado. Entre em contato se precisar de ajuda.' },
  'Aguardando pagamento': { title: 'Pedido recebido! 🎉',    body: 'Aguardando confirmação do pagamento.' },
  'Em andamento':         { title: 'Pedido confirmado! 🎉',  body: 'Seu pedido foi confirmado e está sendo processado.' },
};

module.exports = async function handler(req, res) {
  // Só aceita chamadas do Supabase Webhook ou do painel admin via POST
  if (req.method !== 'POST') return res.status(405).end();

  // Autenticação do webhook via secret compartilhado
  const webhookSecret = process.env.WEBHOOK_SECRET;
  if (webhookSecret) {
    const authHeader = req.headers['x-webhook-secret'];
    if (authHeader !== webhookSecret) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
  }

  // Rate limit por IP (proteção extra)
  const ip = extractIp(req);
  const { blocked } = checkIpRateLimit(ip, 60); // 60 por minuto
  if (blocked) return res.status(429).json({ error: 'Too many requests' });

  // Supabase Database Webhook envia o payload do tipo:
  // { type: 'UPDATE', table: 'orders', record: {...}, old_record: {...} }
  const { record, old_record } = req.body ?? {};

  if (!record) return res.status(400).json({ error: 'No record' });

  const newStatus = record.status;
  const oldStatus = old_record?.status;

  // Só notifica se o status mudou
  if (newStatus === oldStatus) return res.status(200).json({ skipped: true });

  const message = STATUS_MESSAGES[newStatus];
  if (!message) return res.status(200).json({ skipped: 'unknown status' });

  // Busca o push_token do usuário dono do pedido
  const { data: profile, error: profileErr } = await supabaseAdmin
    .from('profiles')
    .select('push_token')
    .eq('id', record.user_id)
    .single();

  if (profileErr || !profile?.push_token) {
    return res.status(200).json({ skipped: 'no push token' });
  }

  const pushToken = profile.push_token;

  // Envia via Expo Push API
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
};
