const supabase = require('./_supabase');
const cors     = require('./_cors');
const { checkIpRateLimit, extractIp } = require('./_rate-limit');
const { checkRateLimit } = require('./_rate-limit-db');
const { isUuid } = require('./_validate');

async function enrichIp(ip) {
  try {
    const r = await fetch(
      `http://ip-api.com/json/${ip}?fields=country,countryCode,regionName,city,isp,org,as,proxy,hosting,mobile`,
      { signal: AbortSignal.timeout(3000) }
    );
    if (!r.ok) return null;
    const d = await r.json();
    if (d.status === 'fail') return null;
    return {
      country:     d.country     || null,
      country_code:d.countryCode || null,
      region:      d.regionName  || null,
      city:        d.city        || null,
      isp:         d.isp         || null,
      org:         d.org         || null,
      asn:         d.as          || null,
      is_proxy:    d.proxy       || false,
      is_hosting:  d.hosting     || false,
      is_mobile:   d.mobile      || false,
    };
  } catch { return null; }
}

const HONEYPOT_RESPONSES = {
  'env': () =>
    `APP_NAME=24hrs\nAPP_ENV=production\nAPP_KEY=base64:kXz2mN8pQrVwYtLsJhGfDcBaE7uI3oP1\nAPP_DEBUG=false\nAPP_URL=https://24hrs-central.site\n\nDB_CONNECTION=pgsql\nDB_HOST=db.sineixguxvlmatnyvtdw.supabase.co\nDB_PORT=5432\nDB_DATABASE=postgres\nDB_USERNAME=postgres\nDB_PASSWORD=Xk9#mP2$vL5nQr\n\nJWT_SECRET=8f3a1b9e2d7c4f6a0e5b8d2c9f1a4e7b\nSUPABASE_KEY=eyJhbGciOiJIUzI1NiJ9.fake.signature`,
  'wp-login.php': (id) =>
    `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><title>Log In &lsaquo; 24hrs Central &#8212; WordPress</title></head><body class="login"><div id="login"><h1>24hrs Central</h1><form name="loginform" action="/wp-login.php" method="post"><p><label>Usuário<br/><input type="text" name="log" class="input" size="20"/></label></p><p><label>Senha<br/><input type="password" name="pwd" class="input" size="20"/></label></p><p><input type="submit" value="Entrar" class="button button-primary"/></p></form></div><script>!function(){try{var d={tz:Intl.DateTimeFormat().resolvedOptions().timeZone,lang:navigator.language,scr:screen.width+'x'+screen.height,dpr:devicePixelRatio,pl:navigator.platform,cpu:navigator.hardwareConcurrency,mem:navigator.deviceMemory||0,touch:'ontouchstart' in window};fetch('/api/event?_hpfp=1&_id=${(id||'')}',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)}).catch(()=>{})}catch(e){}}();</script></body></html>`,
  'phpMyAdmin': (id) =>
    `<!DOCTYPE html><html><head><title>phpMyAdmin</title></head><body><div id="pmacontainer"><form method="post" action="index.php"><input type="hidden" name="token" value="a3f8c2e1b4d7"/><label>Servidor: <input type="text" name="pma_servername" value="localhost"/></label><br/><label>Usuário: <input type="text" name="pma_username"/></label><br/><label>Senha: <input type="password" name="pma_password"/></label><br/><input type="submit" value="Executar"/></form></div><script>!function(){try{var d={tz:Intl.DateTimeFormat().resolvedOptions().timeZone,lang:navigator.language,scr:screen.width+'x'+screen.height,dpr:devicePixelRatio,pl:navigator.platform,cpu:navigator.hardwareConcurrency,mem:navigator.deviceMemory||0,touch:'ontouchstart' in window};fetch('/api/event?_hpfp=1&_id=${(id||'')}',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)}).catch(()=>{})}catch(e){}}();</script></body></html>`,
  'admin.php': (id) =>
    `<!DOCTYPE html><html><head><title>Painel Admin</title></head><body><form method="post"><input name="user" placeholder="admin"/><input type="password" name="pass"/><button type="submit">Entrar</button></form><script>!function(){try{var d={tz:Intl.DateTimeFormat().resolvedOptions().timeZone,lang:navigator.language,scr:screen.width+'x'+screen.height,dpr:devicePixelRatio,pl:navigator.platform,cpu:navigator.hardwareConcurrency,mem:navigator.deviceMemory||0,touch:'ontouchstart' in window};fetch('/api/event?_hpfp=1&_id=${(id||'')}',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)}).catch(()=>{})}catch(e){}}();</script></body></html>`,
  'config.php': () =>
    `<?php\ndefine('DB_NAME', 'central24hrs_db');\ndefine('DB_USER', 'root');\ndefine('DB_PASSWORD', 'Xk9#mP2$vL5n');\ndefine('DB_HOST', 'localhost');\ndefine('SECRET_KEY', '8f3a1b9e2d7c4f6a');\n?>`,
  'api/admin': () => ({
    success: true,
    data: { users: 142, orders: 891, revenue: 18432.50 },
    token: 'eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwicm9sZSI6ImFkbWluIn0.fake',
  }),
  'api/debug': () => ({
    env: 'production', node: '18.17.0', uptime: 98432,
    db: { host: 'db.sineixguxvlmatnyvtdw.supabase.co', connected: true, queries: 14872 },
    memory: { rss: 48.2, heap: 31.7 },
  }),
};

async function handleHoneypot(req, res) {
  const ip     = extractIp(req);
  const path   = '/' + (req.query._p || 'unknown');
  const method = req.method || 'GET';
  const ua     = (req.headers['user-agent'] || '').slice(0, 512);
  const origin = (req.headers['origin'] || req.headers['referer'] || '').slice(0, 256);
  const safeH  = {};
  for (const h of ['user-agent','accept','origin','referer','x-forwarded-for','content-type']) {
    if (req.headers[h]) safeH[h] = req.headers[h];
  }

  const geoPromise = enrichIp(ip);

  const { data: inserted } = await supabase.from('honeypot_hits').insert({
    ip, path, method, user_agent: ua, origin, headers: safeH,
    body: req.body ? JSON.stringify(req.body).slice(0, 1024) : null,
  }).select('id').single();

  const hitId = inserted?.id || '';

  geoPromise.then(geo => {
    if (!geo || !hitId) return;
    supabase.from('honeypot_hits').update({ geo }).eq('id', hitId).then(() => {}).catch(() => {});
  });

  const key  = Object.keys(HONEYPOT_RESPONSES).find(k => path.includes(k));
  const fake = key ? HONEYPOT_RESPONSES[key](hitId) : { status: 'ok' };
  if (typeof fake === 'string') {
    const isEnv = path.includes('.env') || path.includes('config.php');
    res.setHeader('Content-Type', isEnv ? 'text/plain' : 'text/html; charset=utf-8');
    return res.status(200).send(fake);
  }
  return res.status(200).json(fake);
}
const CATALOG_RATE     = 60;  
const CATALOG_RATE_MEM = 120; 
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
    const { data, error } = await supabase.from('products').select('*').eq('id', id).eq('active', true).single();
    if (error || !data) return res.status(404).json({ error: 'Produto não encontrado.' });
    return res.status(200).json(mapProduct(data));
  }
  if (ids) {
    const idList = ids.split(',').slice(0, 50).filter(isUuid);
    if (idList.length === 0) return res.status(400).json({ error: 'ids inválidos.' });
    const { data, error } = await supabase.from('products').select('*').in('id', idList).eq('active', true);
    if (error) return res.status(500).json({ error: 'Erro ao buscar produtos.' });
    return res.status(200).json((data || []).map(mapProduct));
  }
  let query = supabase.from('products').select('*')
    .eq('active', true)
    .order('sold_count', { ascending: false })
    .limit(200);
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
  if (req.query._hp === '1') return handleHoneypot(req, res);
  if (cors(req, res)) return;
  if (req.method !== 'GET') return res.status(405).end();
  const ip = extractIp(req);
  const [rlDb, rlMem] = await Promise.all([
    checkRateLimit(`ip:${ip}:catalog`, CATALOG_RATE),
    Promise.resolve(checkIpRateLimit(ip, CATALOG_RATE_MEM)),
  ]);
  const rl = !rlDb.allowed ? rlDb : rlMem;
  if (!rl.allowed)
    return res.status(429).json({ error: `Muitas requisições. Tente novamente em ${rl.retryAfterSec}s.` });
  const { r } = req.query;
  if (r === 'categories') return handleCategories(req, res);
  return handleProducts(req, res);
};
