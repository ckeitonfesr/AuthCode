// UUID v4 format (36 chars)
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isUuid(s) {
  return typeof s === 'string' && UUID_RE.test(s);
}

// Returns body size in bytes (after JSON parse)
function bodySize(req) {
  if (!req.body) return 0;
  try { return Buffer.byteLength(JSON.stringify(req.body)); }
  catch { return Infinity; }
}

module.exports = { isUuid, bodySize };
