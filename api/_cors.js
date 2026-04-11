const ALLOWED_ORIGIN = 'https://24hrs-central.site';

function cors(req, res) {
  res.setHeader('Access-Control-Allow-Origin',  ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers',
    'Content-Type, x-request-token, x-device-id, x-app-key, x-timestamp, x-signature, x-user-token, x-webhook-secret, x-app-platform, x-integrity-token, x-integrity-nonce, authorization, apikey, accept-profile, prefer'
  );

  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return true;
  }
  return false;
}

module.exports = cors;
