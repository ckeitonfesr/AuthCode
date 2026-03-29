const crypto = require('crypto');

const PACKAGE_NAME = 'com.cleitontwz.convenienciacentral';
const NONCE_TTL_MS = 90 * 1000;

// Cache de tokens do Google já usados nesta instância (evita reuso dentro da janela)
const usedIntegrityTokens = new Map();

function evict() {
  const now = Date.now();
  for (const [k, exp] of usedIntegrityTokens.entries()) {
    if (now > exp) usedIntegrityTokens.delete(k);
  }
}

/**
 * Obtém access token do Google via JWT de service account (RS256).
 * Não requer biblioteca externa — usa apenas o módulo crypto nativo do Node.
 */
async function getGoogleAccessToken(serviceAccountJson) {
  const sa  = typeof serviceAccountJson === 'string'
    ? JSON.parse(serviceAccountJson)
    : serviceAccountJson;

  const now = Math.floor(Date.now() / 1000);
  const header  = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    iss:   sa.client_email,
    scope: 'https://www.googleapis.com/auth/playintegrity',
    aud:   'https://oauth2.googleapis.com/token',
    iat:   now,
    exp:   now + 3600,
  })).toString('base64url');

  const unsigned  = `${header}.${payload}`;
  const signature = crypto
    .createSign('RSA-SHA256')
    .update(unsigned)
    .sign(sa.private_key, 'base64url');

  const jwt = `${unsigned}.${signature}`;

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion:  jwt,
    }),
  });

  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) {
    throw new Error(`Google auth falhou: ${tokenData.error_description || tokenData.error}`);
  }
  return tokenData.access_token;
}

/**
 * Verifica um token do Play Integrity (Android) ou App Attest (iOS).
 *
 * @param {string} integrityToken  - token recebido do dispositivo
 * @param {string} expectedNonce   - nonce que o servidor emitiu
 * @param {'android'|'ios'} platform
 * @returns {{ valid: boolean, reason?: string }}
 */
async function verifyIntegrityToken(integrityToken, expectedNonce, platform = 'android') {
  const saJson = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;

  // Se a service account não estiver configurada, ignora verificação (apenas em dev)
  if (!saJson) {
    if (process.env.NODE_ENV !== 'production') {
      console.warn('[integrity] GOOGLE_SERVICE_ACCOUNT_JSON não configurado — verificação ignorada em dev');
      return { valid: true };
    }
    console.error('[integrity] GOOGLE_SERVICE_ACCOUNT_JSON ausente em produção');
    return { valid: false, reason: 'Serviço de integridade não configurado' };
  }

  evict();

  // Impede reuso do mesmo token de integridade
  const tokenKey = crypto.createHash('sha256').update(integrityToken).digest('hex');
  if (usedIntegrityTokens.has(tokenKey)) {
    return { valid: false, reason: 'Token de integridade reutilizado' };
  }

  try {
    if (platform === 'android') {
      const accessToken = await getGoogleAccessToken(saJson);

      const verifyRes = await fetch(
        `https://playintegrity.googleapis.com/v1/${PACKAGE_NAME}:decodeIntegrityToken`,
        {
          method:  'POST',
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type':  'application/json',
          },
          body: JSON.stringify({ integrity_token: integrityToken }),
        }
      );

      const result = await verifyRes.json();

      if (!verifyRes.ok) {
        console.error('[integrity] Google API erro:', result);
        return { valid: false, reason: 'Falha na verificação com Google' };
      }

      const payload = result?.tokenPayloadExternal;

      // 1. Confere o nonce
      if (payload?.requestDetails?.nonce !== expectedNonce) {
        return { valid: false, reason: 'Nonce inválido' };
      }

      // 2. Confere package name
      if (payload?.requestDetails?.requestPackageName !== PACKAGE_NAME) {
        return { valid: false, reason: 'Package name inválido' };
      }

      // 3. Confere frescor do token (máx 90 segundos)
      const issuedMs = Number(payload?.requestDetails?.timestampMillis);
      if (!issuedMs || Date.now() - issuedMs > NONCE_TTL_MS) {
        return { valid: false, reason: 'Token de integridade expirado' };
      }

      // 4. Confere reconhecimento do app
      const appVerdict = payload?.appIntegrity?.appRecognitionVerdict;
      if (!['PLAY_RECOGNIZED', 'UNRECOGNIZED_VERSION'].includes(appVerdict)) {
        return { valid: false, reason: `App não reconhecido: ${appVerdict}` };
      }

      // 5. Confere integridade do dispositivo
      const deviceVerdicts = payload?.deviceIntegrity?.deviceRecognitionVerdict ?? [];
      if (!deviceVerdicts.includes('MEETS_DEVICE_INTEGRITY')) {
        return { valid: false, reason: `Dispositivo comprometido: ${deviceVerdicts.join(',')}` };
      }

      usedIntegrityTokens.set(tokenKey, Date.now() + NONCE_TTL_MS);
      return { valid: true };

    } else {
      // iOS — App Attest: a verificação completa requer Apple DeviceCheck API
      // Por ora, aceitamos o token com aviso (implementação completa requer apple-app-attest)
      console.warn('[integrity] Verificação iOS App Attest não implementada — aceitando');
      usedIntegrityTokens.set(tokenKey, Date.now() + NONCE_TTL_MS);
      return { valid: true };
    }

  } catch (err) {
    console.error('[integrity] Erro inesperado:', err.message);
    return { valid: false, reason: 'Erro interno de verificação' };
  }
}

module.exports = { verifyIntegrityToken };
