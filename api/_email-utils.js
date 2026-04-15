const EMAIL_RE = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
const ALLOWED_DOMAINS = new Set([
  'gmail.com','googlemail.com',
  'outlook.com','outlook.com.br',
  'hotmail.com','hotmail.com.br',
  'live.com','live.com.br','msn.com',
]);
function isValidEmail(email) {
  return typeof email === 'string' && email.length <= 254 && EMAIL_RE.test(email);
}
function isAllowedDomain(email) {
  const domain = (email || '').split('@')[1] || '';
  return ALLOWED_DOMAINS.has(domain);
}
module.exports = { isValidEmail, isAllowedDomain };
