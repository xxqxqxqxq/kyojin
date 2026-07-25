const crypto = require('crypto');
const { sign, ADMIN_HASH } = require('./_lib');

const RATE_LIMITS = {};

function checkRate(ip) {
  const now = Date.now();
  RATE_LIMITS[ip] = (RATE_LIMITS[ip] || []).filter(t => now - t < 60000);
  if (RATE_LIMITS[ip].length >= 30) return false;
  RATE_LIMITS[ip].push(now);
  return true;
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
  if (!checkRate(ip)) return res.status(429).json({ error: 'Rate limited' });

  let body = '';
  for await (const chunk of req) body += chunk;
  let data;
  try { data = JSON.parse(body); } catch { return res.status(400).json({ error: 'Invalid JSON' }); }

  const username = String(data.username || '').trim().slice(0, 50);
  const password = String(data.password || '').trim().slice(0, 100);
  if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });

  const hash = crypto.createHash('sha256').update(password).digest('hex');
  if (!ADMIN_HASH || hash !== ADMIN_HASH) {
    await new Promise(r => setTimeout(r, 500));
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = sign({ username, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600 });

  res.setHeader('Set-Cookie', `session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600`);
  return res.status(200).json({ success: true });
};
