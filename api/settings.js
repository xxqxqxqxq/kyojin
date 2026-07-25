const { verify, BOT_URL } = require('./_lib');

module.exports = async function handler(req, res) {
  const cookies = (req.headers.cookie || '').split(';').reduce((acc, c) => {
    const [k, v] = c.trim().split('=');
    if (k) acc[k] = v;
    return acc;
  }, {});

  const session = verify(cookies.session);
  const apiKey = req.headers['x-api-key'] || '';
  if (!session && (!apiKey || apiKey !== (process.env.BOT_API_KEY || ''))) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const resp = await fetch(`${BOT_URL}/api/settings`, {
      method: req.method,
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': process.env.BOT_API_KEY || '',
      },
      body: req.method === 'POST' ? (() => { let b = ''; return null; })() : undefined,
    });
    const result = await resp.json();
    return res.status(200).json(result);
  } catch (e) {
    return res.status(500).json({ error: 'Bot server unreachable' });
  }
};
