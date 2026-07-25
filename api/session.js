const { verify } = require('./_lib');

module.exports = async function handler(req, res) {
  const cookies = (req.headers.cookie || '').split(';').reduce((acc, c) => {
    const [k, v] = c.trim().split('=');
    if (k) acc[k] = v;
    return acc;
  }, {});

  const session = verify(cookies.session);
  if (!session) return res.status(200).json({ authenticated: false });

  return res.status(200).json({ authenticated: true, username: session.username });
};
