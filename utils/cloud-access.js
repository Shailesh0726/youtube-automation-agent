const crypto = require('node:crypto');
const { google } = require('googleapis');

function equal(a, b) {
  return crypto.timingSafeEqual(crypto.createHash('sha256').update(a).digest(), crypto.createHash('sha256').update(b).digest());
}

// Cloud-only protection sits before every upstream route, including static files.
function installCloudAccess(agent) {
  if (process.env.CLOUD_MODE !== 'true') return;
  const app = agent.app;
  const states = new Map();
  const attempts = new Map();
  app.set('trust proxy', 1);
  app.get('/cloud/health', (_req, res) => res.json({ ok: true }));
  app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    res.set('Referrer-Policy', 'no-referrer');
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('X-Frame-Options', 'DENY');
    const password = process.env.DASHBOARD_PASSWORD || '';
    if (password.length < 20) return res.status(503).send('Set DASHBOARD_PASSWORD (at least 20 characters) in Railway Variables to finish private setup.');
    const now = Date.now();
    for (const [key, value] of attempts) if (value.until < now) attempts.delete(key);
    const entry = attempts.get(req.ip);
    if (entry?.count >= 10) return res.status(429).send('Too many login attempts. Try again in 15 minutes.');
    const header = req.get('authorization') || '';
    const supplied = header.startsWith('Basic ') ? Buffer.from(header.slice(6), 'base64').toString() : '';
    if (!equal(supplied, `admin:${password}`)) {
      if (header) attempts.set(req.ip, { count: (entry?.count || 0) + 1, until: entry?.until || now + 900000 });
      res.set('WWW-Authenticate', 'Basic realm="YouTube dashboard", charset="UTF-8"');
      return res.status(401).send('Sign in with username admin and your dashboard password.');
    }
    attempts.delete(req.ip);
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      const origin = process.env.PUBLIC_BASE_URL;
      if (!origin || req.get('origin') !== origin) return res.status(403).send('Invalid request origin');
    }
    // The outer gate authenticates the browser; preserve upstream API-key gates.
    if (process.env.API_KEY) req.headers['x-api-key'] = process.env.API_KEY;
    next();
  });

  const getClient = () => {
    const base = new URL(process.env.PUBLIC_BASE_URL || '');
    if (base.protocol !== 'https:' || base.pathname !== '/') throw new Error('PUBLIC_BASE_URL must be an HTTPS origin');
    const { YOUTUBE_CLIENT_ID, YOUTUBE_CLIENT_SECRET } = process.env;
    if (!YOUTUBE_CLIENT_ID || !YOUTUBE_CLIENT_SECRET) throw new Error('Add Google Web application OAuth credentials to Railway Variables');
    return new google.auth.OAuth2(YOUTUBE_CLIENT_ID, YOUTUBE_CLIENT_SECRET, `${base.origin}/cloud/youtube/callback`);
  };
  app.get('/cloud/setup', (_req, res) => {
    res.type('html').send(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>YouTube setup</title><style>body{font:17px system-ui;max-width:620px;margin:40px auto;padding:24px;line-height:1.6;background:#101828;color:#fff}a{color:#8ed8ff}li{margin:14px 0}</style></head><body><h1>Your YouTube studio</h1><p>Private setup for Shailesh. Automatic production starts paused.</p><ol><li>In Railway Variables, set an AI provider key, such as GEMINI_API_KEY.</li><li>Create a Google OAuth client of type <strong>Web application</strong>. Enable YouTube Data API v3 and YouTube Analytics API. Set its authorized redirect URI to this site's origin followed by <code>/cloud/youtube/callback</code>.</li><li>Add YOUTUBE_CLIENT_ID and YOUTUBE_CLIENT_SECRET in Railway Variables.</li><li><a href="/cloud/youtube/start">Connect your YouTube channel</a></li></ol><p>After connecting, restart the Railway service, then <a href="/">open the dashboard</a>. Review one draft and its cost before activating automation.</p><p>Enter secrets in Railway Variables, never in GitHub or chat.</p></body></html>`);
  });
  app.get('/cloud/youtube/start', (_req, res) => {
    try {
      const client = getClient();
      const state = crypto.randomBytes(32).toString('hex');
      for (const [key, value] of states) if (value < Date.now()) states.delete(key);
      states.set(state, Date.now() + 600000);
      res.cookie('youtube_oauth_state', state, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 600000, path: '/cloud/youtube/callback' });
      res.redirect(client.generateAuthUrl({ access_type: 'offline', prompt: 'consent', state, scope: [
        'https://www.googleapis.com/auth/youtube.upload',
        'https://www.googleapis.com/auth/youtube.readonly',
        'https://www.googleapis.com/auth/yt-analytics.readonly'
      ] }));
    } catch { res.status(503).send('Set PUBLIC_BASE_URL, YOUTUBE_CLIENT_ID and YOUTUBE_CLIENT_SECRET in Railway Variables first.'); }
  });
  app.get('/cloud/youtube/callback', async (req, res) => {
    const state = typeof req.query.state === 'string' ? req.query.state : '';
    const cookie = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith('youtube_oauth_state='))?.slice(20) || '';
    const expires = states.get(state);
    states.delete(state);
    res.clearCookie('youtube_oauth_state', { path: '/cloud/youtube/callback', secure: true, httpOnly: true, sameSite: 'lax' });
    if (!expires || expires < Date.now() || !equal(cookie, state) || typeof req.query.code !== 'string') return res.status(400).send('Authorization expired or was denied. Start again from /cloud/setup.');
    try {
      const client = getClient();
      const { tokens } = await client.getToken(req.query.code);
      if (!tokens.refresh_token) return res.status(400).send('Google did not return offline access. Reconnect with consent.');
      agent.credentials.credentials.youtube = {
        client_id: process.env.YOUTUBE_CLIENT_ID,
        client_secret: process.env.YOUTUBE_CLIENT_SECRET,
        redirect_uris: [`${process.env.PUBLIC_BASE_URL}/cloud/youtube/callback`]
      };
      agent.credentials.tokens.youtube = tokens;
      await agent.credentials.saveCredentials();
      await agent.credentials.saveTokens();
      res.send('YouTube connected. Restart this service in Railway, then open the dashboard. Automation remains paused.');
    } catch { res.status(502).send('Google authorization could not be completed. Check the OAuth configuration and try again.'); }
  });
}

module.exports = { installCloudAccess, equal };
