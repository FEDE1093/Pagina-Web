require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const path = require('path');

const { DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, STEAM_API_KEY, BASE_URL = 'http://localhost:3000', SESSION_SECRET, PORT = 3000 } = process.env;
if (!SESSION_SECRET) throw new Error('Falta SESSION_SECRET en .env');

const app = express();
const secure = BASE_URL.startsWith('https');

const sign = v => crypto.createHmac('sha256', SESSION_SECRET).update(v).digest('base64url');
const setCookie = (res, name, obj, maxAge) => {
  const v = Buffer.from(JSON.stringify(obj)).toString('base64url');
  res.append('Set-Cookie', `${name}=${v}.${sign(v)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure ? '; Secure' : ''}`);
};
const getCookie = (req, name) => {
  const raw = (req.headers.cookie || '').split('; ').find(c => c.startsWith(name + '='));
  if (!raw) return null;
  const [v, sig] = raw.slice(name.length + 1).split('.');
  const ok = sig && sig.length === sign(v).length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(sign(v)));
  if (!ok) return null;
  try { return JSON.parse(Buffer.from(v, 'base64url').toString()); } catch { return null; }
};

app.get('/', (_, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.get('/api/me', (req, res) => res.json(getCookie(req, 'session') || null));
app.get('/auth/logout', (_, res) => {
  res.append('Set-Cookie', 'session=; Path=/; Max-Age=0');
  res.redirect('/');
});

// Discord OAuth2
app.get('/auth/discord', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  setCookie(res, 'oauth_state', { state }, 600);
  const q = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: `${BASE_URL}/auth/discord/callback`,
    response_type: 'code',
    scope: 'identify',
    state
  });
  res.redirect(`https://discord.com/oauth2/authorize?${q}`);
});

app.get('/auth/discord/callback', async (req, res) => {
  try {
    const saved = getCookie(req, 'oauth_state');
    if (!saved || saved.state !== req.query.state || !req.query.code) return res.status(400).send('Solicitud inválida');
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code: req.query.code,
        redirect_uri: `${BASE_URL}/auth/discord/callback`
      })
    });
    const token = await tokenRes.json();
    if (!token.access_token) return res.status(400).send('No se pudo autenticar con Discord');
    const u = await (await fetch('https://discord.com/api/users/@me', { headers: { Authorization: `Bearer ${token.access_token}` } })).json();
    const avatar = u.avatar ? `https://cdn.discordapp.com/avatars/${u.id}/${u.avatar}.png` : null;
    setCookie(res, 'session', { provider: 'discord', id: u.id, name: u.global_name || u.username, avatar }, 604800);
    res.redirect('/');
  } catch (e) {
    console.error(e);
    res.status(500).send('Error de autenticación');
  }
});

// Steam OpenID 2.0
app.get('/auth/steam', (req, res) => {
  const q = new URLSearchParams({
    'openid.ns': 'http://specs.openid.net/auth/2.0',
    'openid.mode': 'checkid_setup',
    'openid.return_to': `${BASE_URL}/auth/steam/callback`,
    'openid.realm': BASE_URL,
    'openid.identity': 'http://specs.openid.net/auth/2.0/identifier_select',
    'openid.claimed_id': 'http://specs.openid.net/auth/2.0/identifier_select'
  });
  res.redirect(`https://steamcommunity.com/openid/login?${q}`);
});

app.get('/auth/steam/callback', async (req, res) => {
  try {
    const params = new URLSearchParams(req.query);
    params.set('openid.mode', 'check_authentication');
    const check = await (await fetch('https://steamcommunity.com/openid/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params
    })).text();
    const m = /^https:\/\/steamcommunity\.com\/openid\/id\/(\d+)$/.exec(req.query['openid.claimed_id'] || '');
    if (!/is_valid:true/.test(check) || !m) return res.status(400).send('Steam no validó el inicio de sesión');
    const steamId = m[1];
    let name = steamId, avatar = null;
    if (STEAM_API_KEY) {
      const r = await (await fetch(`https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?key=${STEAM_API_KEY}&steamids=${steamId}`)).json();
      const p = r.response && r.response.players && r.response.players[0];
      if (p) { name = p.personaname; avatar = p.avatarfull; }
    }
    setCookie(res, 'session', { provider: 'steam', id: steamId, name, avatar }, 604800);
    res.redirect('/');
  } catch (e) {
    console.error(e);
    res.status(500).send('Error de autenticación');
  }
});

app.listen(PORT, () => console.log(`Origen.es en ${BASE_URL}`));
