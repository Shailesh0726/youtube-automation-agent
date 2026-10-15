const assert = require('node:assert/strict');
const express = require('express');
const { google } = require('googleapis');
const { installCloudAccess } = require('../utils/cloud-access');

async function main() {
  Object.assign(process.env, { CLOUD_MODE: 'true', PUBLIC_BASE_URL: 'https://studio.example.com', YOUTUBE_CLIENT_ID: 'test-client', YOUTUBE_CLIENT_SECRET: 'test-secret', API_KEY: 'internal-test-key' });
  delete process.env.DASHBOARD_PASSWORD;
  const agent = { app: express(), credentials: { credentials: {}, tokens: {}, saveCredentials: async () => {}, saveTokens: async () => {} } };
  installCloudAccess(agent);
  agent.app.get('/private', (_req, res) => res.send('private'));
  agent.app.post('/mutation', (req, res) => res.json({ key: req.get('x-api-key') }));
  const server = agent.app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const request = (route, options = {}) => fetch(base + route, { redirect: 'manual', ...options });
  try {
    assert.equal((await request('/cloud/health')).status, 200);
    assert.equal((await request('/private')).status, 503);
    process.env.DASHBOARD_PASSWORD = 'test-only-password-123456789';
    const auth = { authorization: 'Basic ' + Buffer.from('admin:' + process.env.DASHBOARD_PASSWORD).toString('base64') };
    assert.equal((await request('/private')).status, 401);
    assert.equal((await request('/private', { headers: auth })).status, 200);
    assert.equal((await request('/mutation', { method: 'POST', headers: auth })).status, 403);
    assert.equal((await request('/mutation', { method: 'POST', headers: { ...auth, origin: 'https://evil.example' } })).status, 403);
    const mutation = await request('/mutation', { method: 'POST', headers: { ...auth, origin: process.env.PUBLIC_BASE_URL } });
    assert.equal((await mutation.json()).key, 'internal-test-key');
    assert.equal((await request('/cloud/youtube/callback?state=forged&code=x', { headers: auth })).status, 400);
    const start = await request('/cloud/youtube/start', { headers: auth });
    assert.equal(start.status, 302);
    const redirect = new URL(start.headers.get('location'));
    assert.equal(redirect.hostname, 'accounts.google.com');
    assert.equal(redirect.searchParams.get('redirect_uri'), process.env.PUBLIC_BASE_URL + '/cloud/youtube/callback');
    const state = redirect.searchParams.get('state');
    const cookie = start.headers.get('set-cookie').split(';')[0];
    assert.match(start.headers.get('set-cookie'), /HttpOnly/);
    assert.match(start.headers.get('set-cookie'), /Secure/);
    google.auth.OAuth2.prototype.getToken = async () => ({ tokens: { refresh_token: 'mock-refresh' } });
    const callback = `/cloud/youtube/callback?state=${state}&code=mock-code`;
    assert.equal((await request(callback, { headers: { ...auth, cookie } })).status, 200);
    assert.equal(agent.credentials.tokens.youtube.refresh_token, 'mock-refresh');
    assert.equal((await request(callback, { headers: { ...auth, cookie } })).status, 400);
    console.log('PASS: locked setup, auth, CSRF, internal API key, OAuth redirect, cookie binding, token persistence and replay rejection');
  } finally { server.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
