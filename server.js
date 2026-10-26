'use strict';
const http = require('http');
const { WebSocketServer } = require('ws');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const STATS_FILE = path.join(__dirname, 'events.jsonl');

// ID, которые скрыты из статистики
const IGNORED_PLAYER_IDS = new Set([
  '29506969',           // тестовый VK
  '560206319344',       // тестовый OK
  'ok_560206319344',    // тестовый OK (с префиксом)
  'ok_29506969',        // тестовый VK в OK-режиме
]);
function isIgnoredPlayer(playerId){
  if(!playerId) return false;
  return IGNORED_PLAYER_IDS.has(String(playerId));
}

// [STATS] Persistent statistics in Postgres.
const DATABASE_URL = process.env.DATABASE_URL || '';
const pgPool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl: false,
      max: 10,
      idleTimeoutMillis: 30000,
    })
  : null;

async function initStatsTable() {
  if (!pgPool) { console.warn('[STATS] DATABASE_URL не задано, работаем через файл'); return; }
  try {
    await pgPool.query([
      'CREATE TABLE IF NOT EXISTS events (',
      '  id BIGSERIAL PRIMARY KEY,',
      '  t BIGINT NOT NULL,',
      "  app TEXT NOT NULL DEFAULT 'antivirus',",
      '  ev TEXT NOT NULL,',
      '  player_id TEXT,',
      '  session_id TEXT,',
      "  payload JSONB NOT NULL DEFAULT '{}'::jsonb,",
      '  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()',
      ');',
      'CREATE INDEX IF NOT EXISTS idx_events_app_t ON events (app, t DESC);',
      'CREATE INDEX IF NOT EXISTS idx_events_ev ON events (ev);'
    ].join(String.fromCharCode(10)));
    console.log('[STATS] Postgres table ready');
    try {
      const ids = [...IGNORED_PLAYER_IDS];
      const r = await pgPool.query(
        'DELETE FROM events WHERE player_id = ANY($1::text[])',
        [ids]
      );
      if (r.rowCount > 0) console.log('[STATS] Removed', r.rowCount, 'events from test accounts');
    } catch (e) { console.warn('[STATS] Cleanup failed:', e.message); }
    try {
      if (fs.existsSync(STATS_FILE)) {
        const lines = fs.readFileSync(STATS_FILE, 'utf8').split(String.fromCharCode(10)).filter(Boolean);
        if (lines.length > 0) {
          const { rows } = await pgPool.query('SELECT COUNT(*)::int AS c FROM events');
          if (rows[0].c === 0) {
            console.log('[STATS] Migrating', lines.length, 'events from file...');
            for (const line of lines) {
              try {
                const e = JSON.parse(line);
                await pgPool.query(
                  'INSERT INTO events (t, app, ev, player_id, session_id, payload) VALUES ($1,$2,$3,$4,$5,$6)',
                  [e.t || 0, e.app || 'antivirus', e.ev || 'unknown', e.playerId || null, e.sessionId || null, e]
                );
              } catch (err) { /* skip bad line */ }
            }
            console.log('[STATS] Migration done');
            fs.renameSync(STATS_FILE, STATS_FILE + '.migrated');
          }
        }
      }
    } catch (e) { console.warn('[STATS] Migration failed:', e.message); }
  } catch (e) {
    console.error('[STATS] Table init failed:', e.message);
  }
}
const STATS_TOKEN = process.env['STATS_TOKEN'] || 'change-me-antivirus-stats';

const PORT = process.env.PORT || 3000;
const MATCHMAKING_TIMEOUT = 120 * 1000;
const MAX_GARBAGE = 5;
const TARGET_VIRUSES = 15;

const VK_APP_SECRET       = process.env.VK_APP_SECRET || '';
const VK_APP_SECRET_TANKS = process.env.VK_APP_SECRET_TANKS || '';
const OK_APP_SECRET       = process.env.OK_APP_SECRET || '';
const OK_APP_SECRET_TANKS = process.env.OK_APP_SECRET_TANKS || '';

const SHOP_ITEMS = {
  bombs_pack:     { title: 'Набор бомб ×5',  price: 5,  photo_url: 'https://darones.github.io/antivirus/logo.png' },
  bombs_pack_big: { title: 'Набор бомб ×20', price: 15, photo_url: 'https://darones.github.io/antivirus/logo.png' },
  remove_ads:     { title: 'Убрать рекламу', price: 10, photo_url: 'https://darones.github.io/antivirus/logo.png' },
};
const TANKS_SHOP_ITEMS = {
  tanks_coins_small:  { title: '10 000 монет', price: 5,  photo_url: 'https://raw.githubusercontent.com/Darones/assets/main/coin.png' },
  tanks_coins_medium: { title: '25 000 монет', price: 10, photo_url: 'https://raw.githubusercontent.com/Darones/assets/main/coin.png' },
  tanks_coins_large:  { title: '60 000 монет', price: 20, photo_url: 'https://raw.githubusercontent.com/Darones/assets/main/coin.png' },
};
const VK_SHOP_ITEMS_BY_APP = {
  '54764920': SHOP_ITEMS,
  '54786750':      TANKS_SHOP_ITEMS,
  '512005381577':  TANKS_SHOP_ITEMS,
  '512004990432': SHOP_ITEMS,
};
const purchases = new Map();

function validateOKSig(params, secretOverride) {
  const secret = secretOverride || OK_APP_SECRET;
  if (!secret) return true;
  const { sig, access_token, ...rest } = params;
  if (!sig) return false;
  const secretKey = crypto.createHash('md5').update((access_token || '') + secret).digest('hex');
  const sorted = Object.keys(rest).sort().map(k => k + '=' + rest[k]).join('&');
  const hash = crypto.createHash('md5').update(sorted + secretKey).digest('hex');
  return hash === sig;
}

function validatePaymentsSig(params) {
  const appId = String(params.app_id || '');
  const isOK = (params.site === 'OK') || (appId === '512004990432') || (appId === '512005381577');
  const isTanks = (appId === '54786750') || (appId === '512005381577');

  let secret;
  if (isOK) secret = OK_APP_SECRET;
  else if (isTanks) secret = VK_APP_SECRET_TANKS;
  else secret = VK_APP_SECRET;

  if (!secret) return true;
  const { sig, ...rest } = params;
  if (!sig) return false;

  const sorted = Object.keys(rest).sort().map(k => k + '=' + rest[k]).join('');
  const hash = crypto.createHash('md5').update(sorted + secret).digest('hex');
  return hash === sig;
}

function validateVKParams(params) {
  if (!VK_APP_SECRET) return true;
  const { sign, ...rest } = params;
  if (!sign) return false;
  const sorted = Object.keys(rest).sort().map(k => `${k}=${rest[k]}`).join('&');
  const hash = crypto.createHmac('sha256', VK_APP_SECRET).update(sorted)
    .digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return hash === sign;
}

const rooms = new Map();
const waiting = [];
const players = new Map();
let roomCounter = 0;

const createRoomId = () => 'r' + (++roomCounter).toString(36) + Math.random().toString(36).slice(2, 6);
const send = (ws, msg) => { if (ws.readyState === 1) ws.send(JSON.stringify(msg)); };

function setCORS(res){
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
}

const server = http.createServer((req, res) => {
  setCORS(res);
  if(req.method === 'OPTIONS'){ res.writeHead(204); res.end(); return; }
  if (req.url === '/stats/event' && req.method === 'POST') {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', async () => {
      try {
        const data = JSON.parse(body);
        const rawEvents = Array.isArray(data?.events) ? data.events : [];
        const events = rawEvents.filter(e => !isIgnoredPlayer(e.playerId));
        if (events.length === 0) { res.writeHead(200); res.end('{"ok":true}'); return; }
        if (pgPool) {
          const values = [];
          const placeholders = [];
          let i = 1;
          for (const e of events) {
            placeholders.push('($' + i++ + ',$' + i++ + ',$' + i++ + ',$' + i++ + ',$' + i++ + ',$' + i++ + ')');
            values.push(
              Number(e.t) || 0,
              String(e.app || 'antivirus'),
              String(e.ev || 'unknown'),
              e.playerId ? String(e.playerId) : null,
              e.sessionId ? String(e.sessionId) : null,
              JSON.stringify(e)
            );
          }
          await pgPool.query(
            'INSERT INTO events (t, app, ev, player_id, session_id, payload) VALUES ' + placeholders.join(','),
            values
          );
        } else {
          const lines = events.map(e => JSON.stringify(e)).join(String.fromCharCode(10)) + String.fromCharCode(10);
          fs.appendFileSync(STATS_FILE, lines, 'utf8');
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, received: events.length }));
      } catch (e) {
        console.warn('[STATS] bad payload:', e.message);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":false}');
      }
    });
    return;
  }

  if (req.url.startsWith('/stats/reset')) {
    (async () => {
      const urlObj = new URL(req.url, 'http://x');
      const token = urlObj.searchParams.get('token') || '';
      if (token !== STATS_TOKEN) { res.writeHead(403); res.end('forbidden'); return; }
      try {
        if (pgPool) {
          await pgPool.query('TRUNCATE events RESTART IDENTITY');
          console.log('[STATS] DB truncated by token');
        } else {
          fs.writeFileSync(STATS_FILE, '', 'utf8');
          console.log('[STATS] file cleared by token');
        }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('<meta charset="utf-8"><h2>Статистика очищена</h2><p><a href="/stats/dashboard?token=' + encodeURIComponent(token) + '">К дашборду</a></p>');
      } catch (e) {
        console.warn('[STATS] reset failed:', e.message);
        res.writeHead(500); res.end('reset failed');
      }
    })().catch(e => { console.error('[STATS/reset]', e); res.writeHead(500); res.end('reset failed'); });
    return;
  }

  if (req.url.startsWith('/stats/player')) {
    (async () => {
      const urlObj = new URL(req.url, 'http://x');
      const token = urlObj.searchParams.get('token') || '';
      const playerId = urlObj.searchParams.get('id') || '';
      if (token !== STATS_TOKEN) { res.writeHead(403); res.end('forbidden'); return; }
      if (!playerId) { res.writeHead(400); res.end('player id required'); return; }
      let events;
      if (pgPool) {
        const result = await pgPool.query('SELECT payload FROM events WHERE player_id = $1 ORDER BY t DESC LIMIT 100', [playerId]);
        events = result.rows.map(row => row.payload);
      } else {
        let lines = [];
        try { lines = fs.readFileSync(STATS_FILE, 'utf8').split(String.fromCharCode(10)).filter(Boolean); } catch { lines = []; }
        events = [];
        for (const line of lines) {
          try { const event = JSON.parse(line); if (String(event.playerId || '') === playerId) events.push(event); } catch {}
        }
        events.sort((a, b) => (Number(b.t) || 0) - (Number(a.t) || 0));
        events = events.slice(0, 100);
      }
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(events));
    })().catch(e => { console.error('[STATS/player]', e); res.writeHead(500); res.end('error'); });
    return;
  }

  if (req.url.startsWith('/stats/data')) {
    (async () => {
      const urlObj = new URL(req.url, 'http://x');
      const token = urlObj.searchParams.get('token') || '';
      const period = urlObj.searchParams.get('period') || 'all';
      if (token !== STATS_TOKEN) { res.writeHead(403); res.end('forbidden'); return; }
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      const summary = await buildStatsSummary(period);
      res.end(JSON.stringify(summary));
    })().catch(e => { console.error('[STATS/data]', e); res.writeHead(500); res.end('error'); });
    return;
  }

  if (req.url.startsWith('/stats/dashboard')) {
    const urlObj = new URL(req.url, 'http://x');
    const token = urlObj.searchParams.get('token') || '';
    if (token !== STATS_TOKEN) { res.writeHead(403); res.end('forbidden'); return; }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(renderStatsDashboard(token));
    return;
  }
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, rooms: rooms.size, waiting: waiting.length }));
    return;
  }
  
  if (req.url.startsWith('/ok/pay')) {
    const urlObj = new URL(req.url, 'http://x');
    const params = Object.fromEntries(urlObj.searchParams);
    const rawAppId = String(params.app_id || urlObj.searchParams.get('app') || '');
    const appParam = rawAppId || '512004990432';
    const isTanks = (appParam === '54786750') || (appParam === '512005381577');
    const isOKRequest = (params.site === 'OK')
                   || (appParam === '512004990432')
                   || (appParam === '512005381577')
                   || (appParam === '54786750')
                   || (params.method === 'callbacks.payment');
    const shop = VK_SHOP_ITEMS_BY_APP[appParam] || SHOP_ITEMS;
    const okSecret = isTanks ? OK_APP_SECRET_TANKS : OK_APP_SECRET;

    let notificationType = params.notification_type || params.operation_type || '';
    if (!notificationType && (params.product_code || params.code || params.item_id) && (params.status || params.amount || params.method === 'callbacks.payment')) {
      notificationType = 'order_status_change';
    }
    const itemId = params.product_code || params.item || params.code;
    const userId = params.uid || params.user_id;
    const orderId = params.order_id || params.transaction_id;

    if (isOKRequest) {
      // skip sig
    } else if (okSecret) {
      const { sig, access_token, ...rest } = params;
      if (sig) {
        const secretKey = crypto.createHash('md5').update((access_token || '') + okSecret).digest('hex');
        const sorted = Object.keys(rest).sort().map(k => k + '=' + rest[k]).join('&');
        const expected = crypto.createHash('md5').update(sorted + secretKey).digest('hex');
        if (expected !== sig) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end('{"status":"error","error_code":104,"error_msg":"invalid signature"}');
          return;
        }
      }
    }

    if (notificationType === 'get_item' || notificationType === 'get_item_test') {
      const item = shop[itemId];
      if (!item) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: { error_code: 20, error_msg: 'Unknown item', critical: true } }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ response: { title: item.title, price: item.price, photo_url: item.photo_url || '', item_id: itemId } }));
      return;
    }

    if (notificationType === 'order_status_change' || notificationType === 'order_status_change_test') {
      const isOKPayment = (params.method === 'callbacks.payment') || (params.application_key === 'CBOGCBOGDIHBABABA') || !params.status;
      const isChargeable = (params.status === 'chargeable') || (isOKPayment && (params.product_code || params.item_id || params.item));
      if (isChargeable) {
        const resolvedItemId = params.product_code || params.item_id || params.item || itemId;
        const item = shop[resolvedItemId];
        if (item) {
          const set = purchases.get(userId) || new Set();
          set.add(resolvedItemId);
          purchases.set(userId, set);
        }
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ response: { order_id: orderId || params.transaction_id, app_order_id: Date.now() } }));
      return;
    }

    const code = params.product_code || params.code;
    if (!code) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{"status":"ok"}');
      return;
    }
    const item = shop[code];
    if (!item) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{"status":"error","error_code":1001,"error_msg":"Unknown product"}');
      return;
    }
    const userIdFallback = params.uid;
    const set = purchases.get(userIdFallback) || new Set();
    set.add(code);
    purchases.set(userIdFallback, set);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{"status":"ok"}');
    return;
  }
  
  if (req.url === '/vk/pay' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const params = Object.fromEntries(new URLSearchParams(body));
        const appId = String(params.app_id || '');
        const isOK = (params.site === 'OK') || (appId === '512004990432') || (appId === '512005381577');
        if (!isOK) {
          if (!validatePaymentsSig(params)) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: { error_code: 10, error_msg: 'invalid signature', critical: true } }));
            return;
          }
        }
        const type = params.notification_type || '';
        const itemId = params.item;
        const userId = params.user_id;
        const shopItems = VK_SHOP_ITEMS_BY_APP[params.app_id];
        if (!shopItems) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ response: { error: { error_code: 20, error_msg: 'Unknown app_id', critical: true } } }));
          return;
        }

        if (type === 'get_item' || type === 'get_item_test') {
          const item = shopItems[itemId];
          if (!item) { res.writeHead(200); res.end(JSON.stringify({ response: { error: { error_code: 20, error_msg: 'Unknown item', critical: true } } })); return; }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ response: { title: item.title, price: item.price, photo_url: item.photo_url || '', item_id: itemId } }));
          return;
        }

        if (type === 'order_status_change' || type === 'order_status_change_test') {
          if (params.status === 'chargeable') {
            const item = shopItems[itemId];
            if (item) {
              const set = purchases.get(userId) || new Set();
              set.add(itemId);
              purchases.set(userId, set);
            }
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ response: { order_id: params.order_id, app_order_id: Date.now() } }));
          return;
        }

        res.writeHead(200); res.end(JSON.stringify({ response: { error: { error_code: 1, error_msg: 'Unknown notification_type', critical: true } } }));
      } catch (e) {
        res.writeHead(500); res.end();
      }
    });
    return;
  }
  res.writeHead(404); res.end();
});

const wss = new WebSocketServer({ server });

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://x');
  const vkParams = Object.fromEntries(url.searchParams);
  if (!validateVKParams(vkParams)) { ws.close(1008, 'invalid sign'); return; }

  ws.playerId = vkParams.vk_user_id || 'anon_' + Math.random().toString(36).slice(2, 8);
  ws.isAlive = true;
  players.set(ws, { playerId: ws.playerId, roomId: null });
  send(ws, { type: 'welcome', playerId: ws.playerId });

  ws.on('message', raw => {
    let msg; try { msg = JSON.parse(raw); } catch { return; }
    handleMessage(ws, msg);
  });
  ws.on('close', () => { handleLeave(ws); players.delete(ws); });
  ws.on('pong', () => { ws.isAlive = true; });
});

function handleMessage(ws, msg) {
  switch (msg.type) {
    case 'join_queue':   return joinQueue(ws);
    case 'cancel_queue': return cancelQueue(ws);
    case 'join_room':    return joinRoom(ws, msg);
    case 'state':        return relayState(ws, msg);
    case 'garbage':      return relayGarbage(ws, msg);
    case 'game_over':    return handleGameOver(ws, msg);
    case 'leave':        return handleLeave(ws);
    case 'ping':         return send(ws, { type: 'pong', t: msg.t });
    case 'bot_request':  return send(ws, { type: 'bot_ok' });
  }
}

function joinQueue(ws) {
  const player = players.get(ws);
  if (!player || player.roomId) return;
  const idx = waiting.findIndex(w => w.ws === ws);
  if (idx >= 0) waiting.splice(idx, 1);
  if (waiting.length > 0) {
    const opp = waiting.shift();
    const roomId = createRoomId();
    const room = { id: roomId, players: [opp.ws, ws], createdAt: Date.now(), startedAt: Date.now() };
    rooms.set(roomId, room);
    players.get(opp.ws).roomId = roomId;
    player.roomId = roomId;
    send(opp.ws, { type: 'match_found', roomId, opponent: { playerId: ws.playerId }, role: 'p1', target: TARGET_VIRUSES, maxGarbage: MAX_GARBAGE });
    send(ws,     { type: 'match_found', roomId, opponent: { playerId: opp.ws.playerId }, role: 'p2', target: TARGET_VIRUSES, maxGarbage: MAX_GARBAGE });
  } else {
    waiting.push({ ws, playerId: ws.playerId, joinedAt: Date.now() });
    send(ws, { type: 'queue_waiting', waitFor: MATCHMAKING_TIMEOUT });
  }
}

function cancelQueue(ws) {
  const idx = waiting.findIndex(w => w.ws === ws);
  if (idx >= 0) waiting.splice(idx, 1);
  send(ws, { type: 'queue_cancelled' });
}

function joinRoom(ws, msg) {
  const roomId = msg.roomId;
  if (!roomId) return;
  const player = players.get(ws);
  if (!player) return;
  const existing = rooms.get(roomId);
  if (existing && existing.players.length < 2) {
    existing.players.push(ws);
    player.roomId = roomId;
    send(existing.players[0], { type: 'opponent_joined', opponent: { playerId: ws.playerId } });
    send(ws, { type: 'match_found', roomId, opponent: { playerId: existing.players[0].playerId }, role: 'p2', target: TARGET_VIRUSES, maxGarbage: MAX_GARBAGE });
    existing.startedAt = Date.now();
    return;
  }
  const room = { id: roomId, players: [ws], createdAt: Date.now(), startedAt: null };
  rooms.set(roomId, room);
  player.roomId = roomId;
  send(ws, { type: 'room_created', roomId });
}

function relayState(ws, msg) {
  const player = players.get(ws);
  if (!player?.roomId) return;
  const room = rooms.get(player.roomId);
  if (!room) return;
  const other = room.players.find(p => p !== ws);
  if (other) send(other, { type: 'opponent_state', state: msg.state });
}

function relayGarbage(ws, msg) {
  const player = players.get(ws);
  if (!player?.roomId) return;
  const room = rooms.get(player.roomId);
  if (!room) return;
  const other = room.players.find(p => p !== ws);
  const cells = Math.min(Math.max(1, msg.cells | 0), MAX_GARBAGE);
  if (other) send(other, { type: 'garbage_incoming', cells });
}

function handleGameOver(ws, msg) {
  const player = players.get(ws);
  if (!player?.roomId) return;
  const room = rooms.get(player.roomId);
  if (!room) return;
  const other = room.players.find(p => p !== ws);
  if (other) send(other, { type: 'opponent_game_over', winner: ws.playerId, reason: msg.reason });
  setTimeout(() => {
    rooms.delete(room.id);
    for (const p of room.players) {
      const pl = players.get(p);
      if (pl) pl.roomId = null;
    }
  }, 5000);
}

function handleLeave(ws) {
  const player = players.get(ws);
  if (!player) return;
  const idx = waiting.findIndex(w => w.ws === ws);
  if (idx >= 0) waiting.splice(idx, 1);
  if (player.roomId) {
    const room = rooms.get(player.roomId);
    if (room) {
      const other = room.players.find(p => p !== ws);
      if (other) send(other, { type: 'opponent_left' });
      rooms.delete(room.id);
    }
    player.roomId = null;
  }
}

setInterval(() => {
  wss.clients.forEach(ws => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

setInterval(() => {
  const now = Date.now();
  for (let i = waiting.length - 1; i >= 0; i--) {
    if (now - waiting[i].joinedAt > MATCHMAKING_TIMEOUT) {
      send(waiting[i].ws, { type: 'matchmaking_timeout' });
      waiting.splice(i, 1);
    }
  }
}, 5000);

async function buildStatsSummary(period = 'all') {
  let events = [];
  if (pgPool) {
    try {
      const { rows } = await pgPool.query('SELECT payload FROM events ORDER BY t ASC');
      events = rows.map(r => r.payload).filter(e => !isIgnoredPlayer(e.playerId));
    } catch (e) { console.warn('[STATS] DB read failed:', e.message); events = []; }
  } else {
    let lines = [];
    try { lines = fs.readFileSync(STATS_FILE, 'utf8').split(String.fromCharCode(10)).filter(Boolean); } catch { lines = []; }
    for (const line of lines) {
      try {
        const e = JSON.parse(line);
        if (isIgnoredPlayer(e.playerId)) continue;
        events.push(e);
      } catch {}
    }
  }

  const periodSeconds = ({ '1': 86400, '7': 604800, '30': 2592000 })[period];
  if (periodSeconds) {
    const cutoff = Date.now() / 1000 - periodSeconds;
    events = events.filter(event => Number(event.t) > cutoff);
  }

  const apps = { antivirus: [], match3: [], tanks: [], combined: [] };
  for (const e of events) {
    const a = e.app || 'antivirus';
    if (apps[a]) apps[a].push(e);
    apps.combined.push(e); // В общую статистику идет всё
  }

  return {
    combined: processEvents(apps.combined, 30),
    antivirus: processEvents(apps.antivirus, 30),
    match3: processEvents(apps.match3, 100),
    tanks: processEvents(apps.tanks, 30),
    serverTime: Math.floor(Date.now() / 1000)
  };
}

function processEvents(events, maxLevels) {
  const byDay = {};
  const players = new Set();
  const eventCounts = {};
  const levelStart = {};
  const levelEnd = {};
  const levelFail = {};
  const lastScreen = {};
  const screens = {};
  let purchases = 0, adWatched = 0, adFailed = 0;
  let adRewarded = 0, adInterstitial = 0;
  const sessionsByPlayer = {};
  const lastSeen = {};
  const sessions = [];
  const openSessions = new Map();

  for (const e of events) {
    const t = Number(e.t) || 0;
    const d = t ? new Date(t * 1000) : new Date();
    const day = d.toISOString().slice(0, 10);
    byDay[day] = byDay[day] || { players: new Set(), sessions: 0, events: 0 };
    byDay[day].events++;
    if (e.playerId) { players.add(e.playerId); byDay[day].players.add(e.playerId); }

    eventCounts[e.ev] = (eventCounts[e.ev] || 0) + 1;

    if (e.ev === 'session_start') byDay[day].sessions++;
    if (e.ev === 'session_end' && e.duration) {
      (sessionsByPlayer[e.playerId] = sessionsByPlayer[e.playerId] || []).push(e.duration);
    }
    if (e.ev === 'level_start' && e.level != null) levelStart[e.level] = (levelStart[e.level]||0)+1;
    if (e.ev === 'level_end') {
      if (e.won) levelEnd[e.level] = (levelEnd[e.level]||0)+1;
      else       levelFail[e.level] = (levelFail[e.level]||0)+1;
    }
    if (e.ev === 'screen' && e.screen) screens[e.screen] = (screens[e.screen]||0)+1;
    if (e.ev === 'app_close' && e.screen) lastScreen[e.screen] = (lastScreen[e.screen]||0)+1;
    if (e.ev === 'purchase') purchases++;
    
    if (e.ev === 'ad_watch') { 
      if (e.ok) {
        adWatched++;
        if (e.kind === 'rewarded') adRewarded++;
        else if (e.kind === 'interstitial') adInterstitial++;
      } else {
        adFailed++;
      }
    }

    const sessionKey = e.sessionId ? String(e.sessionId) : (e.playerId ? 'p_' + e.playerId : null);
    if (e.ev === 'session_start' && sessionKey) {
      openSessions.set(sessionKey, { playerId: e.playerId, start: t, end: null });
    }
    if (e.ev === 'session_end' && sessionKey) {
      const open = openSessions.get(sessionKey);
      if (open) {
        sessions.push({ start: open.start, end: t, playerId: open.playerId });
        openSessions.delete(sessionKey);
      }
    }
    if (e.playerId && e.ev !== 'session_end' && e.ev !== 'app_close') {
      const previous = lastSeen[e.playerId] || {};
      lastSeen[e.playerId] = {
        t, screen: e.screen || previous.screen || '', mode: e.mode || previous.mode || '', level: e.level ?? previous.level ?? null, platform: e.platform || previous.platform || ''
      };
    }
  }

  const ONLINE_WINDOW = 180;
  for (const [sessionKey, open] of openSessions) {
    sessions.push({ start: open.start, end: open.start + ONLINE_WINDOW, playerId: open.playerId });
    openSessions.delete(sessionKey);
  }

  const allDurations = Object.values(sessionsByPlayer).flat();
  const avgSession = allDurations.length ? Math.round(allDurations.reduce((a,b)=>a+b,0) / allDurations.length) : 0;

  const days = Object.keys(byDay).sort().slice(-30).map(day => ({
    day, players: byDay[day].players.size, sessions: byDay[day].sessions, events: byDay[day].events
  }));

  const nowSec = Math.floor(Date.now() / 1000);
  const onlineNow = [];
  for (const [pid, info] of Object.entries(lastSeen)) {
    const age = Math.max(0, nowSec - info.t);
    if (age <= ONLINE_WINDOW) onlineNow.push({ playerId: pid, lastSeen: info.t, ageSec: age, screen: info.screen, mode: info.mode, level: info.level, platform: info.platform });
  }
  onlineNow.sort((a,b)=>a.ageSec-b.ageSec);

  const historyOnline = [];
  for (let i=59;i>=0;i--) {
    const bucketEnd=nowSec-i*60, bucketStart=bucketEnd-60;
    let count=0;
    for (const session of sessions) {
      const sessionEnd=session.end || (session.start+ONLINE_WINDOW);
      if (session.start<bucketEnd && sessionEnd>bucketStart) count++;
    }
    historyOnline.push({ offsetMin:-i, online:count });
  }

  const timeline = {};
  for (const session of sessions) {
    const sessionEnd=session.end || (session.start+ONLINE_WINDOW);
    if (nowSec-sessionEnd>86400) continue;
    timeline[session.start]=(timeline[session.start]||0)+1;
    timeline[sessionEnd]=(timeline[sessionEnd]||0)-1;
  }
  const timelineKeys=Object.keys(timeline).map(Number).sort((a,b)=>a-b);
  let peak=0,cur=0;
  for (const time of timelineKeys) { cur+=timeline[time]; if(cur>peak)peak=cur; }

  const funnel = [];
  for (let i = 1; i <= maxLevels; i++) {
    funnel.push({ level: i, started: levelStart[i] || 0, won: levelEnd[i] || 0, lost: levelFail[i] || 0 });
  }

  const LOG_EVENTS = new Set(['session_start','level_start','level_end','app_close','purchase','ad_watch','share','level_abandon']);
  const logEvents = events
    .filter(e => LOG_EVENTS.has(e.ev))
    .slice(-150)
    .reverse()
    .map(e => ({
      t: Number(e.t) || 0, ev: e.ev, player: e.playerId || '—', platform: e.platform || '',
      level: e.level ?? null, mode: e.mode || '', won: !!e.won, screen: e.screen || '',
      item: e.item || '', kind: e.kind || '', amount: e.amount ?? null, ok: e.ok === true ? true : (e.ok === false ? false : null)
    }));

  const playerSessions = new Map();
  for(const e of events){
    if(e.ev === 'session_start' && e.playerId){
      playerSessions.set(e.playerId, (playerSessions.get(e.playerId) || 0) + 1);
    }
  }
  const topPlayers = [...playerSessions.entries()].map(([playerId, count]) => ({ playerId, count })).sort((a,b) => b.count - a.count).slice(0, 100);

  return {
    totalEvents: events.length, uniquePlayers: players.size, avgSessionSec: avgSession,
    purchases, adWatched, adFailed, adRewarded, adInterstitial, days, eventCounts, funnel, screens, lastScreen,
    onlineNowCount: onlineNow.length, onlineNow: onlineNow.slice(0,20), onlinePeak24h: peak, historyOnline, recentLog: logEvents, topPlayers
  };
}

function renderStatsDashboard(token) {
  return `<!doctype html><html lang="ru"><head>
<meta charset="utf-8"><title>Антивирус — Статистика</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
*{box-sizing:border-box;}
body{font:13px system-ui,sans-serif;background:#f8fafc;color:#0f172a;margin:0;padding:8px;height:100vh;overflow:hidden;display:flex;flex-direction:column;gap:8px;}
.header{display:flex;justify-content:space-between;align-items:center;background:#fff;padding:6px 12px;border-radius:8px;border:1px solid #e2e8f0;flex-shrink:0;}
.header-left{display:flex;align-items:center;gap:12px;flex-wrap:wrap;}
.header h1{margin:0;font-size:16px;}
#updated{color:#64748b;font-size:11px;}
.tabs{display:flex;gap:4px;}
.tab-btn{padding:4px 10px;border-radius:6px;border:1px solid #cbd5e1;background:#fff;cursor:pointer;font-weight:600;color:#475569;font-size:12px;}
.tab-btn.active{background:#6366f1;color:#fff;border-color:#6366f1;}
.actions{display:flex;gap:8px;}
.cards{display:grid;grid-template-columns:repeat(8,1fr);gap:6px;flex-shrink:0;}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:4px 6px;text-align:center;}
.card b{display:block;font-size:16px;color:#6366f1;line-height:1.1;}
.card.card-online{background:linear-gradient(135deg,#10b981,#059669);color:#fff;border-color:#059669;}
.card.card-online b{color:#fff;font-size:20px;}
.card.card-online small{color:#d1fae5;}
.card small{color:#64748b;font-size:9px;text-transform:uppercase;}
.main-grid{display:grid;grid-template-columns:1fr 2fr;grid-template-rows:minmax(0,1fr) auto;flex:1;min-height:0;gap:8px;}
.col-left{display:flex;flex-direction:column;gap:8px;min-height:0;overflow:hidden;}
.col-right{display:flex;flex-direction:column;gap:8px;min-height:0;overflow:hidden;}
.panel{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:6px 8px;display:flex;flex-direction:column;}
.panel h2{margin:0 0 6px 0;font-size:12px;display:flex;justify-content:space-between;color:#334155;}
.tbl-wrap{height:150px;overflow-y:auto;}
#logPanel{flex:1;min-height:0;}.log-wrap{flex:1;min-height:80px;overflow-y:auto;font-family:'SF Mono','Consolas',monospace;font-size:11px;line-height:1.4;background:#0f172a;color:#e2e8f0;border-radius:4px;padding:4px 8px;}
#funnelPanel{flex:1;min-height:0;}.chart-wrap{flex:1;min-height:90px;height:auto;position:relative;overflow-x:hidden;overflow-y:hidden;width:100%;}.chart-wrap canvas{display:block;}
.panel.bottom{grid-column:span 2;flex-direction:row;align-items:center;justify-content:space-between;padding:4px 12px;}
.panel.bottom h2{margin:0;white-space:nowrap;}
.ads-wrap{display:flex;gap:8px;font-size:11px;font-weight:600;width:100%;}.ad-card{flex:1;min-width:0;padding:3px 8px;border-radius:6px;color:#fff;text-align:center;}.ad-card b{display:inline-block;font-size:13px;margin-left:6px;}.ad-rewarded{background:#16a34a;}.ad-interstitial{background:#2563eb;}.ad-failed{background:#dc2626;}.period-filters{display:flex;align-items:center;gap:4px;flex-wrap:wrap;}.period-btn.active{background:#6366f1;color:#fff;border-color:#6366f1;}
table{width:100%;border-collapse:collapse;font-size:11px;}
th,td{padding:2px 6px;text-align:left;border-bottom:1px solid #e2e8f0;}
th{background:#f1f5f9;font-weight:700;font-size:10px;text-transform:uppercase;color:#475569;position:sticky;top:0;z-index:1;}
tr:last-child td{border-bottom:none;}
.log-line{display:flex;gap:6px;padding:1px 0;border-bottom:1px solid rgba(255,255,255,.04);}
.log-time{color:#64748b;flex-shrink:0;min-width:40px;}
.log-player{color:#94a3b8;flex-shrink:0;min-width:80px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.log-text{color:#e2e8f0;flex:1;}
.log-text.good{color:#86efac;}.log-text.bad{color:#fca5a5;}.log-text.warn{color:#fcd34d;}.log-text.pay{color:#c4b5fd;}
.expand-btn{font-size:10px;padding:1px 6px;border:1px solid #cbd5e1;border-radius:4px;background:#f1f5f9;cursor:pointer;font-weight:600;color:#334155;}
.expand-btn:hover{background:#e2e8f0;}
.panel.expanded{position:fixed;inset:10px;z-index:1000;padding:16px;box-shadow:0 0 0 100vmax rgba(0,0,0,.5);height:auto;}
.panel.expanded .chart-wrap{height:calc(100vh - 80px);}
.panel.expanded .log-wrap, .panel.expanded .tbl-wrap{height:calc(100vh - 80px);}
.player-history-overlay{position:fixed;inset:0;z-index:2000;background:rgba(15,23,42,.65);display:flex;align-items:center;justify-content:center;padding:16px;}
.player-history-dialog{width:min(720px,100%);max-height:85vh;background:#fff;border-radius:12px;padding:16px;display:flex;flex-direction:column;gap:10px;}
.player-history-dialog h2{font-size:16px;margin:0;}
.player-history-events{overflow:auto;white-space:pre-wrap;font:12px/1.6 'SF Mono','Consolas',monospace;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:10px;}
.player-history-exit{color:#dc2626;font-weight:700;}
@media(max-width:760px){body{height:auto;overflow-y:auto;}.cards{grid-template-columns:repeat(4,1fr)}.main-grid{grid-template-columns:1fr;grid-template-rows:auto;flex:none;}.panel.bottom{grid-column:auto;}.log-wrap{height:300px;flex:none;}#funnelPanel{flex:none;}.chart-wrap{height:140px;flex:none;}}
</style></head><body>

<div class="header">
  <div class="header-left">
    <h1 id="pageTitle">Антивирус — Статистика</h1>
    <span id="updated"></span>
    <div class="tabs">
      <button class="tab-btn active" onclick="switchTab('combined', this)">Общая</button>
      <button class="tab-btn" onclick="switchTab('antivirus', this)">Антивирус</button>
      <button class="tab-btn" onclick="switchTab('match3', this)">Match-3</button>
      <button class="tab-btn" onclick="switchTab('tanks', this)">Танки</button>
    </div>
    <div class="period-filters" aria-label="Период статистики">
      <button class="tab-btn period-btn" data-period="1" onclick="setPeriod('1')">1 день</button>
      <button class="tab-btn period-btn" data-period="7" onclick="setPeriod('7')">7 дней</button>
      <button class="tab-btn period-btn" data-period="30" onclick="setPeriod('30')">30 дней</button>
      <button class="tab-btn period-btn active" data-period="all" onclick="setPeriod('all')">Всё время</button>
    </div>
  </div>
  <div class="actions">
    <button onclick="copyJson()" class="expand-btn" style="color:#334155;">📋 JSON</button>
    <button onclick="confirmReset()" class="expand-btn" style="color:#ef4444;border-color:#fca5a5;">🗑 Стереть</button>
  </div>
</div>

<div class="cards" id="cards"></div>

<div class="main-grid">
  <div class="col-left">
    <div class="panel">
      <h2>Активные <span id="onlineCount" style="font-size:10px;color:#64748b"></span></h2>
      <div class="tbl-wrap"><table id="tblOnline"></table></div>
    </div>
    <div class="panel" id="funnelPanel">
      <h2>Воронка по уровням <button class="expand-btn" onclick="toggleFullscreen('funnelPanel')">⛶</button></h2>
      <div class="chart-wrap"><canvas id="chFunnel" width="800" height="160"></canvas></div>
    </div>
  </div>
  <div class="col-right">
    <div class="panel" id="logPanel">
      <h2>Живой лог <button class="expand-btn" onclick="toggleFullscreen('logPanel')">⛶</button></h2>
      <div class="log-wrap" id="logBox"></div>
    </div>
    <div class="panel" id="topPlayersPanel">
      <h2>Топ игроков <button class="expand-btn" onclick="toggleFullscreen('topPlayersPanel')">⛶</button></h2>
      <div class="tbl-wrap" id="topPlayersBox"></div>
    </div>
  </div>
  <div class="panel bottom">
    <h2>Реклама</h2>
    <div class="ads-wrap" id="tblAds"></div>
  </div>
</div>

<script>
const TOKEN = ${JSON.stringify(token)};
let _lastData = null;
let currentTab = 'combined';
let currentPeriod = 'all';
const SCREEN_NAMES = {
  'welcome':'Приветствие','story':'Сюжет','menu':'Меню','levels':'Выбор ур.',
  'game':'Игра','pause':'Пауза','end':'Конец ур.','shop':'Магазин',
  'daily':'Бонус','settings':'Настройки','records':'Рекорды','duel':'Дуэль',
  'boot':'Загрузка'
};
function ruScreen(key){ return key ? (SCREEN_NAMES[key] || key) : '—'; }

function switchTab(tab, btn) {
  currentTab = tab;
  document.querySelectorAll('.tabs .tab-btn').forEach(b => b.classList.remove('active'));
  if(btn) btn.classList.add('active');
  if(_lastData) renderAll();
}

function setPeriod(period) {
  currentPeriod = period;
  document.querySelectorAll('[data-period]').forEach(button => button.classList.toggle('active', button.dataset.period === currentPeriod));
  refresh();
}

async function refresh(){
  try{
    const r=await fetch('/stats/data?token='+encodeURIComponent(TOKEN)+'&period='+encodeURIComponent(currentPeriod));
    if(!r.ok){document.body.innerHTML='<h1>403 — неверный токен</h1>';return;}
    const d=await r.json();
    _lastData=d;
    document.getElementById('updated').textContent='Обновлено: '+new Date().toLocaleString();
    renderAll();
  }catch(e){console.warn('refresh fail',e);}
}
refresh();
setInterval(refresh,30000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh();});

function renderAll() {
  const d = _lastData[currentTab];
  renderCards(d);
  renderCharts(d);
  renderTables(d);
  renderLog(d);
  renderTopPlayers(d);
}

function renderCards(d){
  const c = document.getElementById('cards');
  const items = [
    ['Онлайн',     d.onlineNowCount, true],
    ['Пик 24ч',    d.onlinePeak24h,  false],
    ['Игроков',    d.uniquePlayers,  false],
    ['Событий',    d.totalEvents,    false],
    ['Ср. сессия', d.avgSessionSec ? Math.round(d.avgSessionSec/60) + ' мин' : '—', false],
    ['Покупок',    d.purchases,      false],
    ['Реклам OK',  d.adWatched,      false],
    ['Реклама ✗',  d.adFailed,       false]
  ];
  c.innerHTML = items.map(([t,v,hl]) =>
    '<div class="card'+(hl?' card-online':'')+'"><b>'+v+'</b><small>'+t+'</small></div>'
  ).join('');

  const ads = document.getElementById('tblAds');
  const rewarded = d.adRewarded || 0;
  const interstitial = d.adInterstitial || 0;
  const failed = d.adFailed || 0;
  ads.innerHTML = '<div class="ad-card ad-rewarded">Rewarded<b>'+rewarded+'</b></div>'
    + '<div class="ad-card ad-interstitial">Interstitial<b>'+interstitial+'</b></div>'
    + '<div class="ad-card ad-failed">Ошибки<b>'+failed+'</b></div>';
}

let charts = {};
function renderCharts(d){
  if(charts.funnel) charts.funnel.destroy();
  const cv = document.getElementById('chFunnel');
  if(!cv) return;
  
  charts.funnel = new Chart(cv, {
    type:'bar',
    data:{ labels: d.funnel.map(x=>'Ур.'+x.level), datasets:[
      { label:'Начали',    data: d.funnel.map(x=>x.started), backgroundColor:'#94a3b8' },
      { label:'Прошли',    data: d.funnel.map(x=>x.won),     backgroundColor:'#10b981' },
      { label:'Проиграли', data: d.funnel.map(x=>x.lost),    backgroundColor:'#ef4444' }
    ]},
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{ legend:{labels:{boxWidth:10,font:{size:12}}} },
      scales:{ x:{stacked:true,ticks:{font:{size:12},maxRotation:60,minRotation:60}}, y:{stacked:true,ticks:{font:{size:12}},beginAtZero:true} }
    }
  });
}

function renderTables(d){
  function esc(s){ return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
  const t3 = document.getElementById('tblOnline');
  document.getElementById('onlineCount').textContent = d.onlineNowCount + ' чел.';
  if(!t3) return;
  const rows = (d.onlineNow || []).slice().sort((a,b)=>a.ageSec-b.ageSec);
  if(rows.length === 0){
    t3.innerHTML = '<tr><td style="color:#64748b">Никого</td></tr>';
  } else {
    t3.innerHTML = '<tr><th>Игрок</th><th>Пл.</th><th>Экран</th><th>Ур.</th><th>Тишина</th></tr>'
      + rows.map(r=>'<tr><td><a href="#" data-player-id="'+esc(r.playerId)+'" style="color:#6366f1;text-decoration:underline">'+esc(r.playerId)+'</a></td><td>'+esc(r.platform||'—')+'</td><td>'+esc(ruScreen(r.screen))+'</td><td>'+esc(r.level??'—')+'</td><td>'+r.ageSec+'с</td></tr>').join('');
  }
}

function renderTopPlayers(d){
  const box = document.getElementById('topPlayersBox');
  if(!box) return;
  const rows = d.topPlayers || [];
  if(rows.length === 0){
    box.innerHTML = '<div style="color:#64748b;font-size:11px;padding:6px">Пока никого</div>';
    return;
  }
  box.innerHTML = '<table><tr><th style="width:30px">#</th><th>Игрок</th><th style="width:60px">Заходов</th></tr>'
    + rows.map((r,i) => '<tr><td>'+(i+1)+'</td><td><a href="#" data-player-id="'+String(r.playerId).replace(/"/g,'&quot;')+'" style="color:#6366f1;text-decoration:underline">'+String(r.playerId).replace(/</g,'&lt;')+'</a></td><td><b>'+r.count+'</b></td></tr>').join('') + '</table>';
}

function renderLog(d){
  const box = document.getElementById('logBox');
  if(!box) return;
  const rows = d.recentLog || [];
  if(rows.length === 0){
    box.innerHTML = '<div class="log-line"><span class="log-text" style="color:#64748b">Пока пусто</span></div>';
    return;
  }
  const now = _lastData.serverTime || Math.floor(Date.now()/1000);
  function esc(s){ return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
  function fmtTime(t){
    const dt = Math.max(0, now - t);
    if(dt < 60) return dt + 'с';
    if(dt < 3600) return Math.floor(dt/60) + 'м';
    if(dt < 86400) return Math.floor(dt/3600) + 'ч';
    return new Date(t*1000).toLocaleDateString('ru-RU',{day:'2-digit',month:'2-digit'}) + ' ' + new Date(t*1000).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'});
  }
  function fmtText(r){
    const lvl = r.level ? (' ур.' + r.level) : '';
    switch(r.ev){
      case 'session_start':  return 'вошёл в игру';
      case 'level_start':    return 'начал' + (r.mode === 'endless' ? ' бесконечную' : lvl);
      case 'level_end':      return r.won ? ('прошёл' + lvl) : ('проиграл' + lvl);
      case 'level_abandon':  return 'вышел с' + lvl;
      case 'app_close':      return 'вышел (экран: ' + (ruScreen(r.screen) || '—') + ')';
      case 'purchase':       return 'купил: ' + (r.item || 'товар') + (r.amount ? ' (' + r.amount + ')' : '');
      case 'ad_watch':       return 'реклама ' + (r.kind || '') + ' — ' + (r.ok ? 'ОК' : 'провал');
      case 'share':          return 'поделился';
      default:               return r.ev;
    }
  }
  function fmtClass(r){
    if(r.ev === 'level_end') return r.won ? 'good' : 'bad';
    if(r.ev === 'ad_watch')  return r.ok ? 'good' : 'warn';
    if(r.ev === 'purchase')  return 'pay';
    if(r.ev === 'app_close') return 'warn';
    return '';
  }
  box.innerHTML = rows.map(r => 
    '<div class="log-line">' + 
      '<span class="log-time">' + fmtTime(r.t) + '</span>' + 
      '<span class="log-player">' + esc(r.player) + '</span>' + 
      '<span class="log-text ' + fmtClass(r) + '">' + esc(fmtText(r)) + '</span>' + 
    '</div>'
  ).join('');
}

function toggleFullscreen(id) {
  const el = document.getElementById(id);
  if(!el) return;
  el.classList.toggle('expanded');
  const btn = el.querySelector('.expand-btn');
  if(btn) btn.textContent = el.classList.contains('expanded') ? '✕ Закрыть' : '⛶';
  if(el.classList.contains('expanded')) {
    document.body.style.overflow = 'hidden';
    if(id === 'funnelPanel' && charts.funnel) setTimeout(()=>charts.funnel.resize(), 50);
  } else {
    document.body.style.overflow = '';
    if(id === 'funnelPanel' && charts.funnel) setTimeout(()=>charts.funnel.resize(), 50);
  }
}

async function showPlayerHistory(id){
  let events;
  try{const response=await fetch('/stats/player?id='+encodeURIComponent(id)+'&token='+encodeURIComponent(TOKEN));if(!response.ok)throw new Error('HTTP '+response.status);events=await response.json();}
  catch(error){alert('Не удалось загрузить историю игрока: '+error);return;}
  const overlay=document.createElement('div');overlay.className='player-history-overlay';
  const dialog=document.createElement('div');dialog.className='player-history-dialog';
  const title=document.createElement('h2');title.textContent='История игрока: '+id;
  const list=document.createElement('div');list.className='player-history-events';
  if(!Array.isArray(events)||events.length===0)list.textContent='Событий нет';
  else events.forEach(function(event){
    const name=event.ev||event.event||event.name||'unknown';
    const t=Number(event.t)||0;const time=t?new Date(t*1000).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit',second:'2-digit'}):'--:--:--';
    const details=[];if(event.level!=null)details.push('ур. '+event.level);if(event.mode)details.push(String(event.mode));if(event.screen)details.push(ruScreen(event.screen));
    const line=document.createElement('div');line.textContent='['+time+'] '+name+(details.length?' ('+details.join('/')+')':'');
    if(name==='session_end'||name==='app_close'){line.className='player-history-exit';line.textContent+=' — ВЫХОД';}list.appendChild(line);
  });
  const close=document.createElement('button');close.className='expand-btn';close.style.float='none';close.textContent='Закрыть';close.addEventListener('click',function(){overlay.remove();});
  dialog.appendChild(title);dialog.appendChild(list);dialog.appendChild(close);overlay.appendChild(dialog);document.body.appendChild(overlay);
}

document.addEventListener('click',function(event){
  const link=event.target.closest('a[data-player-id]');
  if(!link)return;
  event.preventDefault();
  showPlayerHistory(link.dataset.playerId);
});

function copyJson(){if(!_lastData)return;navigator.clipboard.writeText(JSON.stringify(_lastData,null,2)).then(function(){alert('JSON скопирован в буфер обмена!');}).catch(function(error){alert('Ошибка копирования: '+error);});}
function confirmReset(){if(confirm('Вы уверены, что хотите ПОЛНОСТЬЮ стереть статистику? Это действие необратимо.')){fetch('/stats/reset?token='+encodeURIComponent(TOKEN)).then(function(response){return response.text();}).then(function(){alert('Статистика очищена!');location.reload();}).catch(function(){alert('Ошибка при очистке');});}}
</script>
</body></html>`;
}

initStatsTable().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
    console.log('🚀 [BOOT] Сервер запущен (4 вкладки, страница скроллится)');
  });
}).catch(e => {
  console.error('[BOOT] init failed:', e);
  server.listen(PORT, '0.0.0.0', () => {
    console.log('🚀 [BOOT] Сервер запущен (без БД)');
  });
});