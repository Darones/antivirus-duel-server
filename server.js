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
    // Migrate events.jsonl once when the database is empty.
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

// [PAYMENTS] Товары (id должны совпадать с SHOP_ITEMS в index.html)
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
// [PAYMENTS] Хранилище покупок: userId → Set(itemId)
const purchases = new Map();

function validateOKSig(params, secretOverride) {
  const secret = secretOverride || OK_APP_SECRET;
  if (!secret) return true;
  const { sig, access_token, ...rest } = params;
  if (!sig) return false;
  const secretKey = crypto.createHash('md5').update((access_token || '') + secret).digest('hex');
  const sorted = Object.keys(rest).sort().map(k => `${k}=${rest[k]}`).join('&');
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
  // POST /stats/event — приём батча событий от клиента
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

  // GET /stats/reset?token=XXX — очистить events.jsonl
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

  // GET /stats/player?id=XXX&token=XXX
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

  // GET /stats/data?token=XXX — сводка в JSON
  if (req.url.startsWith('/stats/data')) {
    (async () => {
      const urlObj = new URL(req.url, 'http://x');
      const token = urlObj.searchParams.get('token') || '';
      if (token !== STATS_TOKEN) { res.writeHead(403); res.end('forbidden'); return; }
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      // Возвращаем сводку сразу для всех игр (antivirus и match3)
      const summary = await buildStatsSummary();
      res.end(JSON.stringify(summary));
    })().catch(e => { console.error('[STATS/data]', e); res.writeHead(500); res.end('error'); });
    return;
  }

  // GET /stats/dashboard?token=XXX — HTML-страница с графиками
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
  // [PAYMENTS] Обработка платёжных уведомлений ОК (GET-запрос)
  if (req.url.startsWith('/ok/pay')) {
    const urlObj = new URL(req.url, 'http://x');
    const params = Object.fromEntries(urlObj.searchParams);
    console.log('[OK-PAY-RAW]', JSON.stringify(params));
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
      console.log('[OK-PAY] OK request — sig check skipped');
    } else if (okSecret) {
      const { sig, access_token, ...rest } = params;
      if (sig) {
        const secretKey = crypto.createHash('md5').update((access_token || '') + okSecret).digest('hex');
        const sorted = Object.keys(rest).sort().map(k => k + '=' + rest[k]).join('&');
        const expected = crypto.createHash('md5').update(sorted + secretKey).digest('hex');
        if (expected !== sig) {
          console.warn('[OK-PAY] invalid sig');
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
  // [PAYMENTS] Обработка платёжных уведомлений VK
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
        console.error('[PAY] error:', e.message);
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

async function buildStatsSummary() {
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

  const apps = { antivirus: [], match3: [], combined: events };

  for (const e of events) {
    const a = e.app || 'antivirus';
    if (apps[a]) apps[a].push(e);
  }

  const result = {
    combined: processEvents(apps.combined, 30),
    antivirus: processEvents(apps.antivirus, 30),
    match3: processEvents(apps.match3, 100),
    serverTime: Math.floor(Date.now() / 1000)
  };
  return result;
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
        t,
        screen: e.screen || previous.screen || '',
        mode: e.mode || previous.mode || '',
        level: e.level ?? previous.level ?? null,
        platform: e.platform || previous.platform || ''
      };
    }
  }

  const ONLINE_WINDOW = 180;
  for (const [sessionKey, open] of openSessions) {
    sessions.push({ start: open.start, end: open.start + ONLINE_WINDOW, playerId: open.playerId });
    openSessions.delete(sessionKey);
  }

  const allDurations = Object.values(sessionsByPlayer).flat();
  const avgSession = allDurations.length
    ? Math.round(allDurations.reduce((a,b)=>a+b,0) / allDurations.length)
    : 0;

  const days = Object.keys(byDay).sort().slice(-30).map(day => ({
    day,
    players: byDay[day].players.size,
    sessions: byDay[day].sessions,
    events: byDay[day].events
  }));

  const nowSec = Math.floor(Date.now() / 1000);
  const onlineNow = [];
  for (const [pid, info] of Object.entries(lastSeen)) {
    const age = nowSec - info.t;
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
    funnel.push({
      level: i,
      started: levelStart[i] || 0,
      won: levelEnd[i] || 0,
      lost: levelFail[i] || 0
    });
  }

  const LOG_EVENTS = new Set(['session_start','level_start','level_end','app_close','purchase','ad_watch','share','level_abandon']);
  const logEvents = events
    .filter(e => LOG_EVENTS.has(e.ev))
    .slice(-150)
    .reverse()
    .map(e => ({
      t: Number(e.t) || 0,
      ev: e.ev,
      player: e.playerId || '—',
      platform: e.platform || '',
      level: e.level ?? null,
      mode: e.mode || '',
      won: !!e.won,
      screen: e.screen || '',
      item: e.item || '',
      kind: e.kind || '',
      amount: e.amount ?? null,
      ok: e.ok === true ? true : (e.ok === false ? false : null)
    }));

  const playerSessions = new Map();
  for(const e of events){
    if(e.ev === 'session_start' && e.playerId){
      playerSessions.set(e.playerId, (playerSessions.get(e.playerId) || 0) + 1);
    }
  }
  const topPlayers = [...playerSessions.entries()]
    .map(([playerId, count]) => ({ playerId, count }))
    .sort((a,b) => b.count - a.count)
    .slice(0, 100);

  return {
    totalEvents: events.length,
    uniquePlayers: players.size,
    avgSessionSec: avgSession,
    purchases,
    adWatched,
    adFailed,
    adRewarded,
    adInterstitial,
    days,
    eventCounts,
    funnel,
    screens,
    lastScreen,
    onlineNowCount: onlineNow.length,
    onlineNow: onlineNow.slice(0,20),
    onlinePeak24h: peak,
    historyOnline,
    recentLog: logEvents,
    topPlayers
  };
}

function renderStatsDashboard(token) {
  return `<!doctype html><html lang="ru"><head>
<meta charset="utf-8"><title>Антивирус — Статистика</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body{font:13px system-ui,sans-serif;background:#f8fafc;color:#0f172a;margin:0;padding:10px;overflow:hidden}
h1{margin:0 0 4px;font-size:18px}
h2{font-size:13px;margin:0 0 4px;color:#334155;font-weight:700;display:flex;justify-content:space-between;align-items:center}
.tabs{display:flex;gap:6px;margin-bottom:10px}
.tab-btn{padding:6px 16px;border-radius:8px;border:1px solid #cbd5e1;background:#fff;cursor:pointer;font-weight:600;color:#475569}
.tab-btn.active{background:#6366f1;color:#fff;border-color:#6366f1}
.cards{display:grid;grid-template-columns:repeat(8,1fr);gap:6px;margin:6px 0 10px}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:6px 8px;text-align:center}
.card b{display:block;font-size:20px;color:#6366f1;line-height:1.1}
.card.card-online{background:linear-gradient(135deg,#10b981,#059669);color:#fff;border-color:#059669}
.card.card-online b{color:#fff;font-size:26px}
.card.card-online small{color:#d1fae5}
.card small{color:#64748b;font-size:10px}
.panels{display:grid;grid-template-columns:minmax(240px,1fr) 1.6fr;gap:10px;align-items:start}
.panel{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:8px;transition:all 0.2s}
.panel.fullscreen{position:fixed;inset:10px;z-index:1000;overflow:auto}
table{width:100%;border-collapse:collapse;font-size:11px}
th,td{padding:3px 6px;text-align:left;border-bottom:1px solid #e2e8f0}
th{background:#f1f5f9;font-weight:700;font-size:10px;text-transform:uppercase;letter-spacing:.3px;color:#475569;position:sticky;top:0}
tr:last-child td{border-bottom:none}
.tbl-scroll{max-height:200px;overflow-y:auto}
.funnel-wrap{position:relative;height:320px;width:100%}
.panel.fullscreen .funnel-wrap{height:calc(100vh - 100px)}
.log-scroll{max-height:260px;overflow-y:auto;font-family:'SF Mono','Consolas',monospace;font-size:11.5px;line-height:1.5;background:#0f172a;color:#e2e8f0;border-radius:6px;padding:6px 10px}
.panel.fullscreen .log-scroll{max-height:calc(100vh - 100px)}
.log-line{display:flex;gap:8px;padding:1px 0;border-bottom:1px solid rgba(255,255,255,.04)}
.log-line:last-child{border-bottom:none}
.log-time{color:#64748b;flex-shrink:0;min-width:52px}
.log-player{color:#94a3b8;flex-shrink:0;min-width:90px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.log-text{color:#e2e8f0;flex:1}
.log-text.good{color:#86efac}.log-text.bad{color:#fca5a5}.log-text.warn{color:#fcd34d}.log-text.pay{color:#c4b5fd}
.expand-btn{font-size:11px;padding:2px 10px;border:1px solid #cbd5e1;border-radius:6px;background:#f1f5f9;cursor:pointer;font-weight:600;color:#334155}
.expand-btn:hover{background:#e2e8f0}
.player-history-overlay{position:fixed;inset:0;z-index:2000;background:rgba(15,23,42,.65);display:flex;align-items:center;justify-content:center;padding:16px}
.player-history-dialog{width:min(720px,100%);max-height:85vh;background:#fff;border-radius:12px;padding:16px;display:flex;flex-direction:column;gap:10px;box-shadow:0 20px 60px rgba(0,0,0,.25)}
.player-history-dialog h2{font-size:16px;margin:0}
.player-history-events{overflow:auto;white-space:pre-wrap;font:12px/1.6 'SF Mono','Consolas',monospace;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:10px}
.player-history-exit{color:#dc2626;font-weight:700}
@media(max-width:760px){.cards{grid-template-columns:repeat(4,1fr)}.panels{grid-template-columns:1fr}}
</style></head><body>

<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
  <h1 id="pageTitle">Антивирус — Статистика</h1>
  <div style="display:flex;gap:10px;">
    <button onclick="copyJson()" class="expand-btn" style="color:#334155;">📋 Скопировать JSON</button>
    <button onclick="confirmReset()" class="expand-btn" style="color:#ef4444;border-color:#fca5a5;">🗑 Стереть</button>
  </div>
</div>
<p id="updated" style="color:#64748b;font-size:11px;margin:0 0 10px"></p>

<div class="tabs">
  <button class="tab-btn active" onclick="switchTab('combined')">Общая статистика</button>
  <button class="tab-btn" onclick="switchTab('antivirus')">Антивирус (Dr. Mario)</button>
  <button class="tab-btn" onclick="switchTab('match3')">Три в ряд (Match-3)</button>
</div>

<div class="cards" id="cards"></div>

<div class="panels">
  <div class="panel">
    <h2>Активные сейчас <span id="onlineCount" style="font-size:11px;color:#64748b"></span></h2>
    <div class="tbl-scroll" style="max-height:150px"><table id="tblOnline"></table></div>
  </div>
  
  <div class="panel" id="funnelPanel" style="grid-row:span 2">
    <h2>Воронка по уровням <button class="expand-btn" onclick="toggleFullscreen('funnelPanel')">⛶ Развернуть</button></h2>
    <div class="funnel-wrap"><canvas id="chFunnel"></canvas></div>
  </div>

  <div class="panel">
    <h2>Реклама <span id="adSummary" style="font-size:11px;color:#64748b"></span></h2>
    <table id="tblAds"></table>
  </div>

  <div class="panel" id="logPanel" style="grid-column:1/-1">
    <h2>Живой лог <button class="expand-btn" onclick="toggleFullscreen('logPanel')">⛶ Развернуть</button></h2>
    <div class="log-scroll" id="logBox"></div>
  </div>

  <div class="panel" id="topPlayersPanel" style="grid-column:1/-1">
    <h2>Топ игроков по заходам <button class="expand-btn" onclick="toggleFullscreen('topPlayersPanel')">⛶ Развернуть</button></h2>
    <div class="tbl-scroll" style="max-height:200px" id="topPlayersBox"></div>
  </div>
</div>

<script>
const TOKEN = ${JSON.stringify(token)};
let _lastData = null;
let currentTab = 'combined';
const SCREEN_NAMES = {
  'welcome':'Приветствие','story':'Сюжет','menu':'Меню','levels':'Выбор ур.',
  'game':'Игра','pause':'Пауза','end':'Конец ур.','shop':'Магазин',
  'daily':'Бонус','settings':'Настройки','records':'Рекорды','duel':'Дуэль',
  'boot':'Загрузка'
};
function ruScreen(key){ return key ? (SCREEN_NAMES[key] || key) : '—'; }

function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  event.target.classList.add('active');
  if(_lastData) renderAll();
}

async function refresh(){
  try{
    const r=await fetch('/stats/data?token='+encodeURIComponent(TOKEN));
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
  document.getElementById('pageTitle').textContent = 
    currentTab === 'combined' ? 'Общая статистика' : 
    currentTab === 'antivirus' ? 'Антивирус (Dr. Mario)' : 'Три в ряд (Match-3)';
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
    ['Всего реклам', d.adWatched,    false],
    ['Реклама ✗',  d.adFailed,       false]
  ];
  c.innerHTML = items.map(([t,v,hl]) =>
    '<div class="card'+(hl?' card-online':'')+'"><b>'+v+'</b><small>'+t+'</small></div>'
  ).join('');

  // Реклама
  const ads = document.getElementById('tblAds');
  const rewarded = d.adRewarded || 0;
  const inter = d.adInterstitial || 0;
  const total = rewarded + inter;
  document.getElementById('adSummary').textContent = 'Всего: ' + total;
  ads.innerHTML = `
    <tr><th>Тип</th><th>Показов</th><th>Доля</th></tr>
    <tr><td>Rewarded (за награду)</td><td>${rewarded}</td><td>${total ? Math.round(rewarded/total*100) : 0}%</td></tr>
    <tr><td>Interstitial (между)</td><td>${inter}</td><td>${total ? Math.round(inter/total*100) : 0}%</td></tr>
    <tr><td style="color:#ef4444">Ошибки/пропуски</td><td>${d.adFailed}</td><td>—</td></tr>
  `;
}

let charts = {};
function renderCharts(d){
  if(charts.funnel) charts.funnel.destroy();
  const cv = document.getElementById('chFunnel');
  if(!cv) return;
  
  const labels = d.funnel.map(x=>'Ур.'+x.level);
  const startedData = d.funnel.map(x=>x.started);
  const wonData = d.funnel.map(x=>x.won);
  const lostData = d.funnel.map(x=>x.lost);

  charts.funnel = new Chart(cv, {
    type:'bar',
    data:{ labels: labels, datasets:[
      { label:'Начали',    data: startedData, backgroundColor:'#94a3b8' },
      { label:'Прошли',    data: wonData,     backgroundColor:'#10b981' },
      { label:'Проиграли', data: lostData,    backgroundColor:'#ef4444' }
    ]},
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{ legend:{labels:{boxWidth:8,font:{size:9}}} },
      scales:{ 
        x:{stacked:true,ticks:{font:{size:7},maxRotation:60,minRotation:60}}, 
        y:{stacked:true,ticks:{font:{size:8}},beginAtZero:true} 
      }
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
    t3.innerHTML = '<tr><td style="color:#64748b">Никого — все ушли</td></tr>';
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
  box.innerHTML = '<table><tr><th style="width:40px">#</th><th>Игрок</th><th style="width:90px">Заходов</th></tr>'
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
    const dt = now - t;
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
  box.innerHTML = rows.map(r => '<div class="log-line"><span class="log-time">' + fmtTime(r.t) + '</span><span class="log-player">' + esc(r.player) + '</span><span class="log-text ' + fmtClass(r) + '">' + esc(fmtText(r)) + '</span></div>').join('');
}

function toggleFullscreen(id) {
  const el = document.getElementById(id);
  if(el) el.classList.toggle('fullscreen');
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
    console.log('🚀 [BOOT] Сервер запущен (Табы дашборда, 2 воронки, Реклама, Фиксы UI)');
    console.log('   Health: http://0.0.0.0:' + PORT + '/health');
    console.log('   Stats: ' + (pgPool ? 'Postgres' : 'file (no DATABASE_URL)'));
  });
}).catch(e => {
  console.error('[BOOT] init failed:', e);
  server.listen(PORT, '0.0.0.0', () => {
    console.log('🚀 [BOOT] Сервер запущен (без БД)');
  });
});