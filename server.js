'use strict';
const http = require('http');
const { WebSocketServer } = require('ws');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const STATS_FILE = path.join(__dirname, 'events.jsonl');

// ID, которые скрыты из статистики
const IGNORED_PLAYER_IDS = new Set(['29506969']);
function isIgnoredPlayer(playerId){
  if(!playerId) return false;
  const idStr = String(playerId);
  // Фильтр anon_ отключен для продакшена (фиксируем всех)
  return IGNORED_PLAYER_IDS.has(idStr);
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
  coins_small:    { title: '5 000 монет',   price: 5,  photo_url: 'https://darones.github.io/antivirus/logo.png' },
  coins_medium:   { title: '15 000 монет',  price: 10, photo_url: 'https://darones.github.io/antivirus/logo.png' },
  coins_large:    { title: '40 000 монет',  price: 20, photo_url: 'https://darones.github.io/antivirus/logo.png' },
  starter_pack:   { title: 'Стартовый набор', price: 10, photo_url: 'https://darones.github.io/antivirus/logo.png' },
};
const TANKS_SHOP_ITEMS = {
  tanks_coins_small:  { title: '10 000 монет', price: 5,  photo_url: 'https://raw.githubusercontent.com/Darones/assets/main/coin.png' },
  tanks_coins_medium: { title: '25 000 монет', price: 10, photo_url: 'https://raw.githubusercontent.com/Darones/assets/main/coin.png' },
  tanks_coins_large:  { title: '60 000 монет', price: 20, photo_url: 'https://raw.githubusercontent.com/Darones/assets/main/coin.png' },
  tanks_weapon_mg:     { title: '\u041f\u0443\u043b\u0435\u043c\u0451\u0442', price: 1, photo_url: 'https://raw.githubusercontent.com/Darones/assets/main/weapon.png' },
  tanks_weapon_sniper: { title: '\u0421\u043d\u0430\u0439\u043f\u0435\u0440\u043a\u0430', price: 2, photo_url: 'https://raw.githubusercontent.com/Darones/assets/main/weapon.png' },
  tanks_weapon_flame:  { title: '\u041e\u0433\u043d\u0435\u043c\u0451\u0442', price: 2, photo_url: 'https://raw.githubusercontent.com/Darones/assets/main/weapon.png' },
  tanks_weapon_rocket: { title: '\u0420\u0430\u043a\u0435\u0442\u043d\u0438\u0446\u0430', price: 3, photo_url: 'https://raw.githubusercontent.com/Darones/assets/main/weapon.png' },
  tanks_weapon_laser:  { title: '\u041b\u0430\u0437\u0435\u0440', price: 5, photo_url: 'https://raw.githubusercontent.com/Darones/assets/main/weapon.png' },
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
        const events = rawEvents;
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

  if (req.url.startsWith('/stats/raw')) {
    (async () => {
      const urlObj = new URL(req.url, 'http://x');
      if ((urlObj.searchParams.get('token') || '') !== STATS_TOKEN) { res.writeHead(403); res.end('forbidden'); return; }
      const limit = Math.min(300, Math.max(1, parseInt(urlObj.searchParams.get('limit') || '80', 10) || 80));
      let rows = [];
      if (pgPool) {
        const r = await pgPool.query('SELECT payload FROM events ORDER BY t DESC LIMIT $1', [limit]);
        rows = r.rows.map(x => x.payload);
      } else {
        let lines = [];
        try { lines = fs.readFileSync(STATS_FILE, 'utf8').split(String.fromCharCode(10)).filter(Boolean); } catch { lines = []; }
        rows = lines.slice(-limit).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean).reverse();
      }
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(rows));
    })().catch(e => { console.error('[STATS/raw]', e); res.writeHead(500); res.end('error'); });
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
    let cutoff = 0;
    if (period === '1') {
      const now = new Date();
      const startOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 0, 0, 0);
      cutoff = Math.floor(startOfDay.getTime() / 1000);
    } else {
      cutoff = Date.now() / 1000 - periodSeconds;
    }
    events = events.filter(event => Number(event.t) > cutoff);
  }

  const apps = { antivirus: [], match3: [], tanks: [], combined: [] };
  for (const e of events) {
    const a = e.app || 'antivirus';
    if (apps[a]) apps[a].push(e);
    apps.combined.push(e); // В общую статистику идет всё
  }

  return {
    combined: processEvents(apps.combined, 100),
    antivirus: processEvents(apps.antivirus, 100),
    match3: processEvents(apps.match3, 100),
    tanks: processEvents(apps.tanks, 30),
    serverTime: Math.floor(Date.now() / 1000)
  };
}

function processEvents(events, maxLevels) {
  // --- УМНЫЙ ФИЛЬТР БОТОВ ---
  const validSessions = new Set();
  const sessionStarts = {};
  const sessionHasLevel = new Set();
  
  // Собираем информацию о сессиях
  for (const e of events) {
    if (!e.sessionId) continue;
    if (e.ev === 'session_start') sessionStarts[e.sessionId] = e.t;
    if (e.ev === 'level_start') sessionHasLevel.add(e.sessionId);
  }
  
  // Проверяем длительность завершенных сессий
  for (const e of events) {
    if (e.ev === 'session_end' && sessionStarts[e.sessionId]) {
      const duration = e.t - sessionStarts[e.sessionId];
      if (duration >= 10) validSessions.add(e.sessionId);
    }
  }
  
  // Добавляем те, где был level_start
  for (const sid of sessionHasLevel) validSessions.add(sid);
  
  // Фильтруем массив: оставляем события только из "валидных" сессий
  // (Если у события вообще нет sessionId, оставляем его, чтобы не сломать общую статистику)
  events = events.filter(e => !e.sessionId || validSessions.has(e.sessionId));
  // --- КОНЕЦ ФИЛЬТРА ---
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
    const day = d.toLocaleDateString('ru-RU', { timeZone: 'Europe/Moscow' }).split('.').reverse().join('-');
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

  const LOG_EVENTS = new Set(['session_start','level_start','level_end','app_close','transition_to_match3','purchase','ad_watch','share','level_abandon']);
  const logEvents = events
    .filter(e => LOG_EVENTS.has(e.ev))
    .slice(-150)
    .reverse()
    .map(e => ({
      t: Number(e.t) || 0, ev: e.ev, player: e.playerId || '—', platform: e.platform || '',
      level: e.level ?? null, mode: e.mode || '', won: !!e.won, screen: e.screen || '',
      item: e.item || '', kind: e.kind || '', amount: e.amount ?? null, ok: e.ok === true ? true : (e.ok === false ? false : null),
      err: e.err || '', pre: e.pre ?? '', step: e.step ?? null
    }));

  const playerSessions = new Map();
  for(const e of events){
    if(e.ev === 'session_start' && e.playerId){
      playerSessions.set(e.playerId, (playerSessions.get(e.playerId) || 0) + 1);
    }
  }
  const topPlayers = [...playerSessions.entries()].map(([playerId, count]) => ({ playerId, count })).sort((a,b) => b.count - a.count).slice(0, 100);

  // --- RETENTION D1, D7, D30 ---
  const playerFirstSeen = {};
  const playerSubsequentDays = {};
  
  for (const e of events) {
    if (e.ev !== 'session_start' || !e.playerId) continue;
    const pid = e.playerId;
    const dayKey = new Date(Number(e.t) * 1000).toISOString().slice(0, 10);
    if (!playerFirstSeen[pid]) playerFirstSeen[pid] = dayKey;
    if (dayKey !== playerFirstSeen[pid]) {
      if (!playerSubsequentDays[pid]) playerSubsequentDays[pid] = new Set();
      playerSubsequentDays[pid].add(dayKey);
    }
  }
  
  let d1 = 0, d7 = 0, d30 = 0, totalPlayers = 0;
  for (const pid of Object.keys(playerFirstSeen)) {
    const first = new Date(playerFirstSeen[pid]);
    totalPlayers++;
    const subs = playerSubsequentDays[pid] || [];
    for (const sd of subs) {
      const diff = Math.floor((new Date(sd) - first) / 86400000);
      if (diff === 1) d1++;
      if (diff === 7) d7++;
      if (diff === 30) d30++;
    }
  }
  const retention = {
    d1: totalPlayers ? Math.round(d1 / totalPlayers * 100) : 0,
    d7: totalPlayers ? Math.round(d7 / totalPlayers * 100) : 0,
    d30: totalPlayers ? Math.round(d30 / totalPlayers * 100) : 0
  };

  return {
    totalEvents: events.length, uniquePlayers: players.size, avgSessionSec: avgSession,
    purchases, adWatched, adFailed, adRewarded, adInterstitial, days, eventCounts, funnel, screens, lastScreen,
    onlineNowCount: onlineNow.length, onlineNow: onlineNow.slice(0,20), onlinePeak24h: peak, historyOnline, recentLog: logEvents, topPlayers, retention
  };
}

function renderStatsDashboard(token) {
  try {
    const html = fs.readFileSync(path.join(__dirname, 'dashboard.html'), 'utf8');
    return html.split('__STATS_TOKEN__').join(JSON.stringify(token));
  } catch (e) {
    console.warn('[DASH] dashboard.html missing:', e.message);
    return '<h1>Dashboard template not found</h1>';
  }
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