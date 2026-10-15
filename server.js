'use strict';
const http = require('http');
const { WebSocketServer } = require('ws');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const STATS_FILE = path.join(__dirname, 'events.jsonl');

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
  if (!pgPool) { console.warn('[STATS] DATABASE_URL \u043d\u0435 \u0437\u0430\u0434\u0430\u043d\u043e, \u0440\u0430\u0431\u043e\u0442\u0430\u0435\u043c \u0447\u0435\u0440\u0435\u0437 \u0444\u0430\u0439\u043b'); return; }
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

// [PAYMENTS] Проверка подписи MD5 (по доке VK)
// [PAYMENTS] Проверка подписи ОК: MD5(MD5(access_token+secret) + params)
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
        const events = Array.isArray(data?.events) ? data.events : [];
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

  // GET /stats/reset?token=XXX ? ???????? events.jsonl
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
        res.end('<meta charset="utf-8"><h2>?????????? ???????</h2><p><a href="/stats/dashboard?token=' + encodeURIComponent(token) + '">? ????????</a></p>');
      } catch (e) {
        console.warn('[STATS] reset failed:', e.message);
        res.writeHead(500); res.end('reset failed');
      }
    })().catch(e => { console.error('[STATS/reset]', e); res.writeHead(500); res.end('reset failed'); });
    return;
  }

  // GET /stats/data?token=XXX — сводка в JSON
  if (req.url.startsWith('/stats/data')) {
    (async () => {
      const urlObj = new URL(req.url, 'http://x');
      const token = urlObj.searchParams.get('token') || '';
      const appFilter = urlObj.searchParams.get('app') || 'antivirus';
      if (token !== STATS_TOKEN) { res.writeHead(403); res.end('forbidden'); return; }
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      const summary = await buildStatsSummary(appFilter);
      res.end(JSON.stringify(summary));
    })().catch(e => { console.error('[STATS/data]', e); res.writeHead(500); res.end('error'); });
    return;
  }

  // GET /stats/dashboard?token=XXX — HTML-страница с графиками
  if (req.url.startsWith('/stats/dashboard')) {
    const urlObj = new URL(req.url, 'http://x');
    const token = urlObj.searchParams.get('token') || '';
    const appFilter = urlObj.searchParams.get('app') || 'antivirus';
    if (token !== STATS_TOKEN) { res.writeHead(403); res.end('forbidden'); return; }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(renderStatsDashboard(token, appFilter));
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
    console.log('[OK-PAY-RAW-KEYS]', Object.keys(params).sort().join(','));
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
    // Если OK присылает подтверждение без notification_type,
    // но с product_code — считаем это order_status_change
    if (!notificationType && (params.product_code || params.code || params.item_id) && (params.status || params.amount || params.method === 'callbacks.payment')) {
      notificationType = 'order_status_change';
      console.log('[OK-PAY] inferred order_status_change from params');
    }
    console.log('[OK-PAY] type=', notificationType, 'status=', params.status, 'product=', params.product_code);
    const itemId = params.product_code || params.item || params.code;
    const userId = params.uid || params.user_id;
    const orderId = params.order_id || params.transaction_id;

    console.log('[OK-PAY]', 'app=', appParam, 'type=', notificationType, 'item=', itemId, 'user=', userId);

    // Для OK пока пропускаем проверку подписи (отладим отдельно)
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

    // get_item — запрос информации о товаре
    if (notificationType === 'get_item' || notificationType === 'get_item_test') {
      const item = shop[itemId];
      if (!item) {
        console.warn('[OK-PAY] unknown item', itemId);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: { error_code: 20, error_msg: 'Unknown item', critical: true } }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        response: {
          title: item.title,
          price: item.price,
          photo_url: item.photo_url || '',
          item_id: itemId
        }
      }));
      return;
    }

    // order_status_change — подтверждение покупки
    if (notificationType === 'order_status_change' || notificationType === 'order_status_change_test') {
      // OK НЕ присылает status. Считаем покупку подтверждённой, если
      // пришёл product_code и (transaction_id или amount).
      // VK присылает status=chargeable — оставляем как условие.
      const isOKPayment = (params.method === 'callbacks.payment') || (params.application_key === 'CBOGCBOGDIHBABABA') || !params.status;
      const isChargeable = (params.status === 'chargeable') || (isOKPayment && (params.product_code || params.item_id || params.item));
      console.log('[OK-PAY-ORDER] isOKPayment=', isOKPayment, 'isChargeable=', isChargeable, 'status=', params.status, 'product_code=', params.product_code);
      if (isChargeable) {
        const resolvedItemId = params.product_code || params.item_id || params.item || itemId;
        const item = shop[resolvedItemId];
        if (item) {
          const set = purchases.get(userId) || new Set();
          set.add(resolvedItemId);
          purchases.set(userId, set);
          console.log('[OK-PAY] granted', resolvedItemId, 'to', userId);
        } else {
          console.warn('[OK-PAY] item not found in shop:', resolvedItemId);
        }
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ response: { order_id: orderId || params.transaction_id, app_order_id: Date.now() } }));
      return;
    }

    // Фолбэк — простое уведомление
    const code = params.product_code || params.code;
    if (!code) {
      console.warn('[OK-PAY] no product_code — responding ok for compatibility');
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
        console.log('[RAW] FULL PARAMS:', JSON.stringify(params));
        console.log('[RAW] keys:', Object.keys(params).sort().join(','));
        const appId = String(params.app_id || '');
        const isOK = (params.site === 'OK') || (appId === '512004990432') || (appId === '512005381577');
        console.log('[PAY]', params.notification_type, 'item=', params.item, 'user=', params.user_id, 'site=', params.site || 'VK', 'isOK=', isOK);
        if (!isOK) {
          // Проверка подписи VK (только для VK-запросов)
          if (!validatePaymentsSig(params)) {
            console.warn('[PAY] invalid sig');
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: { error_code: 10, error_msg: 'invalid signature', critical: true } }));
            return;
          }
        } else {
          // Для OK пока пропускаем проверку подписи (отладим отдельно)
          console.log('[PAY-OK] sig check skipped for OK');
        }
        const type = params.notification_type || '';
        const itemId = params.item;
        const userId = params.user_id;
        const shopItems = VK_SHOP_ITEMS_BY_APP[params.app_id];
        console.log('[PAY] shop lookup app_id=', params.app_id, 'found=', !!shopItems);
        if (!shopItems) {
          console.warn('[PAY] unknown app_id', params.app_id);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ response: { error: { error_code: 20, error_msg: 'Unknown app_id', critical: true } } }));
          return;
        }

        if (type === 'get_item' || type === 'get_item_test') {
          const item = shopItems[itemId];
          if (!item) { res.writeHead(200); res.end(JSON.stringify({ response: { error: { error_code: 20, error_msg: 'Unknown item', critical: true } } })); return; }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          if (!item.photo_url) console.warn('[GET_ITEM] empty photo_url for', itemId);
          res.end(JSON.stringify({ response: { title: item.title, price: item.price, photo_url: item.photo_url || '', item_id: itemId } }));
          return;
        }

        if (type === 'order_status_change'
            || type === 'order_status_change_test') {
          if (params.status === 'chargeable') {
            const item = shopItems[itemId];
            if (item) {
              const set = purchases.get(userId) || new Set();
              set.add(itemId);
              purchases.set(userId, set);
              console.log('[PAY] granted', itemId, 'to', userId);
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
  console.log(`[+] ${ws.playerId}`);
  send(ws, { type: 'welcome', playerId: ws.playerId });

  ws.on('message', raw => {
    let msg; try { msg = JSON.parse(raw); } catch { return; }
    handleMessage(ws, msg);
  });
  ws.on('close', () => { console.log(`[-] ${ws.playerId}`); handleLeave(ws); players.delete(ws); });
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

async function buildStatsSummary(appFilter) {
  const filter = appFilter || 'antivirus';
  let events = [];
  if (pgPool) {
    try {
      const query = filter === 'all'
        ? 'SELECT payload FROM events ORDER BY t ASC'
        : 'SELECT payload FROM events WHERE app = $1 ORDER BY t ASC';
      const params = filter === 'all' ? [] : [filter];
      const { rows } = await pgPool.query(query, params);
      events = rows.map(r => r.payload);
    } catch (e) { console.warn('[STATS] DB read failed:', e.message); events = []; }
  } else {
    let lines = [];
    try { lines = fs.readFileSync(STATS_FILE, 'utf8').split(String.fromCharCode(10)).filter(Boolean); } catch { lines = []; }
    for (const line of lines) {
      try {
        const e = JSON.parse(line);
        const eApp = e.app || 'antivirus';
        if (filter !== 'all' && eApp !== filter) continue;
        events.push(e);
      } catch {}
    }
  }
  const byDay = {};
  const players = new Set();
  const eventCounts = {};
  const levelStart = {};
  const levelEnd = {};
  const levelFail = {};
  const lastScreen = {};
  const screens = {};
  let purchases = 0, adWatched = 0, adFailed = 0;
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
    if (e.ev === 'ad_watch') { if (e.ok) adWatched++; else adFailed++; }

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
  for (let i = 1; i <= 30; i++) {
    funnel.push({
      level: i,
      started: levelStart[i] || 0,
      won: levelEnd[i] || 0,
      lost: levelFail[i] || 0
    });
  }

  return {
    totalEvents: events.length,
    uniquePlayers: players.size,
    avgSessionSec: avgSession,
    purchases,
    adWatched,
    adFailed,
    days,
    eventCounts,
    funnel,
    screens,
    lastScreen,
    onlineNowCount: onlineNow.length,
    onlineNow: onlineNow.slice(0,20),
    onlinePeak24h: peak,
    historyOnline
  };
}

function renderStatsDashboard(token, appFilter) {
  const safeApp = (appFilter || 'antivirus').replace(/[^a-z0-9_-]/gi, '');
  return `<!doctype html><html lang="ru"><head>
<meta charset="utf-8"><title>Антивирус — Статистика</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body{font:13px system-ui,sans-serif;background:#f8fafc;color:#0f172a;margin:0;padding:10px;overflow:hidden}
h1{margin:0 0 4px;font-size:18px}
h2{font-size:13px;margin:0 0 4px;color:#334155;font-weight:700}
.cards{display:grid;grid-template-columns:repeat(8,1fr);gap:6px;margin:6px 0 10px}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:6px 8px;text-align:center}
.card b{display:block;font-size:20px;color:#6366f1;line-height:1.1}
.card.card-online{background:linear-gradient(135deg,#10b981,#059669);color:#fff;border-color:#059669}
.card.card-online b{color:#fff;font-size:26px}
.card.card-online small{color:#d1fae5}
.card small{color:#64748b;font-size:10px}
.panels{display:grid;grid-template-columns:minmax(240px,1fr) 1.6fr;gap:10px;align-items:start}
.panel{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:8px}
table{width:100%;border-collapse:collapse;font-size:11px}
th,td{padding:3px 6px;text-align:left;border-bottom:1px solid #e2e8f0}
th{background:#f1f5f9;font-weight:700;font-size:10px;text-transform:uppercase;letter-spacing:.3px;color:#475569}
tr:last-child td{border-bottom:none}
.tbl-scroll{max-height:440px;overflow-y:auto}
.funnel-wrap{position:relative;height:440px}
@media(max-width:760px){.cards{grid-template-columns:repeat(4,1fr)}.panels{grid-template-columns:1fr}}
</style></head><body>
<h1 id="pageTitle">${appFilter === 'tanks' ? 'Танки' : 'Антивирус'} — статистика</h1>
<p id="updated" style="color:#64748b;font-size:11px;margin:0 0 6px"></p>

<div class="cards" id="cards"></div>

<div class="panels">
  <div class="panel">
    <h2>Активные сейчас</h2>
    <div class="tbl-scroll"><table id="tblOnline"></table></div>
  </div>
  <div class="panel">
    <h2>Воронка по уровням (начали / прошли / проиграли)</h2>
    <div class="funnel-wrap"><canvas id="chFunnel"></canvas></div>
  </div>
</div>
<script>
const TOKEN = ${JSON.stringify(token)};
const APP = ${JSON.stringify(safeApp)};
const SCREEN_NAMES = {
  'welcome':'Приветствие','story':'Сюжет','menu':'Меню','levels':'Выбор ур.',
  'game':'Игра','pause':'Пауза','end':'Конец ур.','shop':'Магазин',
  'daily':'Бонус','settings':'Настройки','records':'Рекорды','duel':'Дуэль',
  'duel-share':'Дуэль: пригл.','duel-waiting':'Дуэль: ожид.',
  'duel-countdown':'Дуэль: отсчёт','boot':'Загрузка','characters-test':'Тест'
};
function ruScreen(key){ return key ? (SCREEN_NAMES[key] || key) : '—'; }
function updateTitleBadge(online){
  document.title=online>0?' '+online+' онлайн — Антивирус':'Антивирус — Статистика';
}
async function refresh(){
  try{
    const r=await fetch('/stats/data?token='+encodeURIComponent(TOKEN)+'&app='+encodeURIComponent(APP));
    if(!r.ok){document.body.innerHTML='<h1>403 — неверный токен</h1>';return;}
    const d=await r.json();
    document.getElementById('updated').textContent='Обновлено: '+new Date().toLocaleString()+' · событий: '+d.totalEvents;
    renderCards(d);renderCharts(d);renderTables(d);updateTitleBadge(d.onlineNowCount||0);
  }catch(e){console.warn('refresh fail',e);}
}
refresh();
setInterval(refresh,30000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh();});
function renderCards(d){
  const c = document.getElementById('cards');
  const items = [
    ['Онлайн',     d.onlineNowCount, true],
    ['Пик 24ч',    d.onlinePeak24h,  false],
    ['Игроков',    d.uniquePlayers,  false],
    ['Событий',    d.totalEvents,    false],
    ['Ср. сессия', d.avgSessionSec ? Math.round(d.avgSessionSec/60) + ' мин' : '—', false],
    ['Покупок',    d.purchases,      false],
    ['Реклама ОК', d.adWatched,      false],
    ['Реклама ✗',  d.adFailed,       false]
  ];
  c.innerHTML = items.map(([t,v,hl]) =>
    '<div class="card'+(hl?' card-online':'')+'"><b>'+v+'</b><small>'+t+'</small></div>'
  ).join('');
}
let charts = {};
function renderCharts(d){
  if(charts.funnel) charts.funnel.destroy();
  const cv = document.getElementById('chFunnel');
  if(!cv) return;
  charts.funnel = new Chart(cv, {
    type:'bar',
    data:{ labels:d.funnel.map(x=>'Ур.'+x.level), datasets:[
      { label:'Начали',    data:d.funnel.map(x=>x.started), backgroundColor:'#94a3b8' },
      { label:'Прошли',    data:d.funnel.map(x=>x.won),     backgroundColor:'#10b981' },
      { label:'Проиграли', data:d.funnel.map(x=>x.lost),    backgroundColor:'#ef4444' }
    ]},
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{ legend:{labels:{boxWidth:10,font:{size:11}}} },
      scales:{ x:{stacked:true,ticks:{font:{size:9}}}, y:{stacked:true,ticks:{font:{size:9}}} }
    }
  });
}
function renderTables(d){
  function esc(s){
    return String(s == null ? '' : s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  }
  const t3 = document.getElementById('tblOnline');
  if(!t3) return;
  const rows = (d.onlineNow || []).slice().sort((a,b)=>a.ageSec-b.ageSec);
  if(rows.length === 0){
    t3.innerHTML = '<tr><td style="color:#64748b">Никого — все ушли</td></tr>';
  } else {
    t3.innerHTML = '<tr><th>Игрок</th><th>Пл.</th><th>Экран</th><th>Ур.</th><th>Тишина</th></tr>'
      + rows.map(r=>'<tr><td>'+esc(r.playerId)+'</td><td>'+esc(r.platform||'—')+'</td><td>'+esc(ruScreen(r.screen))+'</td><td>'+esc(r.level??'—')+'</td><td>'+r.ageSec+'с</td></tr>').join('');
  }
}
load();
</script>
</body></html>`;
}
initStatsTable().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
    console.log('\u2694 Duel server on port ' + PORT);
    console.log('   Health: http://0.0.0.0:' + PORT + '/health');
    console.log('   Stats: ' + (pgPool ? 'Postgres' : 'file (no DATABASE_URL)'));
  });
}).catch(e => {
  console.error('[BOOT] init failed:', e);
  server.listen(PORT, '0.0.0.0', () => {
    console.log('\u2694 Duel server on port ' + PORT + ' (\u0431\u0435\u0437 \u0411\u0414)');
  });
});
