'use strict';
const http = require('http');
const { WebSocketServer } = require('ws');
const crypto = require('crypto');

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
  bombs_pack:     { title: 'Набор бомб ×5',  price: 10, photo_url: 'https://darones.github.io/antivirus/logo.png' },
  bombs_pack_big: { title: 'Набор бомб ×20', price: 25, photo_url: 'https://darones.github.io/antivirus/logo.png' },
  remove_ads:     { title: 'Убрать рекламу', price: 10, photo_url: 'https://darones.github.io/antivirus/logo.png' },
};
const VK_SHOP_ITEMS_BY_APP = {
  '54764920': SHOP_ITEMS,
  '54786750': {
    tanks_coins_small:  { title: '10 000 монет', price: 5, photo_url: 'https://raw.githubusercontent.com/Darones/assets/main/coin.png' },
    tanks_coins_medium: { title: '25 000 монет', price: 10, photo_url: 'https://raw.githubusercontent.com/Darones/assets/main/coin.png' },
    tanks_coins_large:  { title: '60 000 монет', price: 20, photo_url: 'https://raw.githubusercontent.com/Darones/assets/main/coin.png' },
  },
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
  const isOK = (params.site === 'OK') || (appId === '512004990432');
  const isTanks = (appId === '54786750');

  let secret;
  if (isOK) secret = OK_APP_SECRET;
  else if (isTanks) secret = VK_APP_SECRET_TANKS;
  else secret = VK_APP_SECRET;

  if (!secret) return true;
  const { sig, ...rest } = params;
  if (!sig) return false;
  const keys = Object.keys(rest).sort();
  const sorted = keys.map(k => k + '=' + rest[k]).join('&');

  // VK: MD5(sorted + secret)
  const v1 = crypto.createHash('md5').update(sorted + secret).digest('hex');
  if (v1 === sig) { console.log('[PAY-SIG] MATCHED v1_md5, isOK=', isOK); return true; }

  // OK: MD5(MD5(application_key + secret) + sorted)
  if (isOK && params.application_key) {
    const keyHash = crypto.createHash('md5').update(params.application_key + secret).digest('hex');
    const v2 = crypto.createHash('md5').update(keyHash + sorted).digest('hex');
    if (v2 === sig) { console.log('[PAY-SIG] MATCHED v2_ok'); return true; }
  }

  console.log('[PAY-SIG] no match. isOK=', isOK, 'appId=', appId,
    'secret_len=', secret.length, 'first=', secret.slice(0,4));
  console.log('[PAY-SIG] received=', String(sig).slice(0,8));
  console.log('[PAY-SIG] v1_md5=', v1.slice(0,8));
  if (isOK && params.application_key) {
    const keyHash = crypto.createHash('md5').update(params.application_key + secret).digest('hex');
    const v2 = crypto.createHash('md5').update(keyHash + sorted).digest('hex');
    console.log('[PAY-SIG] v2_ok=', v2.slice(0,8));
  }
  return false;
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

const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, rooms: rooms.size, waiting: waiting.length }));
    return;
  }
  // [PAYMENTS] Обработка платёжных уведомлений ОК (GET-запрос)
  if (req.url.startsWith('/ok/pay')) {
    const urlObj = new URL(req.url, 'http://x');
    const params = Object.fromEntries(urlObj.searchParams);
    const appParam = urlObj.searchParams.get('app') || '54764920';
    const isTanks = (appParam === '54786750');
    const shop = VK_SHOP_ITEMS_BY_APP[appParam] || SHOP_ITEMS;
    const okSecret = isTanks ? OK_APP_SECRET_TANKS : OK_APP_SECRET;
    console.log('[OK-PAY]', 'app=', appParam, params.operation_type || params.method || '-', 'code=', params.product_code, 'user=', params.uid);
    if (!validateOKSig(params, okSecret)) {
      console.warn('[OK-PAY] invalid sig');
      res.writeHead(200); res.end('{"status":"error","error_code":104,"error_msg":"invalid signature"}'); return;
    }
    // ОК может запрашивать подтверждение платежа
    const code = params.product_code || params.code;
    const item = shop[code];
    const amount = Number(params.amount);
    if (!item || item.price !== amount) {
      console.warn('[OK-PAY] invalid product or amount', code, params.amount);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{"error_code":1001,"error_msg":"Invocation-error"}'); return;
    }
    const userId = params.uid;
    const set = purchases.get(userId) || new Set();
    set.add(code);
    purchases.set(userId, set);
    console.log('[OK-PAY] granted', code, 'to', userId);
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
        const secret = (appId === '54786750') ? VK_APP_SECRET_TANKS : VK_APP_SECRET;
        const { sig, ...rest } = params;
        const sortedKeys = Object.keys(rest).sort();
        const sigString = sortedKeys.map(k => k + '=' + rest[k]).join('&');
        const expected = crypto.createHash('md5').update(sigString + secret).digest('hex');
        console.log('[PAY]', params.notification_type, 'item=', params.item, 'user=', params.user_id);
        const sigValid = validatePaymentsSig(params);
        if (!sigValid) {
          console.warn('[PAY] invalid sig (пропускаем для теста)');
        }
        const type = params.notification_type || '';
        const itemId = params.item;
        const userId = params.user_id;
        const shopItems = VK_SHOP_ITEMS_BY_APP[params.app_id];
        if (!shopItems) {
          res.writeHead(200); res.end(JSON.stringify({ response: { error: { error_code: 20, error_msg: 'Unknown app_id', critical: true } } })); return;
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

server.listen(PORT, '0.0.0.0', () => {
  console.log(`⚔ Duel server on port ${PORT}`);
  console.log(`   Health: http://0.0.0.0:${PORT}/health`);
});
