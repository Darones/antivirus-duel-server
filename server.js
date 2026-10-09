'use strict';
const http = require('http');
const { WebSocketServer } = require('ws');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const STATS_FILE = path.join(__dirname, 'events.jsonl');
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

const server = http.createServer((req, res) => {
  // POST /stats/event — приём батча событий от клиента
  if (req.url === '/stats/event' && req.method === 'POST') {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        const events = Array.isArray(data?.events) ? data.events : [];
        if (events.length === 0) { res.writeHead(200); res.end('{"ok":true}'); return; }
        const lines = events.map(e => JSON.stringify(e)).join('\n') + '\n';
        fs.appendFileSync(STATS_FILE, lines, 'utf8');
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

  // GET /stats/data?token=XXX — сводка в JSON
  if (req.url.startsWith('/stats/data')) {
    const urlObj = new URL(req.url, 'http://x');
    const token = urlObj.searchParams.get('token') || '';
    if (token !== STATS_TOKEN) { res.writeHead(403); res.end('forbidden'); return; }
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(buildStatsSummary()));
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
        console.log('[RAW] FULL PARAMS:', JSON.stringify(params));
        console.log('[RAW] keys:', Object.keys(params).sort().join(','));
        const appId = String(params.app_id || '');
        const secret = (appId === '54786750') ? VK_APP_SECRET_TANKS : VK_APP_SECRET;
        const { sig, ...rest } = params;
        const sortedKeys = Object.keys(rest).sort();
        const sigString = sortedKeys.map(k => k + '=' + rest[k]).join('&');
        const expected = crypto.createHash('md5').update(sigString + secret).digest('hex');
        console.log('[PAY]', params.notification_type, 'item=', params.item, 'user=', params.user_id);
        if (!validatePaymentsSig(params)) {
          console.warn('[PAY] invalid sig');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: { error_code: 10, error_msg: 'invalid signature', critical: true } }));
          return;
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

function buildStatsSummary() {
  let lines = [];
  try { lines = fs.readFileSync(STATS_FILE, 'utf8').split('\n').filter(Boolean); } catch { lines = []; }
  const events = [];
  for (const line of lines) {
    try { events.push(JSON.parse(line)); } catch {}
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

function renderStatsDashboard(token) {
  return `<!doctype html><html lang="ru"><head>
<meta charset="utf-8"><title>Антивирус — Статистика</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body{font:14px system-ui,sans-serif;background:#f8fafc;color:#0f172a;margin:0;padding:20px}
h1{margin:0 0 6px;font-size:22px}
h2{font-size:16px;margin:24px 0 10px;color:#334155}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px;margin:12px 0}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:12px}
.card b{display:block;font-size:22px;color:#6366f1}
.card small{color:#64748b}
.chart-wrap{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:12px;margin:8px 0}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:12px;overflow:hidden;font-size:13px}
th,td{padding:6px 10px;text-align:left;border-bottom:1px solid #e2e8f0}
th{background:#f1f5f9;font-weight:700}
tr:last-child td{border-bottom:none}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:760px){.cols{grid-template-columns:1fr}}
</style></head><body>
<h1> Антивирус — статистика</h1>
<p id="updated" style="color:#64748b"></p>

<div class="cards" id="cards"></div>

<div class="chart-wrap"><canvas id="chOnlineHistory" height="140"></canvas></div>

<h2>Активные сейчас (последние 3 минуты)</h2>
<div class="chart-wrap"><table id="tblOnline"></table></div>

<div class="cols">
  <div class="chart-wrap"><canvas id="chDays" height="180"></canvas></div>
  <div class="chart-wrap"><canvas id="chEvents" height="180"></canvas></div>
</div>

<h2>Воронка по уровням</h2>
<div class="chart-wrap"><canvas id="chFunnel" height="220"></canvas></div>

<div class="cols">
  <div>
    <h2>Экраны (всего переходов)</h2>
    <table id="tblScreens"></table>
  </div>
  <div>
    <h2>Последний экран перед закрытием</h2>
    <table id="tblLastScreen"></table>
  </div>
</div>

<script>
const TOKEN = ${JSON.stringify(token)};
function updateTitleBadge(online){
  document.title=online>0?' '+online+' онлайн — Антивирус':'Антивирус — Статистика';
}
async function refresh(){
  try{
    const r=await fetch('/stats/data?token='+encodeURIComponent(TOKEN));
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
    ['Онлайн сейчас', d.onlineNowCount],
    ['Пик за сутки', d.onlinePeak24h],
    ['Уникальных игроков', d.uniquePlayers],
    ['Всего событий', d.totalEvents],
    ['Средняя сессия', d.avgSessionSec ? d.avgSessionSec + ' сек' : '—'],
    ['Покупок', d.purchases],
    ['Реклама ок', d.adWatched],
    ['Реклама провал', d.adFailed]
  ];
  c.innerHTML = items.map(([t,v]) => '<div class="card"><b>'+v+'</b><small>'+t+'</small></div>').join('');
}
let charts = {};
function renderCharts(d){
  const labels = d.days.map(x => x.day.slice(5));
  if(charts.days) charts.days.destroy();
  charts.days = new Chart(document.getElementById('chDays'), {
    type:'line',
    data:{ labels, datasets:[
      { label:'Игроки', data:d.days.map(x=>x.players), borderColor:'#6366f1', backgroundColor:'#6366f133', tension:.3, fill:true },
      { label:'Сессии', data:d.days.map(x=>x.sessions), borderColor:'#f59e0b', backgroundColor:'#f59e0b33', tension:.3, fill:true }
    ]},
    options:{ responsive:true, plugins:{ title:{display:true,text:'Игроки и сессии по дням'} } }
  });

  const evLabels = Object.keys(d.eventCounts).sort((a,b)=>d.eventCounts[b]-d.eventCounts[a]).slice(0,10);
  if(charts.events) charts.events.destroy();
  charts.events = new Chart(document.getElementById('chEvents'), {
    type:'bar',
    data:{ labels:evLabels, datasets:[{ label:'Событий', data:evLabels.map(k=>d.eventCounts[k]), backgroundColor:'#6366f1' }]},
    options:{ responsive:true, indexAxis:'y', plugins:{ title:{display:true,text:'Топ событий'} } }
  });

  if(charts.funnel) charts.funnel.destroy();
  charts.funnel = new Chart(document.getElementById('chFunnel'), {
    type:'bar',
    data:{ labels:d.funnel.map(x=>'Ур.'+x.level), datasets:[
      { label:'Начали', data:d.funnel.map(x=>x.started), backgroundColor:'#94a3b8' },
      { label:'Победили', data:d.funnel.map(x=>x.won), backgroundColor:'#10b981' },
      { label:'Проиграли', data:d.funnel.map(x=>x.lost), backgroundColor:'#ef4444' }
    ]},
    options:{ responsive:true, scales:{ x:{stacked:true}, y:{stacked:true} } }
  });

  if(charts.online) charts.online.destroy();
  charts.online = new Chart(document.getElementById('chOnlineHistory'), {
    type:'line',
    data:{ labels:(d.historyOnline||[]).map(x=>x.offsetMin===0?'сейчас':x.offsetMin+'м'), datasets:[{ label:'Онлайн', data:(d.historyOnline||[]).map(x=>x.online), borderColor:'#10b981', backgroundColor:'#10b98133', tension:.3, fill:true, pointRadius:2 }]},
    options:{ responsive:true, plugins:{ title:{display:true,text:'Онлайн за последний час'} }, scales:{ y:{beginAtZero:true,ticks:{precision:0}} } }
  });
}
function renderTables(d){
  const t1 = document.getElementById('tblScreens');
  const rows1 = Object.entries(d.screens).sort((a,b)=>b[1]-a[1]);
  t1.innerHTML = '<tr><th>Экран</th><th>Раз</th></tr>' + rows1.map(([k,v])=>'<tr><td>'+k+'</td><td>'+v+'</td></tr>').join('');
  const t2 = document.getElementById('tblLastScreen');
  const rows2 = Object.entries(d.lastScreen).sort((a,b)=>b[1]-a[1]);
  t2.innerHTML = '<tr><th>Экран</th><th>Уходов</th></tr>' + rows2.map(([k,v])=>'<tr><td>'+k+'</td><td>'+v+'</td></tr>').join('');
  function esc(s){
    return String(s == null ? '' : s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  }
  const t3=document.getElementById('tblOnline');
  if(t3){
    const rows=(d.onlineNow||[]).slice().sort((a,b)=>a.ageSec-b.ageSec);
    if(rows.length===0){
      t3.innerHTML='<tr><td style="color:#64748b">Никого — все ушли</td></tr>';
    }else{
      t3.innerHTML='<tr><th>Игрок</th><th>Платформа</th><th>Экран</th><th>Уровень</th><th>Тишина</th></tr>'
        + rows.map(r=>'<tr><td>'+esc(r.playerId)+'</td><td>'+esc(r.platform||'—')+'</td><td>'+esc(r.screen||'—')+'</td><td>'+esc(r.level??'—')+'</td><td>'+r.ageSec+' сек</td></tr>').join('');
    }
  }
}
load();
</script>
</body></html>`;
}
server.listen(PORT, '0.0.0.0', () => {
  console.log(`⚔ Duel server on port ${PORT}`);
  console.log(`   Health: http://0.0.0.0:${PORT}/health`);
});
