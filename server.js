'use strict';
const http = require('http');
const { WebSocketServer } = require('ws');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const MATCHMAKING_TIMEOUT = 120 * 1000;
const MAX_GARBAGE = 5;
const TARGET_VIRUSES = 15;

const VK_APP_SECRET = process.env.VK_APP_SECRET || '';

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

server.listen(PORT, () => {
  console.log(`⚔ Duel server on port ${PORT}`);
  console.log(`   Health: http://localhost:${PORT}/health`);
});