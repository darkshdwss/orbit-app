// ─────────────────────────────────────────────
//  ORBIT — Backend Server
//  Stack: Express + MongoDB + bcrypt + JWT + Socket.io
// ─────────────────────────────────────────────

const express    = require('express');
const bcrypt     = require('bcrypt');
const jwt        = require('jsonwebtoken');
const path       = require('path');
const cors       = require('cors');
const http       = require('http');
const { Server } = require('socket.io');
const { MongoClient, ObjectId } = require('mongodb');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

const PORT        = process.env.PORT || 3000;
const JWT_SECRET  = process.env.JWT_SECRET  || 'orbit-super-secret-change-in-production';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/orbit';
const ADMIN_KEY   = process.env.ADMIN_KEY   || 'orbit-admin-secret-2026';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ── DATABASE ──────────────────────────────────
let db;
async function connectDB() {
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  db = client.db('orbit');
  console.log('✅ Connected to MongoDB');
}
function uid() { return new ObjectId().toString(); }

// ── AUTH MIDDLEWARE ───────────────────────────
function auth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'No token provided' });
  const token = header.split(' ')[1];
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid or expired token' }); }
}
function adminAuth(req, res, next) {
  const key = req.headers['x-admin-key'] || req.query.key;
  if (key !== ADMIN_KEY) return res.status(401).json({ error: 'Unauthorized' });
  next();
}
function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
}

// ══════════════════════════════════════════════
//  AUTH
// ══════════════════════════════════════════════
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'All fields are required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const emailLower = email.trim().toLowerCase();
  const existing = await db.collection('users').findOne({ $or: [{ email: emailLower }, { username: username.trim() }] });
  if (existing) return res.status(409).json({ error: existing.email === emailLower ? 'Email already taken' : 'Username already taken' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const userId = uid();
    const user = { _id: userId, id: userId, username: username.trim(), email: emailLower, password: hash, created_at: new Date().toISOString() };
    await db.collection('users').insertOne(user);
    const defaultProjects = [
      { _id: uid(), user_id: userId, name: 'Personal', color: '#6ee7f7', created_at: new Date().toISOString() },
      { _id: uid(), user_id: userId, name: 'Work',     color: '#c084fc', created_at: new Date().toISOString() },
      { _id: uid(), user_id: userId, name: 'Health',   color: '#4ade80', created_at: new Date().toISOString() },
    ];
    await db.collection('projects').insertMany(defaultProjects);
    const token = jwt.sign({ id: userId, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username: user.username });
  } catch(err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  const user = await db.collection('users').findOne({ email: email.trim().toLowerCase() });
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'Invalid email or password' });
  const token = jwt.sign({ id: user.id || user._id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, username: user.username });
});

app.get('/api/me', auth, async (req, res) => {
  const user = await db.collection('users').findOne({ id: req.user.id });
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { password, ...safe } = user;
  res.json(safe);
});

// ══════════════════════════════════════════════
//  PROJECTS
// ══════════════════════════════════════════════
app.get('/api/projects', auth, async (req, res) => {
  const projects = await db.collection('projects').find({ user_id: req.user.id }).toArray();
  res.json(projects.map(p => ({ ...p, id: p._id })));
});
app.post('/api/projects', auth, async (req, res) => {
  const { name, color } = req.body;
  if (!name) return res.status(400).json({ error: 'Name is required' });
  const id = uid();
  const project = { _id: id, id, user_id: req.user.id, name: name.trim(), color: color || '#6ee7f7', created_at: new Date().toISOString() };
  await db.collection('projects').insertOne(project);
  res.json(project);
});
app.delete('/api/projects/:id', auth, async (req, res) => {
  const result = await db.collection('projects').deleteOne({ _id: req.params.id, user_id: req.user.id });
  if (result.deletedCount === 0) return res.status(404).json({ error: 'Project not found' });
  res.json({ success: true });
});

// ══════════════════════════════════════════════
//  TASKS
// ══════════════════════════════════════════════
app.get('/api/tasks', auth, async (req, res) => {
  const tasks = await db.collection('tasks').find({ user_id: req.user.id }).sort({ created_at: -1 }).toArray();
  res.json(tasks.map(t => ({ ...t, id: t._id })));
});
app.post('/api/tasks', auth, async (req, res) => {
  const { name, notes, proj_id, priority, due } = req.body;
  if (!name) return res.status(400).json({ error: 'Name is required' });
  const id = uid();
  const task = { _id: id, id, user_id: req.user.id, proj_id: proj_id || null, name: name.trim(), notes: notes || '', priority: priority || 'medium', due: due || '', done: false, created_at: new Date().toISOString() };
  await db.collection('tasks').insertOne(task);
  res.json(task);
});
app.put('/api/tasks/:id', auth, async (req, res) => {
  const { name, notes, proj_id, priority, due, done } = req.body;
  const update = {};
  if (name !== undefined)     update.name     = name;
  if (notes !== undefined)    update.notes    = notes;
  if (proj_id !== undefined)  update.proj_id  = proj_id;
  if (priority !== undefined) update.priority = priority;
  if (due !== undefined)      update.due      = due;
  if (done !== undefined)     update.done     = done;
  await db.collection('tasks').updateOne({ _id: req.params.id, user_id: req.user.id }, { $set: update });
  const task = await db.collection('tasks').findOne({ _id: req.params.id });
  res.json({ ...task, id: task._id });
});
app.delete('/api/tasks/:id', auth, async (req, res) => {
  const result = await db.collection('tasks').deleteOne({ _id: req.params.id, user_id: req.user.id });
  if (result.deletedCount === 0) return res.status(404).json({ error: 'Task not found' });
  res.json({ success: true });
});

// ══════════════════════════════════════════════
//  FRIENDS
// ══════════════════════════════════════════════
app.get('/api/friends', auth, async (req, res) => {
  const myId = req.user.id;
  const allFriends = await db.collection('friends').find({ $or: [{ from: myId }, { to: myId }] }).toArray();
  const users = await db.collection('users').find().toArray();
  const findUser = id => users.find(u => (u.id || u._id) === id);
  const accepted = allFriends.filter(f => f.status === 'accepted').map(f => {
    const fId = f.from === myId ? f.to : f.from;
    const u = findUser(fId);
    return u ? { id: fId, username: u.username, since: f.created_at } : null;
  }).filter(Boolean);
  const incoming = allFriends.filter(f => f.status === 'pending' && f.to === myId).map(f => {
    const u = findUser(f.from);
    return u ? { requestId: f._id, id: f.from, username: u.username, sent_at: f.created_at } : null;
  }).filter(Boolean);
  const outgoing = allFriends.filter(f => f.status === 'pending' && f.from === myId).map(f => {
    const u = findUser(f.to);
    return u ? { requestId: f._id, id: f.to, username: u.username, sent_at: f.created_at } : null;
  }).filter(Boolean);
  res.json({ friends: accepted, incoming, outgoing });
});
app.post('/api/friends/request', auth, async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username is required' });
  const myId = req.user.id;
  const target = await db.collection('users').findOne({ username: { $regex: new RegExp(`^${username.trim()}$`, 'i') } });
  if (!target) return res.status(404).json({ error: 'User not found' });
  const targetId = target.id || target._id;
  if (targetId === myId) return res.status(400).json({ error: 'You cannot add yourself' });
  const existing = await db.collection('friends').findOne({ $or: [{ from: myId, to: targetId }, { from: targetId, to: myId }] });
  if (existing) return res.status(409).json({ error: existing.status === 'accepted' ? 'Already friends' : 'Friend request already sent' });
  const id = uid();
  await db.collection('friends').insertOne({ _id: id, from: myId, to: targetId, status: 'pending', created_at: new Date().toISOString() });
  res.json({ success: true, message: `Friend request sent to ${target.username}` });
});
app.post('/api/friends/accept', auth, async (req, res) => {
  const { requestId } = req.body;
  const result = await db.collection('friends').updateOne({ _id: requestId, to: req.user.id, status: 'pending' }, { $set: { status: 'accepted', created_at: new Date().toISOString() } });
  if (result.matchedCount === 0) return res.status(404).json({ error: 'Request not found' });
  res.json({ success: true });
});
app.post('/api/friends/decline', auth, async (req, res) => {
  const { requestId } = req.body;
  await db.collection('friends').deleteOne({ _id: requestId, $or: [{ to: req.user.id }, { from: req.user.id }] });
  res.json({ success: true });
});
app.delete('/api/friends/:id', auth, async (req, res) => {
  const myId = req.user.id;
  await db.collection('friends').deleteOne({ status: 'accepted', $or: [{ from: myId, to: req.params.id }, { from: req.params.id, to: myId }] });
  res.json({ success: true });
});

// ══════════════════════════════════════════════
//  CHAT
// ══════════════════════════════════════════════
app.get('/api/chat/:friendId', auth, async (req, res) => {
  const myId = req.user.id;
  const friendId = req.params.friendId;
  const msgs = await db.collection('messages').find({ $or: [{ from: myId, to: friendId }, { from: friendId, to: myId }] }).sort({ created_at: 1 }).limit(100).toArray();
  res.json(msgs.map(m => ({ ...m, id: m._id })));
});
app.post('/api/chat/:friendId', auth, async (req, res) => {
  const { text } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ error: 'Message is empty' });
  const myId = req.user.id;
  const friendId = req.params.friendId;
  const areFriends = await db.collection('friends').findOne({ status: 'accepted', $or: [{ from: myId, to: friendId }, { from: friendId, to: myId }] });
  if (!areFriends) return res.status(403).json({ error: 'Not friends' });
  const id = uid();
  const msg = { _id: id, id, from: myId, to: friendId, fromUsername: req.user.username, text: text.trim(), created_at: new Date().toISOString() };
  await db.collection('messages').insertOne(msg);
  res.json(msg);
});

// ══════════════════════════════════════════════
//  ADMIN
// ══════════════════════════════════════════════
app.get('/api/admin/stats', adminAuth, async (req, res) => {
  const [users, projects, tasks, doneTasks] = await Promise.all([
    db.collection('users').countDocuments(),
    db.collection('projects').countDocuments(),
    db.collection('tasks').countDocuments(),
    db.collection('tasks').countDocuments({ done: true }),
  ]);
  res.json({ totalUsers: users, totalProjects: projects, totalTasks: tasks, doneTasks });
});
app.get('/api/admin/users', adminAuth, async (req, res) => {
  const users = await db.collection('users').find().toArray();
  const result = await Promise.all(users.map(async u => {
    const uId = u.id || u._id;
    const [projects, tasks, doneTasks] = await Promise.all([
      db.collection('projects').countDocuments({ user_id: uId }),
      db.collection('tasks').countDocuments({ user_id: uId }),
      db.collection('tasks').countDocuments({ user_id: uId, done: true }),
    ]);
    return { id: uId, username: u.username, email: u.email, password: u.password, created_at: u.created_at, projects, tasks, doneTasks };
  }));
  res.json(result);
});
app.get('/api/admin/users/:id/tasks', adminAuth, async (req, res) => {
  const tasks = await db.collection('tasks').find({ user_id: req.params.id }).toArray();
  res.json(tasks);
});
app.delete('/api/admin/users/:id', adminAuth, async (req, res) => {
  const userId = req.params.id;
  await Promise.all([
    db.collection('users').deleteOne({ $or: [{ id: userId }, { _id: userId }] }),
    db.collection('projects').deleteMany({ user_id: userId }),
    db.collection('tasks').deleteMany({ user_id: userId }),
    db.collection('friends').deleteMany({ $or: [{ from: userId }, { to: userId }] }),
    db.collection('messages').deleteMany({ $or: [{ from: userId }, { to: userId }] }),
  ]);
  res.json({ success: true });
});

// ══════════════════════════════════════════════
//  GIGAPOLY — GAME ROOMS (in-memory)
// ══════════════════════════════════════════════
const gameRooms = {}; // roomCode -> room object

function generateRoomCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

// GET active rooms list
app.get('/api/game/rooms', auth, (req, res) => {
  const rooms = Object.values(gameRooms)
    .filter(r => r.status === 'waiting')
    .map(r => ({
      code: r.code,
      host: r.host,
      players: r.players.length,
      maxPlayers: r.maxPlayers,
      createdAt: r.createdAt,
    }));
  res.json(rooms);
});

// POST create a room
app.post('/api/game/create', auth, (req, res) => {
  // Remove any existing room hosted by this user
  Object.keys(gameRooms).forEach(code => {
    if (gameRooms[code].host === req.user.username) delete gameRooms[code];
  });
  let code = generateRoomCode();
  while (gameRooms[code]) code = generateRoomCode();
  gameRooms[code] = {
    code,
    host: req.user.username,
    hostId: req.user.id,
    players: [],
    status: 'waiting', // waiting | playing | finished
    maxPlayers: 6,
    createdAt: new Date().toISOString(),
    gameState: null,
  };
  res.json({ code });
});

// ══════════════════════════════════════════════
//  GIGAPOLY — SOCKET.IO
// ══════════════════════════════════════════════
io.on('connection', (socket) => {
  let currentRoom = null;
  let currentUser = null;

  // Authenticate socket
  socket.on('auth', (token) => {
    const user = verifyToken(token);
    if (!user) { socket.emit('auth_error', 'Invalid token'); return; }
    currentUser = user;
    socket.emit('auth_ok', { username: user.username, id: user.id });
  });

  // Join a room
  socket.on('join_room', (code) => {
    if (!currentUser) { socket.emit('error', 'Not authenticated'); return; }
    const room = gameRooms[code?.toUpperCase()];
    if (!room) { socket.emit('error', 'Room not found'); return; }
    if (room.status !== 'waiting') { socket.emit('error', 'Game already started'); return; }
    if (room.players.length >= room.maxPlayers) { socket.emit('error', 'Room is full'); return; }

    // Check if already in room
    const alreadyIn = room.players.find(p => p.id === currentUser.id);
    if (!alreadyIn) {
      if (room.status === 'playing') { socket.emit('error', 'Game already started'); return; }
      const colors = ['#f87171','#60a5fa','#4ade80','#fbbf24','#c084fc','#f472b6'];
      room.players.push({
        id: currentUser.id,
        username: currentUser.username,
        color: colors[room.players.length % colors.length],
        socketId: socket.id,
        ready: false,
      });
    } else {
      alreadyIn.socketId = socket.id;
    }

    currentRoom = code.toUpperCase();
    socket.join(currentRoom);

    // If game is already playing, send full game state immediately
    if (room.status === 'playing' && room.gameState) {
      socket.emit('game_start', { gameState: room.gameState });
      console.log(`${currentUser.username} rejoined active game ${currentRoom}`);
    } else {
      io.to(currentRoom).emit('room_update', sanitizeRoom(room));
    }
    console.log(`${currentUser.username} joined room ${currentRoom}`);
  });

  // Leave room
  socket.on('leave_room', () => {
    if (!currentRoom || !currentUser) return;
    leaveRoom(socket, currentRoom, currentUser);
  });

  // Toggle ready
  socket.on('toggle_ready', () => {
    if (!currentRoom || !currentUser) return;
    const room = gameRooms[currentRoom];
    if (!room || room.status !== 'waiting') return;
    const player = room.players.find(p => p.id === currentUser.id);
    if (player) {
      player.ready = !player.ready;
      io.to(currentRoom).emit('room_update', sanitizeRoom(room));
    }
  });

  // Start game (host only)
  socket.on('start_game', () => {
    if (!currentRoom || !currentUser) return;
    const room = gameRooms[currentRoom];
    if (!room) return;
    if (room.hostId !== currentUser.id) { socket.emit('error', 'Only the host can start'); return; }
    if (room.players.length < 2) { socket.emit('error', 'Need at least 2 players'); return; }

    room.status = 'playing';
    room.gameState = initGameState(room);
    io.to(currentRoom).emit('game_start', { gameState: room.gameState });
    console.log(`Game started in room ${currentRoom}`);
  });

  // Game action (dice roll, buy, pass, etc.)
  socket.on('game_action', (action) => {
    if (!currentRoom || !currentUser) return;
    const room = gameRooms[currentRoom];
    if (!room || room.status !== 'playing') return;
    const result = processGameAction(room, currentUser.id, action);
    if (result.error) { socket.emit('error', result.error); return; }
    io.to(currentRoom).emit('game_update', { gameState: room.gameState, event: result.event });
    if (room.gameState.winner) {
      io.to(currentRoom).emit('game_over', { winner: room.gameState.winner });
      room.status = 'finished';
      setTimeout(() => { delete gameRooms[currentRoom]; }, 60000);
    }
  });

  // In-game chat
  socket.on('game_chat', (text) => {
    if (!currentRoom || !currentUser || !text?.trim()) return;
    io.to(currentRoom).emit('game_chat', {
      username: currentUser.username,
      text: text.trim().slice(0, 200),
      time: new Date().toISOString(),
    });
  });

  // Disconnect
  socket.on('disconnect', () => {
    if (currentRoom && currentUser) {
      leaveRoom(socket, currentRoom, currentUser);
    }
  });
});

function leaveRoom(socket, code, user) {
  const room = gameRooms[code];
  if (!room) return;
  // During active game, just disconnect socket — don't remove player
  if (room.status === 'playing') {
    const p = room.players.find(p => p.id === user.id);
    if (p) p.socketId = null;
    socket.leave(code);
    return;
  }
  room.players = room.players.filter(p => p.id !== user.id);
  socket.leave(code);
  if (room.players.length === 0) {
    delete gameRooms[code];
  } else {
    if (room.hostId === user.id && room.players.length > 0) {
      room.host   = room.players[0].username;
      room.hostId = room.players[0].id;
    }
    io.to(code).emit('room_update', sanitizeRoom(room));
  }
}

function sanitizeRoom(room) {
  return {
    code:       room.code,
    host:       room.host,
    hostId:     room.hostId,
    players:    room.players.map(p => ({ id: p.id, username: p.username, color: p.color, ready: p.ready })),
    status:     room.status,
    maxPlayers: room.maxPlayers,
  };
}

// ══════════════════════════════════════════════
//  GIGAPOLY — GAME STATE & LOGIC
// ══════════════════════════════════════════════

const BOARD = [
  // Row bottom (left to right)
  { id:0,  name:'GO',               type:'go' },
  { id:1,  name:'Kyiv',             type:'property', color:'#8dd3c7', price:60,  rent:[2,10,30,90,160,250],  houseCost:50  },
  { id:2,  name:'Community Chest',  type:'community' },
  { id:3,  name:'Odesa',            type:'property', color:'#8dd3c7', price:60,  rent:[4,20,60,180,320,450],  houseCost:50  },
  { id:4,  name:'Income Tax',       type:'tax',      amount:200 },
  { id:5,  name:'Airport',          type:'station',  price:200 },
  { id:6,  name:'Lviv',             type:'property', color:'#fb8072', price:100, rent:[6,30,90,270,400,550],  houseCost:50  },
  { id:7,  name:'Chance',           type:'chance' },
  { id:8,  name:'Dnipro',           type:'property', color:'#fb8072', price:100, rent:[6,30,90,270,400,550],  houseCost:50  },
  { id:9,  name:'Kharkiv',          type:'property', color:'#fb8072', price:120, rent:[8,40,100,300,450,600], houseCost:50  },
  // Right column (bottom to top)
  { id:10, name:'Jail / Visit',     type:'jail' },
  { id:11, name:'Zaporizhzhia',     type:'property', color:'#80b1d3', price:140, rent:[10,50,150,450,625,750], houseCost:100 },
  { id:12, name:'Electric Co.',     type:'utility',  price:150 },
  { id:13, name:'Mykolaiv',         type:'property', color:'#80b1d3', price:140, rent:[10,50,150,450,625,750], houseCost:100 },
  { id:14, name:'Vinnytsia',        type:'property', color:'#80b1d3', price:160, rent:[12,60,180,500,700,900], houseCost:100 },
  { id:15, name:'Station North',    type:'station',  price:200 },
  { id:16, name:'Poltava',          type:'property', color:'#fdb462', price:180, rent:[14,70,200,550,750,950], houseCost:100 },
  { id:17, name:'Community Chest',  type:'community' },
  { id:18, name:'Sumy',             type:'property', color:'#fdb462', price:180, rent:[14,70,200,550,750,950], houseCost:100 },
  { id:19, name:'Cherkasy',         type:'property', color:'#fdb462', price:200, rent:[16,80,220,600,800,1000],houseCost:100 },
  // Top row (right to left)
  { id:20, name:'Free Parking',     type:'parking' },
  { id:21, name:'Zhytomyr',         type:'property', color:'#bc80bd', price:220, rent:[18,90,250,700,875,1050],houseCost:150 },
  { id:22, name:'Chance',           type:'chance' },
  { id:23, name:'Rivne',            type:'property', color:'#bc80bd', price:220, rent:[18,90,250,700,875,1050],houseCost:150 },
  { id:24, name:'Lutsk',            type:'property', color:'#bc80bd', price:240, rent:[20,100,300,750,925,1100],houseCost:150 },
  { id:25, name:'Station West',     type:'station',  price:200 },
  { id:26, name:'Ternopil',         type:'property', color:'#b3de69', price:260, rent:[22,110,330,800,975,1150],houseCost:150 },
  { id:27, name:'Ivano-Frankivsk',  type:'property', color:'#b3de69', price:260, rent:[22,110,330,800,975,1150],houseCost:150 },
  { id:28, name:'Water Works',      type:'utility',  price:150 },
  { id:29, name:'Uzhhorod',         type:'property', color:'#b3de69', price:280, rent:[24,120,360,850,1025,1200],houseCost:150 },
  // Left column (top to bottom)
  { id:30, name:'Go To Jail',       type:'gotojail' },
  { id:31, name:'Chernivtsi',       type:'property', color:'#ffed6f', price:300, rent:[26,130,390,900,1100,1275],houseCost:200 },
  { id:32, name:'Khmelnytskyi',     type:'property', color:'#ffed6f', price:300, rent:[26,130,390,900,1100,1275],houseCost:200 },
  { id:33, name:'Community Chest',  type:'community' },
  { id:34, name:'Zaporizhzhia-2',   type:'property', color:'#ffed6f', price:320, rent:[28,150,450,1000,1200,1400],houseCost:200 },
  { id:35, name:'Station East',     type:'station',  price:200 },
  { id:36, name:'Chance',           type:'chance' },
  { id:37, name:'Donetsk',          type:'property', color:'#fc8d59', price:350, rent:[35,175,500,1100,1300,1500],houseCost:200 },
  { id:38, name:'Luxury Tax',       type:'tax',      amount:100 },
  { id:39, name:'Luhansk',          type:'property', color:'#e31a1c', price:400, rent:[50,200,600,1400,1700,2000],houseCost:200 },
];

const CHANCE_CARDS = [
  { text:'Advance to GO. Collect $200.', action:'goto', target:0 },
  { text:'Advance to Kyiv.', action:'goto', target:1 },
  { text:'Advance to Airport.', action:'goto', target:5 },
  { text:'Bank pays you dividend of $50.', action:'money', amount:50 },
  { text:'Go back 3 spaces.', action:'back', amount:3 },
  { text:'Go to Jail. Do not pass GO.', action:'jail' },
  { text:'Make general repairs: $25 per house, $100 per hotel.', action:'repairs', house:25, hotel:100 },
  { text:'Pay poor tax of $15.', action:'money', amount:-15 },
  { text:'You have won a crossword competition. Collect $100.', action:'money', amount:100 },
  { text:'Your building loan matures. Collect $150.', action:'money', amount:150 },
];

const COMMUNITY_CARDS = [
  { text:'Advance to GO. Collect $200.', action:'goto', target:0 },
  { text:'Bank error in your favor. Collect $200.', action:'money', amount:200 },
  { text:'Doctor\'s fees. Pay $50.', action:'money', amount:-50 },
  { text:'From sale of stock you get $50.', action:'money', amount:50 },
  { text:'Go to Jail. Do not pass GO.', action:'jail' },
  { text:'Holiday fund matures. Receive $100.', action:'money', amount:100 },
  { text:'Income tax refund. Collect $20.', action:'money', amount:20 },
  { text:'It\'s your birthday! Collect $10 from every player.', action:'birthday', amount:10 },
  { text:'Life insurance matures. Collect $100.', action:'money', amount:100 },
  { text:'Pay hospital fees of $100.', action:'money', amount:-100 },
  { text:'Receive $25 consultancy fee.', action:'money', amount:25 },
  { text:'You inherit $100.', action:'money', amount:100 },
];

function initGameState(room) {
  const players = room.players.map((p, i) => ({
    id: p.id,
    username: p.username,
    color: p.color,
    money: 1500,
    position: 0,
    properties: [],
    inJail: false,
    jailTurns: 0,
    bankrupt: false,
    doublesCount: 0,
  }));

  return {
    players,
    properties: BOARD.filter(s => ['property','station','utility'].includes(s.type)).map(s => ({
      id: s.id, ownerId: null, houses: 0, hotel: false, mortgaged: false,
    })),
    currentPlayerIndex: 0,
    phase: 'roll', // roll | action | buy | pay | jail
    dice: [0, 0],
    lastRoll: null,
    log: [`Game started! ${players[0].username}'s turn.`],
    winner: null,
    chanceIndex: 0,
    communityIndex: 0,
    turnCount: 0,
  };
}

function processGameAction(room, userId, action) {
  const gs = room.gameState;
  const cp = gs.players[gs.currentPlayerIndex];
  if (cp.id !== userId) return { error: 'Not your turn' };

  let event = null;

  if (action.type === 'roll' && gs.phase === 'roll') {
    const d1 = Math.floor(Math.random() * 6) + 1;
    const d2 = Math.floor(Math.random() * 6) + 1;
    gs.dice = [d1, d2];
    gs.lastRoll = d1 + d2;
    const doubles = d1 === d2;

    if (cp.inJail) {
      if (doubles) {
        cp.inJail = false;
        cp.jailTurns = 0;
        gs.log.push(`${cp.username} rolled doubles and got out of jail!`);
      } else {
        cp.jailTurns++;
        if (cp.jailTurns >= 3) {
          cp.money -= 50;
          cp.inJail = false;
          cp.jailTurns = 0;
          gs.log.push(`${cp.username} paid $50 to get out of jail.`);
        } else {
          gs.log.push(`${cp.username} is in jail (turn ${cp.jailTurns}/3).`);
          nextTurn(gs);
          return { event: { type: 'rolled', dice: [d1, d2] } };
        }
      }
    } else {
      if (doubles) {
        cp.doublesCount++;
        if (cp.doublesCount >= 3) {
          sendToJail(cp, gs);
          return { event: { type: 'jail', player: cp.username } };
        }
      } else {
        cp.doublesCount = 0;
      }
    }

    // Move player
    const oldPos = cp.position;
    cp.position = (cp.position + d1 + d2) % 40;
    if (cp.position < oldPos && !cp.inJail) {
      cp.money += 200;
      gs.log.push(`${cp.username} passed GO and collected $200!`);
    }

    event = { type: 'moved', player: cp.username, from: oldPos, to: cp.position, dice: [d1, d2] };
    const space = BOARD[cp.position];
    gs.log.push(`${cp.username} rolled ${d1}+${d2}=${d1+d2} and landed on ${space.name}.`);
    const landResult = handleLanding(gs, cp, space, room);
    if (landResult) event.landEvent = landResult;
    if (!doubles) { if (gs.phase === 'roll') nextTurn(gs); }
    else { gs.phase = 'roll'; gs.log.push(`${cp.username} rolled doubles! Roll again.`); }

  } else if (action.type === 'buy' && gs.phase === 'buy') {
    const space = BOARD[cp.position];
    const prop = gs.properties.find(p => p.id === cp.position);
    if (cp.money >= space.price && prop && !prop.ownerId) {
      cp.money -= space.price;
      prop.ownerId = cp.id;
      cp.properties.push(cp.position);
      gs.log.push(`${cp.username} bought ${space.name} for $${space.price}!`);
      event = { type: 'bought', player: cp.username, property: space.name };
    }
    nextTurn(gs);

  } else if (action.type === 'pass' && (gs.phase === 'buy' || gs.phase === 'action')) {
    gs.log.push(`${cp.username} passed.`);
    nextTurn(gs);

  } else if (action.type === 'pay_jail') {
    if (cp.inJail && cp.money >= 50) {
      cp.money -= 50;
      cp.inJail = false;
      cp.jailTurns = 0;
      gs.phase = 'roll';
      gs.log.push(`${cp.username} paid $50 to get out of jail.`);
      event = { type: 'paid_jail', player: cp.username };
    }

  } else if (action.type === 'build_house') {
    const propId = action.propertyId;
    const space = BOARD[propId];
    const prop = gs.properties.find(p => p.id === propId);
    if (!prop || prop.ownerId !== cp.id || prop.hotel) return { error: 'Cannot build here' };
    if (cp.money < space.houseCost) return { error: 'Not enough money' };
    if (!ownsFullSet(gs, cp, space.color)) return { error: 'Need full color set first' };
    cp.money -= space.houseCost;
    if (prop.houses >= 4) { prop.houses = 0; prop.hotel = true; gs.log.push(`${cp.username} built a hotel on ${space.name}!`); }
    else { prop.houses++; gs.log.push(`${cp.username} built a house on ${space.name}.`); }
    event = { type: 'built', player: cp.username, property: space.name };
  }

  // Check bankruptcy
  gs.players.forEach(p => {
    if (p.money < 0 && !p.bankrupt) {
      p.bankrupt = true;
      gs.log.push(`💀 ${p.username} went bankrupt!`);
      gs.properties.forEach(prop => { if (prop.ownerId === p.id) { prop.ownerId = null; prop.houses = 0; prop.hotel = false; } });
    }
  });

  // Check winner
  const activePlayers = gs.players.filter(p => !p.bankrupt);
  if (activePlayers.length === 1) {
    gs.winner = activePlayers[0].username;
    gs.log.push(`🏆 ${gs.winner} wins the game!`);
  }

  return { event };
}

function handleLanding(gs, player, space, room) {
  if (space.type === 'go') { player.money += 200; gs.log.push(`${player.username} landed on GO! Collect $200.`); gs.phase = 'roll'; return; }
  if (space.type === 'gotojail') { sendToJail(player, gs); return { type: 'jail' }; }
  if (space.type === 'tax') { player.money -= space.amount; gs.log.push(`${player.username} paid $${space.amount} tax.`); gs.phase = 'action'; return; }
  if (space.type === 'parking' || space.type === 'jail') { gs.phase = 'action'; return; }

  if (space.type === 'chance') {
    const card = CHANCE_CARDS[gs.chanceIndex % CHANCE_CARDS.length];
    gs.chanceIndex++;
    gs.log.push(`🃏 Chance: ${card.text}`);
    applyCard(gs, player, card, room);
    return { type: 'card', text: card.text };
  }
  if (space.type === 'community') {
    const card = COMMUNITY_CARDS[gs.communityIndex % COMMUNITY_CARDS.length];
    gs.communityIndex++;
    gs.log.push(`🃏 Community: ${card.text}`);
    applyCard(gs, player, card, room);
    return { type: 'card', text: card.text };
  }

  if (['property','station','utility'].includes(space.type)) {
    const prop = gs.properties.find(p => p.id === space.id);
    if (!prop.ownerId) {
      gs.phase = 'buy';
      return { type: 'can_buy', property: space.name, price: space.price };
    } else if (prop.ownerId !== player.id) {
      const owner = gs.players.find(p => p.id === prop.ownerId);
      if (owner && !owner.bankrupt) {
        let rent = calcRent(gs, space, prop);
        player.money -= rent;
        owner.money += rent;
        gs.log.push(`${player.username} paid $${rent} rent to ${owner.username} for ${space.name}.`);
        gs.phase = 'action';
        return { type: 'rent', amount: rent, to: owner.username };
      }
    } else {
      gs.phase = 'action';
    }
  }
}

function calcRent(gs, space, prop) {
  if (space.type === 'station') {
    const ownedStations = gs.properties.filter(p => BOARD[p.id]?.type === 'station' && p.ownerId === prop.ownerId).length;
    return [25, 50, 100, 200][ownedStations - 1] || 25;
  }
  if (space.type === 'utility') {
    const ownedUtils = gs.properties.filter(p => BOARD[p.id]?.type === 'utility' && p.ownerId === prop.ownerId).length;
    return ownedUtils === 2 ? gs.lastRoll * 10 : gs.lastRoll * 4;
  }
  if (prop.hotel) return space.rent[5];
  return space.rent[prop.houses];
}

function ownsFullSet(gs, player, color) {
  const colorProps = BOARD.filter(s => s.color === color);
  return colorProps.every(s => {
    const p = gs.properties.find(pr => pr.id === s.id);
    return p && p.ownerId === player.id;
  });
}

function sendToJail(player, gs) {
  player.position = 10;
  player.inJail = true;
  player.jailTurns = 0;
  player.doublesCount = 0;
  gs.log.push(`🚔 ${player.username} was sent to jail!`);
  gs.phase = 'action';
}

function applyCard(gs, player, card, room) {
  if (card.action === 'money') { player.money += card.amount; gs.phase = 'action'; }
  else if (card.action === 'goto') {
    const oldPos = player.position;
    player.position = card.target;
    if (player.position < oldPos) { player.money += 200; gs.log.push(`${player.username} passed GO! Collect $200.`); }
    const space = BOARD[player.position];
    handleLanding(gs, player, space, room);
  }
  else if (card.action === 'back') {
    player.position = (player.position - card.amount + 40) % 40;
    const space = BOARD[player.position];
    handleLanding(gs, player, space, room);
  }
  else if (card.action === 'jail') { sendToJail(player, gs); }
  else if (card.action === 'repairs') {
    let total = 0;
    player.properties.forEach(pid => {
      const prop = gs.properties.find(p => p.id === pid);
      if (prop) { total += prop.hotel ? card.hotel : prop.houses * card.house; }
    });
    player.money -= total;
    gs.log.push(`${player.username} paid $${total} in repairs.`);
    gs.phase = 'action';
  }
  else if (card.action === 'birthday') {
    gs.players.forEach(p => { if (p.id !== player.id && !p.bankrupt) { p.money -= card.amount; player.money += card.amount; } });
    gs.phase = 'action';
  }
}

function nextTurn(gs) {
  gs.turnCount++;
  let next = (gs.currentPlayerIndex + 1) % gs.players.length;
  let tries = 0;
  while (gs.players[next].bankrupt && tries < gs.players.length) { next = (next + 1) % gs.players.length; tries++; }
  gs.currentPlayerIndex = next;
  gs.phase = 'roll';
  const cp = gs.players[gs.currentPlayerIndex];
  gs.log.push(`--- ${cp.username}'s turn ---`);
}

// ── STATIC FILES ──────────────────────────────
app.get('/game', (req, res) => res.sendFile(path.join(__dirname, 'game.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ── START ─────────────────────────────────────
connectDB().then(() => {
  server.listen(PORT, () => {
    console.log(`\n🚀 ORBIT server running at http://localhost:${PORT}`);
    console.log(`🎲 Gigapoly ready!\n`);
  });
}).catch(err => {
  console.error('❌ Failed to connect to MongoDB:', err);
  process.exit(1);
});
