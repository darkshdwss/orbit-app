// ─────────────────────────────────────────────
//  ORBIT — Backend Server
//  Stack: Express + JSON file DB + bcrypt + JWT
// ─────────────────────────────────────────────

const express = require('express');
const bcrypt  = require('bcrypt');
const jwt     = require('jsonwebtoken');
const path    = require('path');
const cors    = require('cors');
const fs      = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'orbit-super-secret-change-in-production';
const DB_FILE = process.env.RAILWAY_VOLUME_MOUNT_PATH
  ? path.join(process.env.RAILWAY_VOLUME_MOUNT_PATH, 'orbit-db.json')
  : path.join(__dirname, 'orbit-db.json');

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

function readDB() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      const empty = { users: [], projects: [], tasks: [], friends: [], messages: [] };
      fs.writeFileSync(DB_FILE, JSON.stringify(empty, null, 2));
      return empty;
    }
    const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    if (!data.friends)  data.friends  = [];
    if (!data.messages) data.messages = [];
    return data;
  } catch { return { users: [], projects: [], tasks: [], friends: [], messages: [] }; }
}
function writeDB(data) { fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2)); }
function uid() { return '_' + Math.random().toString(36).slice(2,10) + Date.now().toString(36); }

function auth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'No token provided' });
  const token = header.split(' ')[1];
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid or expired token' }); }
}

// ── AUTH ────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'All fields are required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const db = readDB();
  const emailLower = email.trim().toLowerCase();
  if (db.users.find(u => u.email === emailLower)) return res.status(409).json({ error: 'Email already taken' });
  if (db.users.find(u => u.username === username.trim())) return res.status(409).json({ error: 'Username already taken' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const user = { id: uid(), username: username.trim(), email: emailLower, password: hash, created_at: new Date().toISOString() };
    db.users.push(user);
    const defaultProjects = [
      { id: uid(), user_id: user.id, name: 'Personal', color: '#6ee7f7', created_at: new Date().toISOString() },
      { id: uid(), user_id: user.id, name: 'Work',     color: '#c084fc', created_at: new Date().toISOString() },
      { id: uid(), user_id: user.id, name: 'Health',   color: '#4ade80', created_at: new Date().toISOString() },
    ];
    db.projects.push(...defaultProjects);
    writeDB(db);
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username: user.username });
  } catch(err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  const db = readDB();
  const user = db.users.find(u => u.email === email.trim().toLowerCase());
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'Invalid email or password' });
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, username: user.username });
});

app.get('/api/me', auth, (req, res) => {
  const db = readDB();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { password, ...safe } = user;
  res.json(safe);
});

// ── PROJECTS ────────────────────────────────
app.get('/api/projects', auth, (req, res) => { const db = readDB(); res.json(db.projects.filter(p => p.user_id === req.user.id)); });
app.post('/api/projects', auth, (req, res) => {
  const { name, color } = req.body;
  if (!name) return res.status(400).json({ error: 'Name is required' });
  const db = readDB();
  const project = { id: uid(), user_id: req.user.id, name: name.trim(), color: color || '#6ee7f7', created_at: new Date().toISOString() };
  db.projects.push(project); writeDB(db); res.json(project);
});
app.delete('/api/projects/:id', auth, (req, res) => {
  const db = readDB();
  const idx = db.projects.findIndex(p => p.id === req.params.id && p.user_id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Project not found' });
  db.projects.splice(idx, 1); writeDB(db); res.json({ success: true });
});

// ── TASKS ────────────────────────────────────
app.get('/api/tasks', auth, (req, res) => { const db = readDB(); res.json(db.tasks.filter(t => t.user_id === req.user.id)); });
app.post('/api/tasks', auth, (req, res) => {
  const { name, notes, proj_id, priority, due } = req.body;
  if (!name) return res.status(400).json({ error: 'Name is required' });
  const db = readDB();
  const task = { id: uid(), user_id: req.user.id, proj_id: proj_id||null, name: name.trim(), notes: notes||'', priority: priority||'medium', due: due||'', done: false, created_at: new Date().toISOString() };
  db.tasks.unshift(task); writeDB(db); res.json(task);
});
app.put('/api/tasks/:id', auth, (req, res) => {
  const db = readDB();
  const idx = db.tasks.findIndex(t => t.id === req.params.id && t.user_id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Task not found' });
  const { name, notes, proj_id, priority, due, done } = req.body;
  const task = db.tasks[idx];
  db.tasks[idx] = { ...task, name: name!==undefined?name:task.name, notes: notes!==undefined?notes:task.notes, proj_id: proj_id!==undefined?proj_id:task.proj_id, priority: priority!==undefined?priority:task.priority, due: due!==undefined?due:task.due, done: done!==undefined?done:task.done };
  writeDB(db); res.json(db.tasks[idx]);
});
app.delete('/api/tasks/:id', auth, (req, res) => {
  const db = readDB();
  const idx = db.tasks.findIndex(t => t.id === req.params.id && t.user_id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Task not found' });
  db.tasks.splice(idx, 1); writeDB(db); res.json({ success: true });
});

// ── FRIENDS ──────────────────────────────────
app.get('/api/friends', auth, (req, res) => {
  const db = readDB();
  const myId = req.user.id;
  const accepted = db.friends.filter(f => f.status==='accepted' && (f.from===myId||f.to===myId)).map(f => {
    const fId = f.from===myId ? f.to : f.from;
    const user = db.users.find(u => u.id===fId);
    return user ? { id: user.id, username: user.username, since: f.created_at } : null;
  }).filter(Boolean);
  const incoming = db.friends.filter(f => f.status==='pending' && f.to===myId).map(f => {
    const user = db.users.find(u => u.id===f.from);
    return user ? { requestId: f.id, id: user.id, username: user.username, sent_at: f.created_at } : null;
  }).filter(Boolean);
  const outgoing = db.friends.filter(f => f.status==='pending' && f.from===myId).map(f => {
    const user = db.users.find(u => u.id===f.to);
    return user ? { requestId: f.id, id: user.id, username: user.username, sent_at: f.created_at } : null;
  }).filter(Boolean);
  res.json({ friends: accepted, incoming, outgoing });
});

app.post('/api/friends/request', auth, (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username is required' });
  const db = readDB();
  const myId = req.user.id;
  const target = db.users.find(u => u.username.toLowerCase() === username.trim().toLowerCase());
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.id === myId) return res.status(400).json({ error: 'You cannot add yourself' });
  const existing = db.friends.find(f => (f.from===myId&&f.to===target.id)||(f.from===target.id&&f.to===myId));
  if (existing) return res.status(409).json({ error: existing.status==='accepted' ? 'Already friends' : 'Friend request already sent' });
  db.friends.push({ id: uid(), from: myId, to: target.id, status: 'pending', created_at: new Date().toISOString() });
  writeDB(db);
  res.json({ success: true, message: `Friend request sent to ${target.username}` });
});

app.post('/api/friends/accept', auth, (req, res) => {
  const { requestId } = req.body;
  const db = readDB();
  const req_ = db.friends.find(f => f.id===requestId && f.to===req.user.id && f.status==='pending');
  if (!req_) return res.status(404).json({ error: 'Request not found' });
  req_.status = 'accepted'; req_.created_at = new Date().toISOString();
  writeDB(db); res.json({ success: true });
});

app.post('/api/friends/decline', auth, (req, res) => {
  const { requestId } = req.body;
  const db = readDB();
  const idx = db.friends.findIndex(f => f.id===requestId && (f.to===req.user.id||f.from===req.user.id));
  if (idx===-1) return res.status(404).json({ error: 'Request not found' });
  db.friends.splice(idx, 1); writeDB(db); res.json({ success: true });
});

app.delete('/api/friends/:id', auth, (req, res) => {
  const db = readDB();
  const myId = req.user.id;
  const idx = db.friends.findIndex(f => f.status==='accepted' && ((f.from===myId&&f.to===req.params.id)||(f.from===req.params.id&&f.to===myId)));
  if (idx===-1) return res.status(404).json({ error: 'Friend not found' });
  db.friends.splice(idx, 1); writeDB(db); res.json({ success: true });
});

// ── CHAT ─────────────────────────────────────
app.get('/api/chat/:friendId', auth, (req, res) => {
  const db = readDB();
  const myId = req.user.id;
  const friendId = req.params.friendId;
  const msgs = db.messages
    .filter(m => (m.from===myId&&m.to===friendId)||(m.from===friendId&&m.to===myId))
    .sort((a,b) => new Date(a.created_at)-new Date(b.created_at))
    .slice(-100);
  res.json(msgs);
});

app.post('/api/chat/:friendId', auth, (req, res) => {
  const { text } = req.body;
  if (!text||!text.trim()) return res.status(400).json({ error: 'Message is empty' });
  const db = readDB();
  const myId = req.user.id;
  const friendId = req.params.friendId;
  const areFriends = db.friends.find(f => f.status==='accepted' && ((f.from===myId&&f.to===friendId)||(f.from===friendId&&f.to===myId)));
  if (!areFriends) return res.status(403).json({ error: 'Not friends' });
  const msg = { id: uid(), from: myId, to: friendId, fromUsername: req.user.username, text: text.trim(), created_at: new Date().toISOString() };
  db.messages.push(msg); writeDB(db); res.json(msg);
});

// ── ADMIN ────────────────────────────────────
const ADMIN_KEY = process.env.ADMIN_KEY || 'orbit-admin-secret-2026';
function adminAuth(req, res, next) {
  const key = req.headers['x-admin-key'] || req.query.key;
  if (key !== ADMIN_KEY) return res.status(401).json({ error: 'Unauthorized' });
  next();
}
app.get('/api/admin/stats', adminAuth, (req, res) => {
  const db = readDB();
  res.json({ totalUsers: db.users.length, totalProjects: db.projects.length, totalTasks: db.tasks.length, doneTasks: db.tasks.filter(t=>t.done).length });
});
app.get('/api/admin/users', adminAuth, (req, res) => {
  const db = readDB();
  res.json(db.users.map(u => {
    const projects = db.projects.filter(p=>p.user_id===u.id);
    const tasks = db.tasks.filter(t=>t.user_id===u.id);
    return { id:u.id, username:u.username, email:u.email, created_at:u.created_at, projects:projects.length, tasks:tasks.length, doneTasks:tasks.filter(t=>t.done).length };
  }));
});
app.get('/api/admin/users/:id/tasks', adminAuth, (req, res) => { const db=readDB(); res.json(db.tasks.filter(t=>t.user_id===req.params.id)); });
app.delete('/api/admin/users/:id', adminAuth, (req, res) => {
  const db = readDB();
  const idx = db.users.findIndex(u=>u.id===req.params.id);
  if (idx===-1) return res.status(404).json({ error: 'User not found' });
  const userId = db.users[idx].id;
  db.users.splice(idx,1);
  db.projects = db.projects.filter(p=>p.user_id!==userId);
  db.tasks = db.tasks.filter(t=>t.user_id!==userId);
  db.friends = db.friends.filter(f=>f.from!==userId&&f.to!==userId);
  db.messages = db.messages.filter(m=>m.from!==userId&&m.to!==userId);
  writeDB(db); res.json({ success: true });
});
app.get('/admin', (req, res) => { res.sendFile(path.join(__dirname, 'admin.html')); });

app.get('*', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

app.listen(PORT, () => {
  console.log(`\n🚀 ORBIT server running at http://localhost:${PORT}`);
  console.log(`📁 Database: ${DB_FILE}\n`);
});
