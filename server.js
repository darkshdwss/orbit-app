// ─────────────────────────────────────────────
//  ORBIT — Backend Server
//  Stack: Express + MongoDB + bcrypt + JWT
// ─────────────────────────────────────────────

const express    = require('express');
const bcrypt     = require('bcrypt');
const jwt        = require('jsonwebtoken');
const path       = require('path');
const cors       = require('cors');
const { MongoClient, ObjectId } = require('mongodb');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET  = process.env.JWT_SECRET  || 'orbit-super-secret-change-in-production';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/orbit';
const ADMIN_KEY   = process.env.ADMIN_KEY   || 'orbit-admin-secret-2026';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ── DATABASE ─────────────────────────────────
let db;
async function connectDB() {
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  db = client.db('orbit');
  console.log('✅ Connected to MongoDB');
}

function uid() {
  return new ObjectId().toString();
}

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

// ══════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════

app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: 'All fields are required' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const emailLower = email.trim().toLowerCase();
  const existing = await db.collection('users').findOne({
    $or: [{ email: emailLower }, { username: username.trim() }]
  });
  if (existing) {
    return res.status(409).json({
      error: existing.email === emailLower ? 'Email already taken' : 'Username already taken'
    });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    const userId = uid();
    const user = {
      _id: userId, id: userId,
      username: username.trim(),
      email: emailLower,
      password: hash,
      created_at: new Date().toISOString()
    };
    await db.collection('users').insertOne(user);

    // Default projects
    const defaultProjects = [
      { _id: uid(), user_id: userId, name: 'Personal', color: '#6ee7f7', created_at: new Date().toISOString() },
      { _id: uid(), user_id: userId, name: 'Work',     color: '#c084fc', created_at: new Date().toISOString() },
      { _id: uid(), user_id: userId, name: 'Health',   color: '#4ade80', created_at: new Date().toISOString() },
    ];
    await db.collection('projects').insertMany(defaultProjects);

    const token = jwt.sign({ id: userId, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username: user.username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required' });

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
  const allFriends = await db.collection('friends').find({
    $or: [{ from: myId }, { to: myId }]
  }).toArray();

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
  const existing = await db.collection('friends').findOne({
    $or: [{ from: myId, to: targetId }, { from: targetId, to: myId }]
  });
  if (existing) return res.status(409).json({ error: existing.status === 'accepted' ? 'Already friends' : 'Friend request already sent' });
  const id = uid();
  await db.collection('friends').insertOne({ _id: id, from: myId, to: targetId, status: 'pending', created_at: new Date().toISOString() });
  res.json({ success: true, message: `Friend request sent to ${target.username}` });
});

app.post('/api/friends/accept', auth, async (req, res) => {
  const { requestId } = req.body;
  const result = await db.collection('friends').updateOne(
    { _id: requestId, to: req.user.id, status: 'pending' },
    { $set: { status: 'accepted', created_at: new Date().toISOString() } }
  );
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
  await db.collection('friends').deleteOne({
    status: 'accepted',
    $or: [{ from: myId, to: req.params.id }, { from: req.params.id, to: myId }]
  });
  res.json({ success: true });
});

// ══════════════════════════════════════════════
//  CHAT
// ══════════════════════════════════════════════

app.get('/api/chat/:friendId', auth, async (req, res) => {
  const myId = req.user.id;
  const friendId = req.params.friendId;
  const msgs = await db.collection('messages').find({
    $or: [{ from: myId, to: friendId }, { from: friendId, to: myId }]
  }).sort({ created_at: 1 }).limit(100).toArray();
  res.json(msgs.map(m => ({ ...m, id: m._id })));
});

app.post('/api/chat/:friendId', auth, async (req, res) => {
  const { text } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ error: 'Message is empty' });
  const myId = req.user.id;
  const friendId = req.params.friendId;
  const areFriends = await db.collection('friends').findOne({
    status: 'accepted',
    $or: [{ from: myId, to: friendId }, { from: friendId, to: myId }]
  });
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
    const uid = u.id || u._id;
    const [projects, tasks, doneTasks] = await Promise.all([
      db.collection('projects').countDocuments({ user_id: uid }),
      db.collection('tasks').countDocuments({ user_id: uid }),
      db.collection('tasks').countDocuments({ user_id: uid, done: true }),
    ]);
    return { id: uid, username: u.username, email: u.email, password: u.password, created_at: u.created_at, projects, tasks, doneTasks };
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

app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ── START ─────────────────────────────────────
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`\n🚀 ORBIT server running at http://localhost:${PORT}\n`);
  });
}).catch(err => {
  console.error('❌ Failed to connect to MongoDB:', err);
  process.exit(1);
});
