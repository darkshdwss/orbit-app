// ─────────────────────────────────────────────
//  ORBIT — Backend Server
//  Stack: Express + JSON file DB + bcrypt + JWT
//  No compilation needed — works on any Windows!
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
const DB_FILE = path.join(__dirname, 'orbit-db.json');
 
// ── MIDDLEWARE ──────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));
 
// ── JSON DATABASE ───────────────────────────
function readDB() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      const empty = { users: [], projects: [], tasks: [] };
      fs.writeFileSync(DB_FILE, JSON.stringify(empty, null, 2));
      return empty;
    }
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch {
    return { users: [], projects: [], tasks: [] };
  }
}
 
function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}
 
function uid() {
  return '_' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
}
 
// ── AUTH MIDDLEWARE ─────────────────────────
function auth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'No token provided' });
  const token = header.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}
 
// ══════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════
 
// POST /api/register
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: 'All fields are required' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
 
  const db = readDB();
  const emailLower = email.trim().toLowerCase();
 
  if (db.users.find(u => u.email === emailLower))
    return res.status(409).json({ error: 'Email already taken' });
  if (db.users.find(u => u.username === username.trim()))
    return res.status(409).json({ error: 'Username already taken' });
 
  try {
    const hash = await bcrypt.hash(password, 10);
    const user = {
      id: uid(),
      username: username.trim(),
      email: emailLower,
      password: hash,
      created_at: new Date().toISOString()
    };
    db.users.push(user);
 
    const defaultProjects = [
      { id: uid(), user_id: user.id, name: 'Personal', color: '#6ee7f7', created_at: new Date().toISOString() },
      { id: uid(), user_id: user.id, name: 'Work',     color: '#c084fc', created_at: new Date().toISOString() },
      { id: uid(), user_id: user.id, name: 'Health',   color: '#4ade80', created_at: new Date().toISOString() },
    ];
    db.projects.push(...defaultProjects);
    writeDB(db);
 
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username: user.username, message: 'Account created!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});
 
// POST /api/login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required' });
 
  const db = readDB();
  const user = db.users.find(u => u.email === email.trim().toLowerCase());
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });
 
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'Invalid email or password' });
 
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, username: user.username });
});
 
// GET /api/me
app.get('/api/me', auth, (req, res) => {
  const db = readDB();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { password, ...safe } = user;
  res.json(safe);
});
 
// ══════════════════════════════════════════════
//  PROJECT ROUTES
// ══════════════════════════════════════════════
 
app.get('/api/projects', auth, (req, res) => {
  const db = readDB();
  res.json(db.projects.filter(p => p.user_id === req.user.id));
});
 
app.post('/api/projects', auth, (req, res) => {
  const { name, color } = req.body;
  if (!name) return res.status(400).json({ error: 'Name is required' });
  const db = readDB();
  const project = {
    id: uid(), user_id: req.user.id,
    name: name.trim(), color: color || '#6ee7f7',
    created_at: new Date().toISOString()
  };
  db.projects.push(project);
  writeDB(db);
  res.json(project);
});
 
app.delete('/api/projects/:id', auth, (req, res) => {
  const db = readDB();
  const idx = db.projects.findIndex(p => p.id === req.params.id && p.user_id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Project not found' });
  db.projects.splice(idx, 1);
  writeDB(db);
  res.json({ success: true });
});
 
// ══════════════════════════════════════════════
//  TASK ROUTES
// ══════════════════════════════════════════════
 
app.get('/api/tasks', auth, (req, res) => {
  const db = readDB();
  res.json(db.tasks.filter(t => t.user_id === req.user.id));
});
 
app.post('/api/tasks', auth, (req, res) => {
  const { name, notes, proj_id, priority, due } = req.body;
  if (!name) return res.status(400).json({ error: 'Name is required' });
  const db = readDB();
  const task = {
    id: uid(), user_id: req.user.id,
    proj_id: proj_id || null,
    name: name.trim(), notes: notes || '',
    priority: priority || 'medium',
    due: due || '', done: false,
    created_at: new Date().toISOString()
  };
  db.tasks.unshift(task);
  writeDB(db);
  res.json(task);
});
 
app.put('/api/tasks/:id', auth, (req, res) => {
  const db = readDB();
  const idx = db.tasks.findIndex(t => t.id === req.params.id && t.user_id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Task not found' });
  const { name, notes, proj_id, priority, due, done } = req.body;
  const task = db.tasks[idx];
  db.tasks[idx] = {
    ...task,
    name:     name     !== undefined ? name     : task.name,
    notes:    notes    !== undefined ? notes    : task.notes,
    proj_id:  proj_id  !== undefined ? proj_id  : task.proj_id,
    priority: priority !== undefined ? priority : task.priority,
    due:      due      !== undefined ? due      : task.due,
    done:     done     !== undefined ? done     : task.done,
  };
  writeDB(db);
  res.json(db.tasks[idx]);
});
 
app.delete('/api/tasks/:id', auth, (req, res) => {
  const db = readDB();
  const idx = db.tasks.findIndex(t => t.id === req.params.id && t.user_id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Task not found' });
  db.tasks.splice(idx, 1);
  writeDB(db);
  res.json({ success: true });
});
 
// ══════════════════════════════════════════════
//  ADMIN ROUTES (protect with secret key)
// ══════════════════════════════════════════════
const ADMIN_KEY = process.env.ADMIN_KEY || 'orbit-admin-secret-2026';
 
function adminAuth(req, res, next) {
  const key = req.headers['x-admin-key'] || req.query.key;
  if (key !== ADMIN_KEY) return res.status(401).json({ error: 'Unauthorized' });
  next();
}
 
// GET /api/admin/stats
app.get('/api/admin/stats', adminAuth, (req, res) => {
  const db = readDB();
  res.json({
    totalUsers:    db.users.length,
    totalProjects: db.projects.length,
    totalTasks:    db.tasks.length,
    doneTasks:     db.tasks.filter(t => t.done).length,
  });
});
 
// GET /api/admin/users
app.get('/api/admin/users', adminAuth, (req, res) => {
  const db = readDB();
  const users = db.users.map(u => {
    const projects = db.projects.filter(p => p.user_id === u.id);
    const tasks    = db.tasks.filter(t => t.user_id === u.id);
    return {
      id:         u.id,
      username:   u.username,
      email:      u.email,
      created_at: u.created_at,
      projects:   projects.length,
      tasks:      tasks.length,
      doneTasks:  tasks.filter(t => t.done).length,
    };
  });
  res.json(users);
});
 
// GET /api/admin/users/:id/tasks
app.get('/api/admin/users/:id/tasks', adminAuth, (req, res) => {
  const db = readDB();
  const tasks = db.tasks.filter(t => t.user_id === req.params.id);
  res.json(tasks);
});
 
// DELETE /api/admin/users/:id
app.delete('/api/admin/users/:id', adminAuth, (req, res) => {
  const db = readDB();
  const idx = db.users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  const userId = db.users[idx].id;
  db.users.splice(idx, 1);
  db.projects = db.projects.filter(p => p.user_id !== userId);
  db.tasks    = db.tasks.filter(t => t.user_id !== userId);
  writeDB(db);
  res.json({ success: true });
});
 
// GET /admin → serve admin panel
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});
 
// ── CATCH-ALL → serve index.html ────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
 
// ── START ────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 ORBIT server running at http://localhost:${PORT}`);
  console.log(`📁 Database: ${DB_FILE}\n`);
});
