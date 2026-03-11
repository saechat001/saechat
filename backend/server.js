// backend/server.js
// Minimal SaeChat backend: JWT auth + posts. In-memory store for quick start.

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const upload = multer({ dest: 'uploads/' });

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';

// In-memory "DB"
const USERS = [];   // { id, username, email, passwordHash, avatar }
const POSTS = [];   // { id, authorId, text, imageUrl, likes: [] }
let nextId = 1;

// helpers
function genId(){ return String(nextId++); }
function auth(req, res, next){
  const a = req.headers.authorization;
  if(!a) return res.status(401).json({ error: 'no token' });
  const token = a.split(' ')[1];
  try {
    const p = jwt.verify(token, JWT_SECRET);
    req.userId = p.id;
    next();
  } catch (e) { res.status(401).json({ error: 'invalid token' }); }
}

// Register
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body || {};
  if(!username || !email || !password) return res.status(400).json({ error: 'missing fields' });
  if(USERS.find(u => u.email === email)) return res.status(400).json({ error: 'email used' });
  const hash = await bcrypt.hash(password, 8);
  const user = { id: genId(), username, email, passwordHash: hash, avatar: null };
  USERS.push(user);
  const token = jwt.sign({ id: user.id }, JWT_SECRET);
  res.json({ token, user: { id: user.id, username: user.username, avatar: user.avatar } });
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const user = USERS.find(u => u.email === email);
  if(!user) return res.status(400).json({ error: 'invalid' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if(!ok) return res.status(400).json({ error: 'invalid' });
  const token = jwt.sign({ id: user.id }, JWT_SECRET);
  res.json({ token, user: { id: user.id, username: user.username, avatar: user.avatar } });
});

// Create post (text + optional image)
app.post('/api/posts', auth, upload.single('image'), (req, res) => {
  const text = req.body.text || '';
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
  const post = { id: genId(), authorId: req.userId, text, imageUrl, likes: [] };
  POSTS.unshift(post);
  res.json(post);
});

// Feed
app.get('/api/posts/feed', auth, (req, res) => {
  const enriched = POSTS.map(p => {
    const author = USERS.find(u => u.id === p.authorId) || { username: 'unknown' };
    return { ...p, author: { id: p.authorId, username: author.username, avatar: author.avatar } };
  });
  res.json(enriched);
});

// Like/unlike
app.post('/api/posts/:id/like', auth, (req, res) => {
  const p = POSTS.find(x => x.id === req.params.id);
  if(!p) return res.status(404).end();
  const i = p.likes.indexOf(req.userId);
  if(i === -1) p.likes.push(req.userId); else p.likes.splice(i, 1);
  res.json(p);
});

// Basic profile
app.get('/api/users/me', auth, (req, res) => {
  const u = USERS.find(x => x.id === req.userId);
  if(!u) return res.status(404).end();
  res.json({ id: u.id, username: u.username, avatar: u.avatar, email: u.email });
});

app.get('/', (req, res) => res.send('SaeChat backend OK'));
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log('SaeChat backend listening on', PORT));
